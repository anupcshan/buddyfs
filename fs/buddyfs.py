#!/usr/bin/python
"""BuddyFS FUSE filesystem."""

import argparse
import cPickle as pickle
import errno
import hashlib
import llfuse
import logging
import os
import stat
import sys
import threading
from time import time
from twisted.internet import defer
from Crypto import Random
from Crypto.Cipher import AES
sys.path.append(os.path.abspath(os.path.dirname(__file__) + '/..'))
from kad_server.buddynode import BuddyNode
from kad_server.buddyd import KadFacade
from crypto.keys import KeyManager


logger = logging.getLogger(__name__)


class BlockMetadata:

    """ Block metedata structure. """

    def __init__(self):
        self.id = None
        self.symkey = None
        self.quorum = []

DEFAULT_BLOCK_SIZE = 8192


class FileMetadata:

    """ File metadata structure. """

    def __init__(self):
        # TODO: Figure out how to represent compact files within this structure
        self.mtime = time()
        self.name = None
        self.length = 0
        self.block_size = DEFAULT_BLOCK_SIZE
        self.blocks = []
        self.version = 1        # Is this really needed?


class DirMetadata:

    """ Directory metadata structure. """

    def __init__(self):
        self.mtime = time()
        self.name = None
        self.files = []
        self.subdirs = []
        self.version = 1        # Again, needed?


class Inode:

    """ In-memory FS representation.
        Inode data structure. """

    def __init__(self, _id):
        self.id = _id
        self.name = ''
        self.isDir = True
        self.size = 0
        self.permissions = None
        self.uid = os.getuid()
        self.gid = os.getgid()
        self.atime = self.ctime = self.mtime = time()
        self.children = []
        self.parent = None
        self.version = 1
        self.blockMetadata = None
        self.explored = False
        self.bid = None


def unblockr(lock, retval):
    def release_lock(args):
        retval[0] = args
        lock.release()

    return release_lock


class FSTree:

    """ Inode tree structure and associated utilities. """

    def __init__(self, km, start_port, known_ip, known_port):
        self.__current_id = 0
        self.inodes = {}
        self.ROOT_INODE = None
        self.inode_open_count = {}
        self.km = km
        # KadFacade needs the port number to find the SQL table name.
        self.kf = KadFacade(start_port)
        self.start_port = int(start_port)
        self.known_ip = known_ip
        if known_port is not None:
            self.known_port = int(known_port)
        else:
            self.known_port = None

    def _commit_block_(self, blk_meta, blk_data):
        ciphertext = self._encrypt_block_(blk_meta, pickle.dumps(blk_data))
        node = BuddyNode.get_node(self.start_port, self.known_ip,
                                  self.known_port)
        node.set_root(blk_meta.id, ciphertext)
        logger.debug('Committed block ID %s to DHT' % (blk_meta.id))

        node.push_to_dht(self.km.gpg_key['fingerprint'], node.get_node_id())
        logger.debug("Stored <pubkey, nodeid> mapping to DHT")

        pubkey_list = map(lambda x: x.get('keyid'), self.km.gpg.list_keys())
        logger.debug("pubkey list : %s", pubkey_list)

        peers = self.kf.get_all_peers_from_dht(pubkey_list)
        logger.debug("Peer List based on the Web of Trust Social Circle: %s", peers)

    def _read_block_(self, blk_meta):
        deferredVar = BuddyNode.get_node(self.start_port, self.known_ip,
                                         self.known_port).get_root(blk_meta.id)

        ciph = [None]
        unblock_read = threading.Lock()

        unblock_read.acquire()
        deferredVar.addCallback(unblockr(unblock_read, ciph))
        unblock_read.acquire()
        unblock_read.release()

        plaintext = self._decrypt_block_(blk_meta, ciph[0].values()[0])
        return pickle.loads(plaintext)

    def _encrypt_block_(self, blk_meta, blk_data):
        if blk_meta.symkey is None:
            blk_meta.symkey = Random.new().read(AES.block_size)

        cipher = AESCipher(blk_meta.symkey)
        ciphertext = cipher.encrypt(blk_data)
        if blk_meta.id is None:
            blk_meta.id = hashlib.sha256(ciphertext).hexdigest()
        return ciphertext

    def _decrypt_block_(self, blk_meta, ciph_data):
        if blk_meta.symkey is None:
            raise Exception("Key not provied while trying to decrypt block")

        # TODO: Perform integrity check on the block here.
        # if hashlib.sha256(ciph_data).hexdigest() != blk_meta.id:
        #     raise Exception("Integrity check failed: block ID differs from"
        #     "block digest: Expected - %s, Actual - %s"
        #     % (blk_meta.id, hashlib.sha256(ciph_data).hexdigest()))

        cipher = AESCipher(blk_meta.symkey)
        return cipher.decrypt(ciph_data)

    def _export_root_inode_pointer_to_dht(self, rootMeta):
        encrypted_root_block = self.km.gpg.encrypt(pickle.dumps(rootMeta),
                                                   self.km.gpg_key['fingerprint'])
        BuddyNode.get_node(self.start_port, self.known_ip, self.known_port).set_root(
            self.km.gpg_key['fingerprint'], encrypted_root_block.data)

    def generate_root_inode(self):
        if self.ROOT_INODE is not None:
            raise "Attempting to overwrite root inode"

        self.ROOT_INODE = self.new_inode()
        self.ROOT_INODE.parent = self.ROOT_INODE.id
        self.ROOT_INODE.permissions = (stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH |
                                       stat.S_IFDIR | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

        rootMeta = BlockMetadata()
        dirMeta = self.ROOT_INODE.blockMetadata = DirMetadata()
        self._commit_block_(rootMeta, dirMeta)

        self.ROOT_INODE.bid = rootMeta.id
        self._export_root_inode_pointer_to_dht(rootMeta)

    def register_root_inode(self, root_block):
        if self.ROOT_INODE is not None:
            raise "Attempting to overwrite root inode"

        self.ROOT_INODE = self.new_inode()

        decrypted_root_block = self.km.gpg.decrypt(root_block.values()[0])
        self.ROOT_INODE.blockMetadata = pickle.loads(decrypted_root_block.data)
        self.ROOT_INODE.bid = self.ROOT_INODE.blockMetadata.id
        self.ROOT_INODE.blockMetadata = self._read_block_(self.ROOT_INODE.blockMetadata)

        self._explore_childnodes_(self.ROOT_INODE)

        self.ROOT_INODE.parent = self.ROOT_INODE.id
        self.ROOT_INODE.permissions = (stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH |
                                       stat.S_IFDIR | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    def _explore_childnodes_(self, inode):
        if inode.explored:
            return

        for i in range(0, len(inode.blockMetadata.subdirs)):
            child = self.new_inode()
            inode.children.append(child.id)
            child.blockMetadata = self._read_block_(inode.blockMetadata.subdirs[i])
            child.parent = inode.id
            child.name = child.blockMetadata.name
            child.isDir = True
            child.permissions = (stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH |
                                 stat.S_IFDIR | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

        for i in range(0, len(inode.blockMetadata.files)):
            child = self.new_inode()
            inode.children.append(child.id)
            child.blockMetadata = self._read_block_(inode.blockMetadata.files[i])
            child.parent = inode.id
            child.name = child.blockMetadata.name
            child.isDir = False
            child.permissions = (stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH |
                                 stat.S_IFREG)

    def new_inode(self):
        next_id = self.__get_next_id()
        new_inode = Inode(next_id)
        self.inodes[next_id] = new_inode
        return new_inode

    def __get_next_id(self):
        self.__current_id += 1
        return self.__current_id

    def get_inode_for_id(self, _id):
        return self.inodes[_id]

    def get_parent(self, inode):
        return self.get_inode_for_id(inode).parent

    def rename(self, inode_p_old, name_old, inode_p_new, name_new):
        raise 'Not implemented rename'

    def link(self, inode, new_inode_p, new_name):
        raise 'Not implemented link'

    def release(self, fh):
        raise 'Not implemented release'

    def rmdir(self, inode_p, name):
        raise 'Not implemented rmdir'

    def unlink(self, inode_p, name):
        logger.debug('Unlinking %s in %d', name, inode_p)
        node = self._lookup(inode_p, name)
        inode = self.get_inode_for_id(node)

        if inode.isDir:
            raise llfuse.FUSEError(errno.EISDIR)

        parent = self.get_inode_for_id(inode.parent)
        i = 0
        while i < len(parent.blockMetadata.files):
            logger.debug('Iterating %d: ID %s BID %s', i, parent.blockMetadata.files[i].id,
                         inode.bid)
            if parent.blockMetadata.files[i].id == inode.bid:
                parent.blockMetadata.files[i] = parent.blockMetadata.files[
                    len(parent.blockMetadata.files) - 1]
                del parent.blockMetadata.files[len(parent.blockMetadata.files) - 1]

                parent.children.remove(node)
                pparent = self.get_inode_for_id(parent.parent)
                for mblock in pparent.blockMetadata.subdirs:
                    if mblock.id == parent.bid:
                        self._commit_block_(mblock, parent.blockMetadata)
                        break

                break
            else:
                i += 1

    def _lookup(self, dir_id, name):
        inode = None
        if name == '.':
            inode = dir_id
        elif name == '..':
            inode = self.get_parent(dir_id)
        else:
            parent = self.get_inode_for_id(dir_id)
            for child_id in parent.children:
                child = self.get_inode_for_id(child_id)
                if child.name == name:
                    inode = child.id

        if inode:
            return inode

        return None

    def lookup(self, dir_id, name):
        inode = self._lookup(dir_id, name)

        if inode:
            return self.getattr(inode)

        raise llfuse.FUSEError(errno.ENOENT)

    def setattr(self, inode, attr):
        if attr.st_size is not None:
            node = self.get_inode_for_id(inode)
            logger.debug('Resizing file %d from %d to %d bytes', inode, node.size, attr.st_size)
            node.size = node.blockMetadata.length = attr.st_size

            bs = int(node.blockMetadata.block_size)
            curr_block_count = len(node.blockMetadata.blocks)
            new_block_count = (attr.st_size + bs - 1) / bs

            if new_block_count > curr_block_count:
                logger.debug('Expanding block list from %d to %d blocks', curr_block_count,
                             new_block_count)
                blocks_to_add = new_block_count - curr_block_count
                node.blockMetadata.blocks.extend(blocks_to_add * [BlockMetadata()])

        if attr.st_mode is not None:
            logger.warning('[Not Implemented] SetAttr: Changing mode(%d) to %d', inode,
                           attr.st_mode)

        if attr.st_uid is not None:
            logger.warning('[Not Implemented] SetAttr: Changing uid(%d) to %d', inode,
                           attr.st_uid)

        if attr.st_gid is not None:
            logger.warning('[Not Implemented] SetAttr: Changing gid(%d) to %d', inode,
                           attr.st_gid)

        if attr.st_rdev is not None:
            logger.warning('[Not Implemented] SetAttr: Changing rdev(%d) to %d', inode,
                           attr.st_rdev)

        if attr.st_atime is not None:
            logger.warning('[Not Implemented] SetAttr: Changing atime(%d) to %d', inode,
                           attr.st_atime)

        if attr.st_mtime is not None:
            logger.warning('[Not Implemented] SetAttr: Changing mtime(%d) to %d', inode,
                           attr.st_mtime)

        if attr.st_ctime is not None:
            logger.warning('[Not Implemented] SetAttr: Changing ctime(%d) to %d', inode,
                           attr.st_ctime)

        return self.getattr(inode)

    def getattr(self, inode):
        node = self.get_inode_for_id(inode)

        entry = llfuse.EntryAttributes()
        entry.st_ino = inode
        entry.generation = 0
        entry.entry_timeout = 300
        entry.attr_timeout = 300
        entry.st_mode = node.permissions

        if node.isDir:
            entry.st_nlink = len(node.children) + 1
        else:
            entry.st_nlink = 1

        entry.st_uid = node.uid
        entry.st_gid = node.gid
        entry.st_rdev = 0
        entry.st_size = node.size

        entry.st_blksize = 512
        entry.st_blocks = 1
        entry.st_atime = node.atime
        entry.st_mtime = node.mtime
        entry.st_ctime = node.ctime

        return entry

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s: s[0:-ord(s[-1])]


class AESCipher:

    def __init__(self, key):
        self.key = key

    def encrypt(self, raw):
        raw = pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(raw)

    def decrypt(self, enc):
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(enc[16:]))


class BuddyFSOperations(llfuse.Operations):

    """BuddyFS implementation of llfuse Operations class."""

    def __init__(self, key_id, start_port, known_ip, known_port):
        super(BuddyFSOperations, self).__init__()
        self.km = KeyManager(key_id)
        self.tree = FSTree(self.km, start_port, known_ip, known_port)
        self.start_port = int(start_port)
        self.known_ip = known_ip
        if known_port is not None:
            self.known_port = int(known_port)
        else:
            self.known_port = None

    def statfs(self):
        stat_ = llfuse.StatvfsData()

        free_bytes = 0
        total_bytes = 0

        stat_.f_bsize = 512
        stat_.f_frsize = 512

        size = total_bytes
        stat_.f_blocks = size // stat_.f_frsize
        stat_.f_bfree = free_bytes // stat_.f_frsize
        stat_.f_bavail = stat_.f_bfree

        stat_.f_favail = stat_.f_ffree = stat_.f_files = 10000

        return stat_

    def lookup(self, dir_id, name):
        return self.tree.lookup(dir_id, name)

    def opendir(self, inode):
        logger.debug('Opendir for Inode %d', inode)
        return inode

    def readdir(self, inode, off):
        node = self.tree.get_inode_for_id(inode)

        i = off
        for child_id in node.children[off:]:
            child = self.tree.get_inode_for_id(child_id)
            if child.name.count('/') == 0:
                i += 1
                yield (child.name.replace('/', '//'), self.getattr(child.id), i)

    def getattr(self, inode):
        return self.tree.getattr(inode)

    def unlink(self, inode_p, name):
        return self.tree.unlink(inode_p, name)

    def setattr(self, inode, attr):
        return self.tree.setattr(inode, attr)

    def open(self, inode, flags):
        logger.debug('Opening file %d with flags %s', inode, flags)

        if inode not in self.tree.inode_open_count:
            self.tree.inode_open_count[inode] = 0
        self.tree.inode_open_count[inode] += 1
        return inode

    def access(self, inode, mode, ctx):
        return True

    def create(self, parent_inode_id, name, mode, flags, ctx):
        parent_inode = self.tree.get_inode_for_id(parent_inode_id)
        child_inode = self.tree.new_inode()
        child_inode.parent = parent_inode_id
        child_inode.isDir = False
        child_inode.name = name
        child_inode.permissions = mode
        parent_inode.children.append(child_inode.id)
        self.open(child_inode.id, flags)

        blockMeta = BlockMetadata()
        child_inode.blockMetadata = fileMeta = FileMetadata()
        fileMeta.name = name
        self.tree._commit_block_(blockMeta, fileMeta)
        child_inode.bid = blockMeta.id

        parent_inode.blockMetadata.files.append(blockMeta)
        if parent_inode == self.tree.ROOT_INODE:
            # Special treatment for ROOT inode
            metaStore = BlockMetadata()
            self.tree._commit_block_(metaStore, parent_inode.blockMetadata)
            encrypted_root_block = self.km.gpg.encrypt(pickle.dumps(metaStore),
                                                       self.km.gpg_key['fingerprint'])
            BuddyNode.get_node(self.start_port, self.known_ip, self.known_port).set_root(
                self.km.gpg_key['fingerprint'], encrypted_root_block.data)
        else:
            pparent = self.tree.get_inode_for_id(parent_inode.parent)
            for mblock in pparent.blockMetadata.files:
                if mblock.id == parent_inode.bid:
                    self.tree._commit_block_(mblock, parent_inode.blockMetadata)
                    break

        return (child_inode.id, self.getattr(child_inode.id))

    def mkdir(self, parent_inode_id, name, mode, ctx):
        logger.debug('Mkdir: %s in parent %d', name, parent_inode_id)
        parent_inode = self.tree.get_inode_for_id(parent_inode_id)
        child_inode = self.tree.new_inode()
        child_inode.parent = parent_inode_id
        child_inode.isDir = True
        child_inode.children = []
        child_inode.name = name
        child_inode.permissions = mode
        parent_inode.children.append(child_inode.id)

        dirMeta = child_inode.blockMetadata = DirMetadata()
        dirMeta.name = name
        blockMeta = BlockMetadata()

        self.tree._commit_block_(blockMeta, dirMeta)

        parent_inode.blockMetadata.subdirs.append(blockMeta)
        metaStore = BlockMetadata()

        child_inode.bid = blockMeta.id
        if parent_inode == self.tree.ROOT_INODE:
            # Special treatment for ROOT inode
            pass
        else:
            pparent = self.tree.get_inode_for_id(parent_inode.parent)
            for mblock in pparent.blockMetadata.subdirs:
                if mblock.id == parent_inode.bid:
                    metaStore = mblock
                    break

        self.tree._commit_block_(metaStore, parent_inode.blockMetadata)

        if parent_inode == self.tree.ROOT_INODE:
            encrypted_root_block = self.km.gpg.encrypt(pickle.dumps(metaStore),
                                                       self.km.gpg_key['fingerprint'])
            BuddyNode.get_node(self.start_port, self.known_ip, self.known_port).set_root(
                self.km.gpg_key['fingerprint'], encrypted_root_block.data)

        return self.getattr(child_inode.id)

    @defer.inlineCallbacks
    def auto_create_filesystem(self):
        """
        Automatically setup filesystem structure on backend providers.
        """

        key = self.km.gpg_key['fingerprint']
        root = yield BuddyNode.get_node(self.start_port, self.known_ip,
                                        self.known_port).get_root(key)

        if root:
            self.tree.register_root_inode(root)
        else:
            logger.info('Did not find existing root inode pointer.'
                        ' Generating new root inode pointer.')
            self.tree.generate_root_inode()

    def read(self, fh, offset, remaining):
        node = self.tree.get_inode_for_id(fh)
        logger.debug('Reading range (%d, %d) from file %d (len: %d)', offset, offset + remaining,
                     fh, node.blockMetadata.length)
        bs = int(node.blockMetadata.block_size)
        buf = []

        if offset >= node.blockMetadata.length:
            # Return EOF
            return b''

        if offset + remaining > node.blockMetadata.length:
            remaining = node.blockMetadata.length - offset

        if (offset + remaining) / bs > len(node.blockMetadata.blocks):
            raise 'Too few blocks!! Expected %d, Has %d' % ((offset + remaining) / bs,
                                                            len(node.blockMetadata.blocks))

        while remaining > 0:
            blk_num = (int)(offset / bs)
            blk = self.tree._read_block_(node.blockMetadata.blocks[blk_num])

            if offset % bs != 0:
                buf += blk[offset % bs:]
                remaining -= bs - offset % bs

            else:
                buf += blk
                remaining -= min(remaining, bs)

        return ''.join(buf)

    def write(self, fh, offset, buf):
        node = self.tree.get_inode_for_id(fh)
        bs = int(node.blockMetadata.block_size)
        bytes_copied = 0

        remaining = len(buf)
        logger.debug('Writing range (%d, %d) to file %d (len: %d)', offset, offset + remaining,
                     fh, node.blockMetadata.length)

        if ((offset + remaining + bs - 1) / bs) > len(node.blockMetadata.blocks):
            max_blks = int((offset + remaining + bs - 1) / bs)
            lngth = max_blks - len(node.blockMetadata.blocks)
            node.blockMetadata.blocks.extend(lngth * [BlockMetadata()])

        while remaining:
            blk_num = int(offset / bs)

            if offset % bs != 0:
                blk = self.tree._read_block_(node.blockMetadata.blocks[blk_num])

                if (offset % bs + len(buf)) <= bs:
                    blk = blk[:offset % bs - 1] + buf
                    remaining -= len(buf)
                    offset += len(buf)
                    bytes_copied += len(buf)
                    buf = None
                else:
                    blk[offset % bs:] = buf[:bs - offset % bs - 1]
                    remaining -= (bs - offset % bs)
                    offset += (bs - offset % bs)
                    bytes_copied += (bs - offset % bs)
                    buf = buf[bs - offset % bs:]

                self.tree._commit_block_(node.blockMetadata.blocks[blk_num], blk)

            else:
                if remaining < bs:
                    blk = buf
                    offset += remaining
                    bytes_copied += remaining
                    remaining = 0
                    buf = None
                else:
                    blk = buf[:bs - 1]
                    buf = buf[bs:]
                    offset += bs
                    bytes_copied += bs
                    remaining -= bs

                self.tree._commit_block_(node.blockMetadata.blocks[blk_num], blk)

        if offset > node.size:
            node.size = offset
            node.blockMetadata.length = node.size

#        self.propagate_changes(parent)

        return bytes_copied


if __name__ == '__main__':
    # pylint: disable-msg=C0103
    parser = argparse.ArgumentParser(prog='BuddyFS',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose logging')
    parser.add_argument('-k', '--key-id', help='Fingerprint of the GPG key to use'
                        'Please make sure to specify a key without a passphrase.', required=True)
    parser.add_argument('-s', '--start-port', help='Port where the BuddyNode listens to',
                        default=5000)
    parser.add_argument('-i', '--known-ip', help='IP of the known machine in the circle')
    parser.add_argument('-p', '--known-port', help='Port of the known machine in the circle')
    parser.add_argument('mountpoint', help='Root directory of mounted BuddyFS')
    args = parser.parse_args()

    logLevel = logging.INFO
    if args.verbose:
        logLevel = logging.DEBUG

    logging.basicConfig(level=logLevel)

    operations = BuddyFSOperations(args.key_id, args.start_port, args.known_ip, args.known_port)
    operations.auto_create_filesystem()

    logger.info('Mounting BuddyFS')
    llfuse.init(operations, args.mountpoint, [b'fsname=BuddyFS'])
    logger.info('Mounted BuddyFS at %s' % (args.mountpoint))

    try:
        llfuse.main(single=False)
    except:
        llfuse.close(unmount=False)
        raise

    llfuse.close()
