#!/usr/bin/python
"""BuddyFS FUSE filesystem."""

import argparse
import cPickle as pickle
import errno
import gnupg
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

""" On-disk representation. """
class BlockMetadata:
    """ Block metedata structure. """
    def __init__(self):
        self.id = None
        self.symkey = None
        self.quorum = []

class FileMetadata:
    """ File metadata structure. """
    def __init__(self):
        # TODO: Figure out how to represent compact files within this structure.
        self.mtime = time()
        self.name = None
        self.length = 0
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


""" In-memory FS representation. """
class Inode:
    """ Inode data structure. """
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
    def __init__(self, km, start_port):
        self.__current_id = 0
        self.inodes = {}
        self.ROOT_INODE = None
        self.inode_open_count = {}
        self.km = km
        self.kf = KadFacade(start_port)

    def _commit_block_(self, blk_meta, blk_data):
        ciphertext = self._encrypt_block_(blk_meta, pickle.dumps(blk_data))
        node = BuddyNode.get_node()
        #set_root(blk_meta.id, ciphertext)
        print 'Created/updated block ID %s' % (blk_meta.id)

        node.push_to_dht(self.km.gpg_key['fingerprint'], node.get_node_id())
        print "Stored <pubkey, nodeid> mapping to DHT"
        
        pubkey_list = map(lambda x : x.get('keyid'), self.km.gpg.list_keys())
        print "pubkey list : "
        print pubkey_list
         
        peers = self.kf.get_all_peers_from_dht(pubkey_list)
        print "Peer List based on the Web of Trust Social Circle: "
        print peers

    def _read_block_(self, blk_meta):
        deferredVar = BuddyNode.get_node().get_root(blk_meta.id)

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

        if hashlib.sha256(ciph_data).hexdigest() != blk_meta.id:
            raise Exception("Integrity check failed: block ID differs from block digest: Expected - %s, Actual - %s" % (blk_meta.id, hashlib.sha256(ciph_data).hexdigest()))

        cipher = AESCipher(blk_meta.symkey)
        return cipher.decrypt(ciph_data)

    def generate_root_inode(self):
        if self.ROOT_INODE is not None:
            raise "Attempting to overwrite root inode"

        self.ROOT_INODE = self.new_inode()
        self.ROOT_INODE.parent = self.ROOT_INODE.id
        self.ROOT_INODE.permissions = (stat.S_IRUSR | stat.S_IWUSR |
                stat.S_IRGRP | stat.S_IROTH | stat.S_IFDIR | stat.S_IXUSR |
                stat.S_IXGRP | stat.S_IXOTH)

        rootMeta = BlockMetadata()
        dirMeta = self.ROOT_INODE.blockMetadata = DirMetadata()
        self._commit_block_(rootMeta, dirMeta)
        self.ROOT_INODE.bid = rootMeta.id

        encrypted_root_block = self.km.gpg.encrypt(pickle.dumps(rootMeta),
                self.km.gpg_key['fingerprint'])
        root = BuddyNode.get_node().set_root(self.km.gpg_key['fingerprint'], encrypted_root_block.data)

    def register_root_inode(self, root_block):
        if self.ROOT_INODE is not None:
            raise "Attempting to overwrite root inode"

        self.ROOT_INODE = self.new_inode()

        decrypted_root_block = self.km.gpg.decrypt(root_block.values()[0])

        self.ROOT_INODE.blockMetadata = pickle.loads(decrypted_root_block.data)

        self.ROOT_INODE.blockMetadata = self._read_block_(self.ROOT_INODE.blockMetadata)

        self._explore_childnodes_(self.ROOT_INODE)

        self.ROOT_INODE.parent = self.ROOT_INODE.id
        self.ROOT_INODE.permissions = (stat.S_IRUSR | stat.S_IWUSR |
                stat.S_IRGRP | stat.S_IROTH | stat.S_IFDIR | stat.S_IXUSR |
                stat.S_IXGRP | stat.S_IXOTH)

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
            child.permissions = (stat.S_IRUSR | stat.S_IWUSR |
                stat.S_IRGRP | stat.S_IROTH | stat.S_IFDIR | stat.S_IXUSR |
                stat.S_IXGRP | stat.S_IXOTH)

        for i in range(0, len(inode.blockMetadata.files)):
            child = self.new_inode()
            inode.children.append(child.id)
            child.blockMetadata = self._read_block_(inode.blockMetadata.subdirs[i])
            child.parent = inode.id
            child.name = child.blockMetadata.name
            child.isDir = True
            child.permissions = (stat.S_IRUSR | stat.S_IWUSR |
                stat.S_IRGRP | stat.S_IROTH | stat.S_IFDIR | stat.S_IXUSR |
                stat.S_IXGRP | stat.S_IXOTH)

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

    def lookup(self, dir_id, name):
        inode = None
        if name == '.':
            inode = dir_id
        elif name == '..':
            inode = self.get_parent(dir_id)
        else:
            parent = self.get_inode_for_id(self.get_parent(dir_id))
            for child_id in parent.children:
                child = self.get_inode_for_id(child_id)
                if child.name == name:
                    inode = child.id

        if inode:
            return self.getattr(inode)

        raise(llfuse.FUSEError(errno.ENOENT))

    def getattr(self, inode):
        node = self.get_inode_for_id(inode)
        print 'Calling getattr on inode %d : %s' % (inode, node.name)

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
unpad = lambda s : s[0:-ord(s[-1])]

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
    def __init__(self, key_id, start_port):
        super(BuddyFSOperations, self).__init__()
        self.km = KeyManager(key_id)
        self.tree = FSTree(self.km, start_port)

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
        print 'Opendir for Inode %d' % (inode)
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

    def setattr(self, inode, attr):
        logging.info('Setattr not implemented: Inode %d' % (inode))
        return self.getattr(inode)

    def open(self, inode, flags):
        print 'Opening file %d with flags %s' % (inode, flags)

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

        child_inode.blockMetadata = BlockMetadata()
        fileMeta = FileMetadata()
        fileMeta.name = name
        self.tree._commit_block_(child_inode.blockMetadata, fileMeta)

        parent_inode.blockMetadata.files.append(fileMeta)
        if parent_inode == self.tree.ROOT_INODE:
            # Special treatment for ROOT inode
            pass
        else:
            pparent = self.tree.get_inode_for_id(parent_inode.parent)
            self.tree._commit_block_(parent_inode.blockMetadata, pparent.blockMetadata)

        return (child_inode.id, self.getattr(child_inode.id))

    def mkdir(self, parent_inode_id, name, mode, ctx):
        print 'Mkdir: %s in parent %d' % (name, parent_inode_id)
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
        print parent_inode.blockMetadata.subdirs
        metaStore = BlockMetadata()
        if parent_inode == self.tree.ROOT_INODE:
            # Special treatment for ROOT inode
            pass
        else:
            metaStore = self.tree.get_inode_for_id(parent_inode.parent).blockMetadata

        self.tree._commit_block_(metaStore, parent_inode.blockMetadata)

        if parent_inode == self.tree.ROOT_INODE:
            encrypted_root_block = self.km.gpg.encrypt(pickle.dumps(metaStore), self.km.gpg_key['fingerprint'])
            root = BuddyNode.get_node().set_root(self.km.gpg_key['fingerprint'], encrypted_root_block.data)


        return self.getattr(child_inode.id)

    @defer.inlineCallbacks
    def auto_create_filesystem(self):
        """
        Automatically setup filesystem structure on backend providers.
        """

        key = self.km.gpg_key['fingerprint']
        root = yield BuddyNode.get_node().get_root(key)
        
        if root:
            self.tree.register_root_inode(root)
        else:
            logging.info('Did not find existing root inode pointer.'
                    ' Generating new root inode pointer.')
            self.tree.generate_root_inode()

if __name__ == '__main__':
    # pylint: disable-msg=C0103 
    parser = argparse.ArgumentParser(prog='BuddyFS')
    parser.add_argument('-v', '--verbose', action='store_true',
        help='Enable verbose logging')
    parser.add_argument('-k', '--key-id', help='Fingerprint of the GPG key to use.'
            'Please make sure to specify a key without a passphrase.', required=True)
    parser.add_argument('-s', '--start-port', help='Port where the BuddyNode listens to.')
    parser.add_argument('mountpoint', help='Root directory of mounted BuddyFS')
    args = parser.parse_args()

    logLevel = logging.INFO
    if args.verbose:
      logLevel = logging.DEBUG

    logging.basicConfig(level=logLevel)

    operations = BuddyFSOperations(args.key_id, args.start_port)
    operations.auto_create_filesystem()
    
    logging.info('Mounting BuddyFS')
    llfuse.init(operations, args.mountpoint, [ b'fsname=BuddyFS' ])
    logging.info('Mounted BuddyFS at %s' % (args.mountpoint))
    
    try:
        llfuse.main(single=False)
    except:
        llfuse.close(unmount=False)
        raise

    llfuse.close()
