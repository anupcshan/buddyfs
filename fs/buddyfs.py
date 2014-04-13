#!/usr/bin/python
"""BuddyFS FUSE filesystem."""

import argparse
import errno
import gnupg
import llfuse
import logging
import os
import stat
import sys
from time import time
from twisted.internet import defer
from Crypto import Random
from Crypto.Cipher import AES

sys.path.append(os.path.abspath(os.path.dirname(__file__) + '/..'))
from kad_server.buddynode import BuddyNode

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

class FSTree:
    """ Inode tree structure and associated utilities. """
    def __init__(self):
        self.__current_id = 0
        self.inodes = {}
        self.ROOT_INODE = None
        self.inode_open_count = {}

    def _commit_block_(self, blk_meta, blk_data):
        ciphertext = self._encrypt_block_(blk_meta, blk_data)
        BuddyNode.get_node().set_root(blk_meta.id, ciphertext)

    def _read_block_(self, blk_meta):
        ciphertext = BuddyNode.get_node().get_root(blk_meta.id)
        plaintext = self._decrypt_block_(blk_meta, blk_data)
        return plaintext

    def _encrypt_block_(self, blk_meta, blk_data):
        if blk_meta.symkey is None:
            blk_meta.symkey = Random.new().read(AES.block_size)

        cipher = AESCipher(blk_meta.symkey)
        ciphertext = cipher.encrypt(blk_data)
        blk_meta.id = hashlib.sha256(ciphertext).hexdigest()
        return ciphertext

    def _decrypt_block_(self, blk_meta, ciph_data):
        if blk_meta.symkey is None:
            raise Exception("Key not provied while trying to decrypt block")

        if hashlib.sha256(ciph_data) != blk_meta.id:
            raise Exception("Integrity check failed: block ID differs from block digest")

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

        rootMeta = self.ROOT_INODE.blockMetadata = BlockMetadata()
        dirMeta = DirMetadata()
        self._commit_block_(dirMeta, rootMeta)

        root = BuddyNode.get_node().set_root(key, self.ROOT_INODE)

    def register_root_inode(self, root_block):
        if self.ROOT_INODE is not None:
            raise "Attempting to overwrite root inode"

        self.ROOT_INODE = self.new_inode()
        self.ROOT_INODE.parent = self.ROOT_INODE.id
        self.ROOT_INODE.permissions = (stat.S_IRUSR | stat.S_IWUSR |
                stat.S_IRGRP | stat.S_IROTH | stat.S_IFDIR | stat.S_IXUSR |
                stat.S_IXGRP | stat.S_IXOTH)

        self.ROOT_INODE.blockMetadata = root_block

    def new_inode(self):
        next_id = self.__get_next_id()
        new_inode = Inode(next_id)
        self.inodes[next_id] = new_inode
        return new_inode

    def __get_next_id(self):
        self.__current_id += 1
        return self.__current_id

    def get_inode_for_id(self, _id):
        print 'Get Inode for id %d' % (_id)
        return self.inodes[_id]

    def get_parent(self, inode):
        return self.get_inode_for_id(inode).parent

    def lookup(self, dir_id, name):
        print 'Lookup of name %s under dir_id %d' % (name, dir_id)
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
        return base64.b64encode(iv + cipher.encrypt(raw)) 

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(enc[16:]))


class BuddyFSOperations(llfuse.Operations):
    """BuddyFS implementation of llfuse Operations class."""
    def __init__(self, key_id):
        super(BuddyFSOperations, self).__init__()
        self.tree = FSTree()
        self.gpg = gnupg.GPG()
        self.gpg_key = filter (lambda x :
                x.get('keyid').find(key_id) >= 0, self.gpg.list_keys(True))
        if len(self.gpg_key) != 1:
            raise 'Invalid or non-existent GPG key specified'

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
        return inode

    def readdir(self, inode, off):
        print 'Readdir of inode %d at offset %d' % (inode, off)
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
        return self.getattr(child_inode.id)

    @defer.inlineCallbacks
    def auto_create_filesystem(self):
        """
        Automatically setup filesystem structure on backend providers.
        """

        key = self.gpg_key['fingerprint']
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
    parser.add_argument('mountpoint', help='Root directory of mounted BuddyFS')
    args = parser.parse_args()

    logLevel = logging.INFO
    if args.verbose:
      logLevel = logging.DEBUG

    logging.basicConfig(level=logLevel)

    operations = BuddyFSOperations(args.key_id)
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
