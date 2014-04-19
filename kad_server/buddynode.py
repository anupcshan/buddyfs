"""
This will be the fundamental part of the buddy daemon.
Starts a Kademlia node and implements functionality for Node ID verification.
"""
from entangled.kademlia.node import Node
from entangled.kademlia.datastore import SQLiteDataStore
import cPickle as pickle
import hashlib
import logging
import os
import settings
import time
import twisted


logger = logging.getLogger(__name__)


class BuddyNode(Node):

    """ Kademlia node with a few helper functions for BuddyFS """

    node = None

    @classmethod
    def get_node(cls, start_port, known_ip=None, known_port=None):
        if BuddyNode.node is not None:
            return BuddyNode.node

        dbpath = settings.DBPATH + '/buddydht-%s.db' % start_port
        datastore = SQLiteDataStore(dbFile=dbpath)
        logger.info('Starting buddy-daemon on port %d', start_port)
        BuddyNode.node = BuddyNode(None, start_port, datastore)
        if known_ip is None or known_port is None:
            BuddyNode.node.joinNetwork([])
        else:
            BuddyNode.node.joinNetwork([(known_ip, known_port)])
            logger.debug('Bootstrap with node %s:%s', known_ip, known_port)

        return BuddyNode.node

    def __init__(self, nodeid, udpPort, dataStore, routingTable=None, networkProtocol=None):
        if nodeid is None:
            nodeid = self.get_node_id()
        super(BuddyNode, self).__init__(nodeid, udpPort, dataStore, routingTable, networkProtocol)
        logger.debug('Singleton node created')
        BuddyNode.node = self
        return

    def get_node_id(self):
        nodeid = ''
        if os.path.isfile('.nodeid'):
            logger.debug('NodeID file exists')
            f = open('.nodeid', 'r')
            x = f.read()
            if x != '':
                logger.debug('Reusing NodeID %s', x)
                return x

        " Create new node id and store it in .nodeid file "
        file = open('.nodeid', 'w+')
        nodeid = self._generateID()
        logger.debug('New NodeID generated : %s', nodeid)
        file.write(nodeid)
        file.close()
        return nodeid

    def get_root(self, pubkey):
        datastore = SQLiteDataStore(dbFile=settings.DBPATH + '/buddydht.db')
        key = hashlib.sha1('root_' + pubkey).digest()
        return self.iterativeFindValue(key)

    def set_root(self, pubkey, root_inode):
        datastore = SQLiteDataStore(dbFile=settings.DBPATH + '/buddydht.db')
        key = hashlib.sha1('root_' + pubkey).digest()
        self.iterativeStore(key, root_inode, self.get_node_id(), 0)
