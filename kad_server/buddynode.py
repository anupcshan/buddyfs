"""
This will be the fundamental part of the buddy daemon. Starts a Kademlia node and implements functionality for Node ID verification.
"""
from entangled import kademlia
from entangled.kademlia.datastore import SQLiteDataStore
import cPickle as pickle
import os
import settings
import time
import hashlib

class BuddyNode(kademlia.node.Node):
    """ Kademlia node with a few helper functions for BuddyFS """

    node = None

    @classmethod
    def get_node(cls, start_port=settings.BUDDY_PORT, known_ip=None, known_port=None):
        if BuddyNode.node:
            return BuddyNode.node
        
        dbpath = settings.DBPATH+'/buddydht-%s.db' % start_port
        datastore = SQLiteDataStore(dbFile = dbpath)
        print "Starting buddy-daemon on port " , start_port
        BuddyNode.node = BuddyNode(None, start_port, datastore)
        if(known_ip == None or known_port == None):
            BuddyNode.node.joinNetwork([])
        else :
            BuddyNode.node.joinNetwork([(known_ip, known_port)])
        return BuddyNode.node

    def __init__(self, nodeid, udpPort, dataStore, routingTable=None, networkProtocol=None) :
        if nodeid is None:
            nodeid=self.get_node_id()
        kademlia.node.Node.__init__(self, nodeid, udpPort, dataStore, routingTable, networkProtocol)
        BuddyNode.node = self

    def get_node_id(self) :
        nodeid = ""
        if(os.path.isfile(".nodeid")):
            f = open(".nodeid","r")
            x = f.read()
            if x != "":
                return x

        " Create new node id and store it in .nodeid file "
        file = open(".nodeid", "w+")
        nodeid = self._generateID()
        print "New NodeID generated : ", nodeid
        file.write(nodeid)
        file.close()
        return nodeid
    
    def get_root(self, pubkey):
        datastore = SQLiteDataStore(dbFile = settings.DBPATH+'/buddydht.db')
        key = hashlib.sha1("root_"+pubkey).digest()
        return self.iterativeFindValue(key)

    def set_root(self, pubkey, root_inode):
        datastore = SQLiteDataStore(dbFile = settings.DBPATH+'/buddydht.db')
        key = hashlib.sha1("root_"+pubkey).digest()
        self.iterativeStore(key, pickle.dumps(root_inode, pickle.HIGHEST_PROTOCOL), self.get_node_id(), 0)

