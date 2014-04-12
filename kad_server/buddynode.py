"""
This will be the fundamental part of the buddy daemon. Starts a Kademlia node and implements functionality for Node ID verification.
"""
from entangled import kademlia
from entangled.kademlia.datastore import SQLiteDataStore
import cPickle as pickle
import os
import settings
import time

class BuddyNode(kademlia.node.Node):
    """ Kademlia node with a few helper functions for BuddyFS """

    node = None

    @classmethod
    def get_node(cls):
        if BuddyNode.node:
            return BuddyNode.node

        datastore = SQLiteDataStore(dbFile = settings.DBPATH+'/buddydht.db')
        BuddyNode.node = BuddyNode(id, settings.BUDDY_PORT, datastore)
        return BuddyNode.node

    def __init__(self, nodeid, udpPort, dataStore, routingTable=None, networkProtocol=None) :
        if(nodeid==""):
            nodeid=get_node_id()
        kademlia.node.Node.__init__(self, nodeid, udpPort, dataStore, routingTable, networkProtocol)
        BuddyNode.node = self

    def get_node_id(self) :
        nodeid = ""
        if(os.path.isfile(".nodeid")):
            file = open(".nodeid","r")
            if(file.read()!=""):
                return file.read();

        " Create new node id and store it in .nodeid file "
        file = open(".nodeid", "w+")
        nodeid = self._generateID()
        print "New NodeID generated : ", nodeid
        file.write(nodeid)
        file.close()
    
    def get_root(self, pubkey):
        datastore = SQLiteDataStore(dbFile = settings.DBPATH+'/buddydht.db')
        return pickle.loads(datastore.__getitem__("root_"+pubkey))

    def set_root(self, pubkey, root_inode):
        datastore = SQLiteDataStore(dbFile = settings.DBPATH+'/buddydht.db')
        datastore.setItem("root_"+pubkey, pickle.dumps(root_inode, pickle.HIGHEST_PROTOCOL), int(time.time()), int(time.time()), self.get_node_id())

