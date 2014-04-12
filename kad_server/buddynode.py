"""
This will be the fundamental part of the buddy daemon. Starts a Kademlia node and implements functionality for Node ID verification.
"""
from buddyfs.entangled import kademlia

class BuddyNode(kademlia.node.Node):
	""" Kademlia node with a few helper functions for BuddyFS """

	def __init__(self, nodeid, udpPort, dataStore, routingTable=None, networkProtocol=None) :
		if(nodeid==""):
			nodeid=get_node_id()
		kademlia.node.Node.__init__(self, nodeid, udpPort, dataStore, routingTable, networkProtocol)

	def get_node_id(self) :
		nodeid = ""
		if(os.path.isfile(".nodeid")):
			file = open(".nodeid","r")
			if(file.read()!=""):
				return file.read();

		" Create new node id and store it in .nodeid file "
		file = open(".nodeid", "w+")
		nodeid = kademlia.node.Node._generateID()
		print "New NodeID generated : ", nodeid
		file.write(nodeid)
		file.close()


