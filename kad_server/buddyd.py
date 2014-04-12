import sys, os
import os.path
import twisted
sys.path.append(os.path.abspath(os.path.dirname(__file__) + '/..'))
import settings
from kad_server.buddynode import BuddyNode
from entangled.kademlia.datastore import SQLiteDataStore

if __name__ == '__main__':
	print "Starting buddy-daemon on port " , settings.BUDDY_PORT

	" Check if the node already has a Node ID, create one if not present "
	datastore = SQLiteDataStore(dbFile = settings.DBPATH+'/buddydht.db')
	node = BuddyNode(id, settings.BUDDY_PORT, datastore)
	
	" Check DHT for previously connected peers. Next step, check with trackers for the last connected user and get the peer list "

	twisted.internet.reactor.run()

