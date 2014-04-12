import sys
import os.path
import twisted
sys.path.append(os.path.abspath(os.path.dirname(__file__) + '/..'))
import settings
from kad_server.buddynode import BuddyNode

if __name__ == '__main__':
    print "Starting buddy-daemon on port " , settings.BUDDY_PORT

    " Check if the node already has a Node ID, create one if not present "
    BuddyNode.get_node()
    
    " Check DHT for previously connected peers. Next step, check with trackers for the last connected user and get the peer list "

    twisted.internet.reactor.run()

