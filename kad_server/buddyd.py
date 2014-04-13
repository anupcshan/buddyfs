import sys
import os.path
import twisted
sys.path.append(os.path.abspath(os.path.dirname(__file__) + '/..'))
import settings
from kad_server.buddynode import BuddyNode

if __name__ == '__main__':

    " Check if the node already has a Node ID, create one if not present "
    if(len(sys.argv)==1):
        BuddyNode.get_node()
    elif(len(sys.argv)==2):
        BuddyNode.get_node(int(sys.argv[1]))
    elif (len(sys.argv)==4):
        BuddyNode.get_node(int(sys.argv[1]), sys.argv[2], int(sys.argv[3]))
    else: 
       print "USAGE : ./buddy.sh <start_port> <known_ip> <known_port>" 
       sys.exit(1)
    
    " Check DHT for previously connected peers. Next step, check with trackers for the last connected user and get the peer list "
    twisted.internet.reactor.run()
