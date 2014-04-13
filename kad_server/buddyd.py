import sys
import os
import traceback
import os.path
import json
import twisted
sys.path.append(os.path.abspath(os.path.dirname(__file__) + '/..'))
import settings
from kad_server.buddynode import BuddyNode
from twisted.internet.protocol import Protocol, Factory

class RPCServer(Protocol):
  
  def write_block(self):
    pass

  def read_block(self):
    pass

  def diskusage(self):
    st = os.statvfs(".")
    response = {}
    response["total_bytes"] = st.f_blocks * st.f_frsize
    response["free_bytes"] = st.f_bavail * st.f_frsize
    response["used_bytes"] = (st.f_blocks - st.f_bfree) * st.f_frsize
    self.transport.write(json.dumps(response))
    return
  
  def dataReceived(self, data):
    try:
      cmd = json.loads(data)
      command = cmd["command"]
      if(command=="du"):
        self.diskusage()
      elif(command=="write"):
        self.write_block()
      elif(command=="read"):
        self.read_block()
      else:
        raise Exception("Unsupported operation")
    except :
      traceback.print_exc(file=sys.stdout)
      errorObj = {}
      errorObj["type"] = "Error"
      errorObj["reason"] = "Invalid Request"
      self.transport.write(json.dumps(errorObj))

factory = Factory()
factory.protocol = RPCServer
twisted.internet.reactor.listenTCP(9000, factory)

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
