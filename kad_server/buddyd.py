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
from entangled.kademlia.datastore import SQLiteDataStore
from os.path import expanduser
home = expanduser("~")

daemon_port = "9000"


class KadFacade(object):

    def __init__(self, start_port):
        self.dbpath = settings.DBPATH + '/buddydht-%s.db' % start_port
        self.kadstore = SQLiteDataStore(dbFile=self.dbpath)

    def get_all_peers_from_dht(self, pubkeys):
        """ Getting the list of all public keys on a circle's DHT is tough
            because there is no content specific flag on the hash table
            entries. """
        keys = self.kadstore.keys()
        return keys

    def get_peers(pubkeys):
        all_peers = get_all_peers_from_dht()


class RPCServer(Protocol):

    def __init__(self):
        self.data = ""

    def write_block(self):
        """ ~/.buddyrepo is the repository by default (configurable in
            settings.py file). Filename will be the blockID and contents
            the block data. Blocks will be sharded based on the first 8 bits
            into 16 bins """
        reponame = settings.REPONAME
        if not os.path.exists(home + "/" + reponame):
            os.mkdir(home + "/" + reponame + "/", 0o755)

        block_bin = str(self.data["id"] % 16)
        block_bin = block_bin.zfill(3)
        if not os.path.exists(home + "/" + reponame + "/" + block_bin):
            os.mkdir(home + "/" + reponame + "/" + block_bin + "/", 0o755)

        with open(home + "/" + reponame + "/" + block_bin + "/" + str(self.data["id"]), "w+") as f:
            print "File creation in process : " + home + "/" + reponame + "/" + block_bin + "/" \
                + str(self.data["id"])
            print "Creating file with content " + self.data["data"]
            try:
                f.write(self.data["data"])
                f.flush()
                f.close()
            except IOError as err:
                (errno, strerror) = err.args
                print "I/O error({0}): {1}".format(errno, strerror)

        response = {}
        response["result"] = "ack"
        self.transport.write(json.dumps(response))
        return

    def read_block(self):
        reponame = settings.REPONAME
        block_bin = str(self.data["id"] % 16)
        block_bin = block_bin.zfill(3)

        if not os.path.exists(home + "/" + reponame + "/" + block_bin + "/" + str(self.data["id"])):
            response = {}
            response["type"] = "error"
            response["reason"] = "content unavailable"
            self.transport.write(json.dumps(response))
            return

        f = open(home + "/" + reponame + "/" + block_bin + "/" + str(self.data["id"]), 'r')
        response = {}
        response["data"] = f.read()
        f.close()
        self.transport.write(json.dumps(response))
        return

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
            self.data = cmd
            command = cmd["command"]
            if(command == "du"):
                self.diskusage()
            elif(command == "write"):
                self.write_block()
            elif(command == "read"):
                self.read_block()
            else:
                raise Exception("Unsupported operation")
        except:
            traceback.print_exc(file=sys.stdout)
            errorObj = {}
            errorObj["type"] = "Error"
            errorObj["reason"] = "Invalid Request"
            self.transport.write(json.dumps(errorObj))

factory = Factory()
factory.protocol = RPCServer

if __name__ == '__main__':

    " Check if the node already has a Node ID, create one if not present "
    if(len(sys.argv) == 1):
        BuddyNode.get_node()
    elif(len(sys.argv) == 2):
        BuddyNode.get_node(int(sys.argv[1]))
    elif (len(sys.argv) == 4):
        BuddyNode.get_node(int(sys.argv[1]), sys.argv[2], int(sys.argv[3]))
    elif (len(sys.argv) == 5):
        daemon_port = sys.argv[2]
        BuddyNode.get_node(int(sys.argv[1]), sys.argv[3], int(sys.argv[4]))
    else:
        print "USAGE : ./buddy.sh <start_port> <known_ip> <known_port>"
        sys.exit(1)

    twisted.internet.reactor.listenTCP(int(daemon_port), factory)
    " Check DHT for previously connected peers. Next step, check with trackers for the last connected user and get the peer list "
    twisted.internet.reactor.run()
