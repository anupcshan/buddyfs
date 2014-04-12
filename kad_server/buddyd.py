import sys, os
sys.path.append(os.path.abspath(".."))
from buddyfs import settings

if __name__ == '__main__':
	port = settings.BUDDY_PORT
	print "Starting buddy-daemon on port " , port
