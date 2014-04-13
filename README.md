BuddyFS
=======

A distributed, secure file system to share storage space on your computer with your friends. Your social network of friends is based on the web-of-trust model as seen in PGP systems.

Why a new Filesystem?
---------------------
Though the existing filesystems seemingly provide the required the required functionalities of a filesystem, we strongly believe that the technology trends can enable a more powerful storage (and compute) environment. Following are the goals of our filesystem :

* Reliability - A file could be recreated from other peers even if the original host which created the file has lost/corrupted it.
* Sharing - Other peers could access files which another peer has shared with him/her.
* Security - Files should be spread out over untrusted nodes and transmitted over untrusted networks without anyone else being able to gather useful information about file content.
* Integrity - It should be impossible to fake or modify contents of someone’s file or folder listing without them knowing about it.
* Ubiquity - Accessible anywhere! (Future)

Apart from the above goals, we should be able to lease out part of our storage space in exchange for digital currencies. 

Technologies
------------
FUSE for file system layer
Entangled - An implementation of Kademlia for P2P routing
PyCrypto - (A)Symmetric cryptography
Twisted - Network communications

Status
------
Currently in development. Please contact the authors if you are interested in this idea.



