There are two components in BuddyFS. FUSE and the Kad Facade

FUSE :
======

File System APIs - Implement FS requests. Implement the network calls required.

Specific calls :
read() - 
	Get FCB from local storage
	Get the block IDs and the nodes IDs from FCB, and spawn requests.
	FOR READ/WRITE : Wait until QUORUM threads give same block for a block ID request. 
	return

write()
	Get the FCB from local storage.
	Chunk the data into blocks of BLOCK_SIZE (depending on the file requirements)
	Generate Block IDs for the different blocks created. (Individual blocks are ready to be pushed)
	Get the peer list from Kademlia. 
		Get the social-graph (potentially writeable) public keys from the key-server.
		Use those public keys to fetch the list of node IDs.
	Cap the list to quorum size (selection is random or via heuristics on network properties)
	Spawn QUORUM*2-1 threads and waits for QUORUM positive responses.
	Update FCB with block IDs, and node IDs for each block ID.		
	return

create()
	User touches/copies file into mounted directory
	Filename and uniqueness Validations, Quorum size validations.
	Create an empty FCB
	return
	
close()
	If FCB is dirty, then publish the updated FCB and blocks to quorum.
	If FCB not dirty, no op.


Kad facade :
============

GetPeers(public_keys)
	DHT lookup

Write Block
	Check circle to see if this request should go through
	If not present, send "reject" immediately to the requestor
	If present, accept block and store it in local storage. Send back "success" after write goes through.
	
Read Block :
	Read block using block ID, else return "false"
