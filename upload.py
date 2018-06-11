#!/usr/bin/env python3
#
# Name: VT upload
# Description: Determines if malware has already been uploaded. if it hasn't, upload. Get results on malware.
import hashlib

BLOCKSIZE = 65536
hasher = hashlib.sha256()
with open('a55b9addb2447db1882a3ae995a70151', 'rb') as afile:
    buf = afile.read(BLOCKSIZE)
    while len(buf) > 0:
        hasher.update(buf)
        buf = afile.read(BLOCKSIZE)
print(hasher.hexdigest())