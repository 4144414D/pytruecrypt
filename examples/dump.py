import sys

sys.path.append("..")


from pytruecrypt import *
import binascii
import os
from subprocess import *
import stat
import getpass

if len(sys.argv) != 2:
	print "Usage: python dump.py volumepath"
	sys.exit(1)

FILENAME = sys.argv[1]
PASSWORD = getpass.getpass("Enter password: ")

#initialise pytruecrypt
tc = PyTruecrypt(FILENAME)

#open volume (returns false on failure)
if not tc.open(PASSWORD):
	print "Failed to open volume -maybe incorrect pw"
	sys.exit(1)

#Print header fields
print "HEADER RAW ----------"
print hexdump(tc.getHeaderRaw())

print "HEADER ------------"
hdr = tc.getHeader()
for k in hdr:
	print k, ":", 

	if k=="Keys":
		print binascii.hexlify(hdr[k])	
	else:	
		print hdr[k]

#Print first sector
print "FIRST SECTOR-------"
print hexdump(tc.getPlainSector(0))

