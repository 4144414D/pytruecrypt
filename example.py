from pytruecrypt import *
import binascii
import os
from subprocess import *

FILENAME = "/home/gho/test.tc"
PASSWORD = "abc123"

#initialise pytruecrypt
tc = PyTruecrypt(FILENAME, PASSWORD)

#open volume (returns false on failure)
if not tc.open():
	print "Failed to open volume -maybe incorrect pw"
	sys.exit(1)

#Print header fields
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

#if root - mount it
if os.getuid() == 0:
	#find a free loopback device
	child = Popen("losetup -f", shell=True, stdout=PIPE)
	output, errors = child.communicate();
	freeLoopback = output.strip()

	#setup loopback
	os.system("losetup %s %s" % (freeLoopback, FILENAME))

	#setup linux device mapper so can mount volume
	dmtable = tc.getDeviceMapperTable(freeLoopback)
	print dmtable

	#create dm target /dev/mapper/tcrypt
	os.system('echo %s | dmsetup create tcrypt' % (dmtable))

	print "Tcryptdevice on /dev/mapper/tcrypt - you may now mount it"
	#You may now have to mount this manually if your linux doesn't automatically)
	# mount /dev/mapper/tcrypt wheretomount

	#to undo
	#unmount
	#dmsetup remove tcrypt
	#losetup -d /dev/loop0
else:
	print "Must be root to mount"

