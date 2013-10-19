# Truecrypt parsing library for Python by Gareth Owen
# https://github.com/drgowen/pytruecrypt/
# See LICENCE for licence details

# Truecrypt volume mounter for Linux

import sys

sys.path.append("..")


from pytruecrypt import *
import binascii
import os
from subprocess import *
import stat
import getpass

if len(sys.argv) != 2:
	print "Usage: python mount.py volumepath"
	sys.exit(1)

FILENAME = sys.argv[1]
PASSWORD = getpass.getpass("Enter password: ")

#initialise pytruecrypt
tc = PyTruecrypt(FILENAME)

#open volume (returns false on failure)
if not tc.open(PASSWORD, hidden=False):
	print "Failed to open volume -maybe incorrect pw"
	sys.exit(1)

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
	print "Device mapper table"
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

