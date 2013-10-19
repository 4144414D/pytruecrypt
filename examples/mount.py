# Truecrypt parsing library for Python by Gareth Owen
# https://github.com/drgowen/pytruecrypt/
# See LICENCE for licence details

# PyTruecrypt is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# PyTruecrypt is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with PyTruecrypt.  If not, see <http://www.gnu.org/licenses/>.

# Truecrypt volume mounter for Linux

import sys

sys.path.append("..")


from pytruecrypt import *
import binascii
import os
from subprocess import *
import stat
import getpass
import getopt

hidden = False
unmount = False

args = getopt.getopt(sys.argv[1:], "h")

# parse cmdline options
for k in args[0]:
	if k[0]=='-h':
		hidden = True
#	if k[0]=='-u':
#		unmount = True

if len(args[1]) != 2:
	print "Usage: python mount.py [-h] volumepath dmname"
	print "Mount truecrypt volume"
	print
	print "  volumepath\tTruecrypt volume file/device"
	print "  dmname\tDevice mapper name (/dev/mapper/dmname) to map to (e.g. tcrypt)"
	print "  -h\t\tmount hidden volume"
	print
	sys.exit(1)

FILENAME = args[1][0]
PASSWORD = getpass.getpass("Enter password: ")
DMNAME = args[1][1]

#if unmount:
	#todo
	# remove loopback
#	os.system("losetup -d `sudo losetup -a | grep '%s' | cut -d ':' -f 1`" % (FILENAME))

#initialise pytruecrypt
tc = PyTruecrypt(FILENAME)

#open volume (returns false on failure)
if not tc.open(PASSWORD, hidden=hidden):
	print "Failed to open volume -maybe incorrect pw"
	sys.exit(1)

#if root - mount it
if os.getuid() == 0:
	devName = FILENAME
	
	# if not block device - use loopback
	if not stat.S_ISBLK(os.stat(devName).st_mode):
		#find a free loopback device
		child = Popen("losetup -f", shell=True, stdout=PIPE)
		output, errors = child.communicate();
		devName = output.strip()

		#setup loopback
		os.system("losetup %s %s" % (devName, FILENAME))

	#setup linux device mapper so can mount volume
	dmtable = tc.getDeviceMapperTable(devName)

	#create dm target /dev/mapper/tcrypt
#	print "Device mapper table"
#	print dmtable

	os.system('echo %s | dmsetup create %s' % (dmtable, DMNAME))

	print "Tcryptdevice on /dev/mapper/"+DMNAME+" - you may now mount it"
	#You may now have to mount this manually if your linux doesn't automatically)
	# mount /dev/mapper/tcrypt wheretomount

	#to undo
	#unmount
	#dmsetup remove dmname
	#losetup -d /dev/loop0
else:
	print "Must be root to mount"

