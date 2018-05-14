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

# Dumps truecrypt header and first sector from volume

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

args = getopt.getopt(sys.argv[1:], "h")

# parse cmdline options
for k in args[0]:
	if k[0]=='-h':
		hidden = True

if len(args[1]) != 1:
	print "Usage: python dump.py [-h] volumepath"
	print "Dump truecrypt volume"
	print
	print "  -h\tdump hidden volume"
	print
	sys.exit(1)

FILENAME = args[1][0]
PASSWORD = getpass.getpass("Enter password: ")

#initialise pytruecrypt
tc = PyTruecrypt(FILENAME)

#open volume (returns false on failure)
if not tc.open(PASSWORD, hidden=hidden):
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
