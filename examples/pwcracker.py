# PyTruecrypt parsing library for Python by Gareth Owen
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

# Truecrypt password cracker

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

if len(args[1]) != 2:
	print "Usage: python pwcrack.py [-h] volumepath wordlist"
	print "Crack truecrypt volume"
	print
	print "  -h\tcrack hidden volume"
	print
	sys.exit(1)

FILENAME = args[1][0]

# open word list
fdwords = open(args[1][1], "r")

#initialise pytruecrypt
tc = PyTruecrypt(FILENAME)

# loop through words
for line in fdwords.readlines():
	word = line.strip()

	#open volume (returns false on failure)
	if tc.open(word, decode=False, hidden=hidden):
		print "PW Found: "+word
		sys.exit(1)

print "failed"
