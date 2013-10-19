import sys

sys.path.append("..")


from pytruecrypt import *
import binascii
import os
from subprocess import *
import stat
import getpass

if len(sys.argv) != 3:
	print "Usage: python pwcracker.py volumepath wordlist"
	sys.exit(1)

FILENAME = sys.argv[1]

# open word list
fdwords = open(sys.argv[2], "r")

tc = PyTruecrypt(FILENAME)

# loop through words
for line in fdwords.readlines():
	word = line.strip()

	#initialise pytruecrypt


	#open volume (returns false on failure)
	if tc.open(word, decode=False):
		print "PW Found: "+word
		sys.exit(1)

print "failed"
