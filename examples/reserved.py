"""
Reserved can be used to both check for data hidden in the reserved sections of a 
TrueCrypt container, and to hide data there.

GitHub: https://github.com/4144414D/pytruecrypt

Usage:
  reserved check <TrueCrypt> <password> [--hidden]
  reserved hide <TrueCrypt> <password> <file> [--hidden]
 
Options:
  -h, --help              Show this screen.
  --hidden                Use the hidden volume space.
"""

from pytruecrypt import *
from docopt import docopt
import sys
import os

if __name__ == '__main__':
	arguments = docopt(__doc__)
	tc = PyTruecrypt(arguments['<TrueCrypt>'])
	if tc.open(arguments['<password>'],hidden=arguments['--hidden']):
		if arguments['check']:
			reserved = ''
			for i in range(-127,0):
				reserved +=	tc.getPlainSector(i)
			sys.stdout.write(reserved)
		elif arguments['hide']:
			f = open(arguments['<file>'])
			f.seek(0, os.SEEK_END)
			size = f.tell()
			if size > 65024:
				print 'File is too big to hide'
				exit(1)
			f.seek(0)
			data = f.read()
			while len(data) < 65024: data += '\x00'
			for i in range(-127,0):
				tc.putCipherSector(i,data[((i + 127) * 512):(((i + 127) * 512) + 512)])
	else:
		print "Failed to open TrueCrypt volume"
		exit(1)