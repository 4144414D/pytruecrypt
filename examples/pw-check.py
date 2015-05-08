"""
pw-check will test all passwords given against a file to determine if it would
successfully decode a TrueCrypt/VeraCrypt volume. This also allows you to 
see if the standard and backup headers match. 

GitHub: https://github.com/4144414D/pytruecrypt

Usage:
  pw-check <file> <passwords>... [-dv]
 
Options:
  -h, --help              Show this screen.
  -d, --decode            Decode header if successful.
  -v, --veracrypt         Also check for VeraCrypt.
"""

from pytruecrypt import *
from docopt import docopt
import binascii

if __name__ == '__main__':
	arguments = docopt(__doc__)
	for password in arguments['<passwords>']:
		veraoptions = ([False] if not arguments['--veracrypt'] else [False,True])
		for vera in veraoptions:
			for hidden in [False,True]:
				for backup in [False,True]:
					for hash in ['ripemd','sha512','whirlpool']:
						for crypto in [["aes"],["aes","twofish"],["aes","twofish","serpent"],["serpent"],["serpent","aes"],["serpent","twofish","aes"],["twofish"],["twofish","serpent"]]:
							tc = PyTruecrypt(arguments['<file>'], vera, encryption=crypto,hash_func=hash)
							if tc.open(password,hidden=hidden,backup=backup):
								print password,
								print 'appears to be valid for a',
								print ('TrueCrypt' if not vera else 'VeraCrypt'),
								print ('standard' if not hidden else 'hidden'),
								print 'volume using the',
								print ('normal' if not backup else 'backup'),
								print 'header',
								print 'using',
								print crypto,
								print 'and',
								print hash
								if arguments['--decode']:
									header = tc.getHeader()
									for k in header:
										print k, ":", 
										if k=="Keys":
											print binascii.hexlify(header[k])	
										else:	
											print header[k]
									print