"""
pytruecrypt image is used to image a truecrypt container for further analysis.

The container can be open with a password or with keys extracted from memory.

Encryption modes can be assigned long or short hand where:
aes      = a
twofish  = t
serpent  = s

For example 'aes-twofish' can be shortened to 'at' and aes-twofish-serpent 
to ats. 

Similarly hash functions can be assigned long or short hand where:
ripemd    = r
sha-512   = s
whirlpool = w

Example useage:

Scenario 1:
You wish to image a TrueCrypt file "input1.tc" to an image named "output1.dd", 
it uses aes and ripemd. The password is "Scenario1". As ripemd is the default
for TrueCrypt it does not need to be specified.

> image pwd input1.tc output1.dd aes Scenario1 

Scenario 2:
You wish to image a TrueCrypt file "input2.tc" to an image named "output2.dd",
it uses aes-serpent and sha512. The password is "Scenario2". You wish to save 
time and use the short hand commands.

> image pwd input2.tc output2.dd as Scenario2 s

Scenario 3:
You wish to image a TrueCrypt file "input3.tc" to an image named "output3.dd",
it uses aes-serpent. You know it contains a hidden volume and the password is 
"Scenario3".

> image pwd input3.tc output3.dd aes-serpent Scenario3 --hidden

Scenario 4:
You wish to image a TrueCrypt file "input4.tc" to an image named "output4.dd",
it uses aes. You do not know the password but have extracted AES keys from 
memory. 

> image key input4.tc output4.dd aes --aes bac01155a46547f00c3ddf9a4a765159fbe
1f68d94bf11a3bd6910eedf26d867a63263c949812cd68b7dad91a8dfdacb96942b93cc1b21ffa
feeb4791a0befa4

GitHub: https://github.com/4144414D/pytruecrypt

Usage:
 image pwd <tc> <image> <mode> <password> [<hash>] [-vbh] [(-f -oBYTES -dBYTES)]
 image key <tc> <image> <mode> [-aKEY -tKEY -sKEY] [(-oBYTES -dBYTES)]
 image --help

Options:
 --help                       Show this screen
 -a key, --aes key            AES Key
 -t key, --twofish key        TwoFish Key
 -s key, --serpent key        Serpent Key  
 -f, --force                  Continue even if magic number and CRC fail
 -o BYTES, --offset BYTES     Offset in bytes to start of data area
 -d BYTES, --datasize BYTES   Size of data area to image
 -v, --vera                   Treat container as Veracrypt
 -b, --backup                 Use backup header
 -h, --hidden			      Use hidden volume
"""

from pytruecrypt import *
from docopt import docopt
import os
import binascii
import time
from util import * #delete after testing

def checkkey(mode, key,name):
	if key != None:
		#check if key is required but not supplied
		if (name not in mode):
			print "ERROR " + name + " key is not required for the selected encryption mode"
		#check key is correct length
		elif (len(key) == 128):
			try:
				#try to convert hex to bin
				return binascii.unhexlify(key) #good outcome
			except TypeError:
				print "ERROR " + name + " key invalid and contains non hex characters [0-f]"
		#if key is incorrect length give an error
		elif (len(key) != 128):
			print "ERROR " + name + " key is not the correct length"
	else:
		#check if key is required but not supplied
		if (name in mode):
			print "ERROR " + name + " key is required for the selected encryption mode but not supplied"
	return False #everything else is a fail

def percentage(part, whole):
  return 100 * float(part)/float(whole)

def create_log(arguments):
	log = open(arguments['<image>'] + '.log','a')
	log.write("pytruecrypt - image.py - https://github.com/4144414D/pytruecrypt")
	log.write('\n' + '-'*80)
	log.write('\nCompleted at: ' + time.strftime("%d/%b/%Y %H:%M:%S"))
	log.write('\n\nArguments')
	log.write('\nContainer opened with a ' + ('password' if not arguments['key'] else 'key'))
	log.write('\nContainer path: ' + arguments['<tc>'])
	log.write('\nImage path: ' + arguments['<image>'])
	log.write('\nEncryption mode: ' + '-'.join(map(str, arguments['<mode>'])))
	if arguments['<hash>'] != 'default':
		hash = arguments['<hash>']
	else:
		if arguments['--vera']:
			hash = 'sha512'
		else:
			hash = 'ripemd'
	log.write('\nHash Function: ' + hash)
	if arguments['key']:
		if arguments['--aes']:
			log.write('\nAES Key: ' + arguments['--aes'])
		if arguments['--serpent']:
			log.write('\nSerpent Key: ' + arguments['--serpent'])
		if arguments['--twofish']:
			log.write('\nTwofish Key: ' + arguments['--twofish'])
	else:
		log.write('\nPassword: ' + arguments['<password>'])
		
	log.write('\nForce option: ' + ('Used' if arguments['--force'] else 'Not Used')) 
	log.write('\nOffset: ' + (str(arguments['--offset']) if arguments['--offset'] else 'Not Used')) 
	log.write('\nData Size: ' + (str(arguments['--datasize']) if arguments['--datasize'] else 'Not Used')) 
	log.write('\nHidden Container option: ' + ('Used' if arguments['--hidden'] else 'Not Used')) 
	log.write('\nBackup Header option: ' + ('Used' if arguments['--backup'] else 'Not Used')) 
	log.write('\nVeraCrypt option: ' + ('Used' if arguments['--backup'] else 'Not Used')) 
	log.write('\n' + '-'*80)
	log.write('\n\n')

def create_image(image, tc, DataStart, DataSize,startsec=0):
	print '\r',
	tick = 0
	image_file = open(image,'wb')
	for sector in range(0,DataSize/512):
		#check timer to see if display needs updating
		tock = '%.2f' % time.time()
		if tick != tock:
			tick = tock
			completed = (percentage(sector, DataSize/512))
			bars = '=' * (int(completed) / 3)
			bar = '[' + bars + ' ' * (33 - len(bars)) + ']'
			completed = '%.3f' % completed
			print bar + ' ' + str(completed) + '%\r',
		image_file.write(tc.getPlainSector(sector,startsec))
	print '[' + '=' * 33 + '] 100%          '
	
if __name__ == '__main__':
	arguments = docopt(__doc__)
	#check hash function
	if not arguments['<hash>']:
		arguments['<hash>'] = 'default'
	elif arguments['<hash>'] in ['s', 'r', 'w']:
		#viable short hand mode chosen, convert to long hand
		arguments['<hash>'] = arguments['<hash>'].replace('w','1').replace('r','2').replace('s','3')
		arguments['<hash>'] = arguments['<hash>'].replace('1','whirlpool').replace('2','ripemd').replace('3','sha512')
	elif arguments['<hash>'] not in ['sha512','ripemd','whirlpool']:
		print "ERROR Please choose a viable hash function: sha512, ripemd, or whirlpool."
		exit(1)
		
	#check crypto options
	if arguments['<mode>'] in ["a","at","ats","s","sa","sta","t","ts"]:
		#viable short hand mode chosen, convert to long hand
		arguments['<mode>'] = arguments['<mode>'].replace('a','1').replace('t','2').replace('s','3')
		arguments['<mode>'] = arguments['<mode>'].replace('1','aes-').replace('2','twofish-').replace('3','serpent-')[:-1]
	elif arguments['<mode>'] not in ["aes","aes-twofish","aes-twofish-serpent","serpent","serpent-aes","serpent-twofish-aes","twofish","twofish-serpent"]:
		print "ERROR Please choose a viable crypto mode:"
		for line in ["aes","aes-twofish","aes-twofish-serpent","serpent","serpent-aes","serpent-twofish-aes","twofish","twofish-serpent"]:
			print "\t"+line
		exit(1)
	#split long hand into list
	arguments['<mode>'] = arguments['<mode>'].split('-')
	
	#check keys are viable if required
	key_count = 0
	aes_key = None
	twofish_key = None
	serpent_key = None
	if arguments['key']:
		aes_key = checkkey(arguments['<mode>'],arguments['--aes'],'aes')
		twofish_key = checkkey(arguments['<mode>'],arguments['--twofish'],'twofish')
		serpent_key = checkkey(arguments['<mode>'],arguments['--serpent'],'serpent')
		if not (aes_key or twofish_key or serpent_key): exit(1)
		
	#check tc file exists
	if not os.path.isfile(arguments['<tc>']):
		print "ERROR",
		print arguments['<tc>'],
		print "does not exist"
		exit(1)
	
	#check that image file does not already exist
	if os.path.isfile(arguments['<image>']):
		print "ERROR",
		print arguments['<image>'],
		print "already exists"
		exit(1)
	
	#use PyTruecrypt to open container
	tc = PyTruecrypt(arguments['<tc>'], arguments['--vera'], encryption=arguments['<mode>'],hash_func=arguments['<hash>'])
	
	if arguments['pwd']:
		vaild = tc.open(arguments['<password>'], arguments['--hidden'], True, arguments['--backup'])
		if vaild or arguments['--force']:
			if not vaild:
				tc.vaild = True #force pytruecrypt to decrypt
				tc.decodeHeader()
				DataStart = int(arguments['--offset'])
				DataSize = int(arguments['--datasize'])
				offset = int(arguments['--offset']) / 512
			else:
				header = tc.getHeader()
				DataStart = int(header['DataStart'])
				DataSize = int(header['DataSize'])
				offset = 0
			create_image(arguments['<image>'],tc, DataStart, DataSize, offset)
			create_log(arguments)
		else:
			print "ERROR incorrect password"
	else:
		tc.open_with_key(aes_key,twofish_key,serpent_key)
		#if sizes not given calculate sizes for a standard vol
		if not arguments['--offset']:
			arguments['--offset'] = 131072
		if not arguments['--datasize']:
			arguments['--datasize'] = tc.size - (131072*2)
		create_image(arguments['<image>'],tc, int(arguments['--offset']), int(arguments['--datasize']), int(arguments['--offset']) / 512)
		create_log(arguments)