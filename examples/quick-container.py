"""
quick-container will create a simple TC container very quickly, and 
always uses AES and RIPEMD-160.

While the containers work it should not be considered secure.

GitHub: https://github.com/4144414D/pytruecrypt

Usage:
  quick-container <container> <password> <mb-size>
"""

import binascii
from docopt import docopt
from Crypto.Random import _UserFriendlyRNG as RNG
from Crypto.Hash import RIPEMD
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import *
from util import *

def encrypt(enc, encxts, sector, plaintext, offset=0):
	# Encrypt IV to produce XTS tweak
	ek2n = encxts.encrypt(inttoLE(sector))

	tc_cipher = ''
	for i in range(offset, 512, 16):
		# Decrypt and apply tweak according to XTS scheme
		# pt = Dec(ct ^ ek2n) ^ ek2n
		ctext = xor( enc.encrypt( xor(ek2n, plaintext[i:i+16]) ) , ek2n)
		tc_cipher += ctext
		ek2n = exponentiate_tweak(ek2n)
	return tc_cipher

# exponentiate tweak for next block (multiply by two in finite field)
def exponentiate_tweak(ek2n):
	ek2n_i = LEtoint(ek2n)		       # Little Endian to python int
	ek2n_i = (ek2n_i << 1)			   # multiply by two using left shift
	if ek2n_i & (1<<128):			   # correct for carry
		ek2n_i ^= 0x87
	return inttoLE(ek2n_i)

if __name__ == '__main__':
	arguments = docopt(__doc__)
	file = open(arguments['<container>'],'wb')
	size = int(arguments['<mb-size>']) * 1024 * 1024 #get size in bytes
	
	#create large file
	file.truncate(size)
	
	#create empty header
	header = ""
	
	#create salt for normal header
	salt = RNG.get_random_bytes(64)
	header += salt
	
	#ASCII string "TRUE"
	header += "TRUE"
	
	#Volume header format version 
	header += "\x00\x05" #Same as 7.1a
	
	#Minimum program version required to open the volume
	header += "\x07\x00" #Same as 7.1a
	
	#CRC-32 checksum of the (decrypted) bytes 256-511 (to be calculated later)
	header += "\xAA" * 4
	
	#Reserved (must contain zeroes)
	header += "\x00" * 16

	#Size of hidden volume (set to zero in non-hidden volumes)
	header += "\x00" * 8
	
	#Size of volume
	volume_size = size - 262144
	header += struct.pack('>Q',volume_size)
	
	#Byte offset of the start of the master key scope
	header += "\x00\x00\x00\x00\x00\x02\x00\x00"
	
	#Size of the encrypted area within the master key scope
	header += "\x00\x00\x00\x00\x00\x0c\x00\x00"
	
	#Flag bits
	header += "\x00" * 4
	
	#Sector size (in bytes)
	header += "\x00\x00\x02\x00"
	
	#Reserved (must contain zeroes) 
	header += "\x00" * 120
	
	#CRC-32 checksum of the (decrypted) bytes 64-251 (to be calculated later)
	header += "\xBB" * 4
	
	#generate password hash
	pwhash = PBKDF2(arguments['<password>'], salt, 64, count=2000, prf=lambda p,s: HMAC.new(p,s,RIPEMD).digest())
	
	#create header pycrypto
	hdrkeys = { 'key':pwhash[0:32], 'xtskey':pwhash[32:64] }
	hdraes = AES.new(hdrkeys['key'], AES.MODE_ECB)
	hdraesxts = AES.new(hdrkeys['xtskey'], AES.MODE_ECB)
	
	#create container keys
	containerkey = PBKDF2(RNG.get_random_bytes(64), RNG.get_random_bytes(64), 64, count=50000, prf=lambda p,s: HMAC.new(p,s,RIPEMD).digest())
	header += containerkey
	
	#fill sector with zeros
	header += "\x00" * 192
	
	#calculate CRC-32 checksum of the (decrypted) bytes 256-511
	calculatedCRC = struct.pack('>I',binascii.crc32(header[256:]) & 0xffffffff)
	header = header[:72] + calculatedCRC + header[76:]
	
	#calculate CRC-32 checksum of the (decrypted) bytes 64-251
	calculatedCRC = struct.pack('>I',binascii.crc32(header[64:252]) & 0xffffffff)
	header = header[:252] + calculatedCRC + header[256:]

	#encrypt header with header keys
	encrypted_header = salt + encrypt(hdraes, hdraesxts, 0, header, 64)
	
	#create backup salt
	backup_salt = RNG.get_random_bytes(64)
	
	#generate backup password hash
	pwhash = PBKDF2(arguments['<password>'], backup_salt, 64, count=2000, prf=lambda p,s: HMAC.new(p,s,RIPEMD).digest())
	
	#create backup header pycrypto
	hdrkeys = { 'key':pwhash[0:32], 'xtskey':pwhash[32:64] }
	hdraes = AES.new(hdrkeys['key'], AES.MODE_ECB)
	hdraesxts = AES.new(hdrkeys['xtskey'], AES.MODE_ECB)
	
	#encrypt backup header
	encrypted_backup_header = backup_salt + encrypt(hdraes, hdraesxts, 0, header, 64)
	
	#write headers
	file.seek(0)
	file.write(encrypted_header)
	file.seek(size - 131072)
	file.write(encrypted_backup_header)
	file.close()