from collections import namedtuple
import sys
from Crypto.Protocol.KDF import *
from Crypto.Hash import *
from Crypto.Cipher import AES
import binascii
import struct 
from util import *

# Decrypts a sector, given pycrypto aes object for master key plus xts key
# Offset for partial sector decrypts (e.g. hdr)
def decrypt_sector(aes, aesxts, sector, ciphertext, offset=0):
	# Encrypt IV to produce XTS tweak
	ek2n = aesxts.encrypt(buftostr(inttoLE(sector)))

	tc_plain = ''
	for i in range(offset, 512, 16):
		# Decrypt and apply tweak according to XTS scheme
		ptext = xor( aes.decrypt( xor(ek2n, ciphertext[i:i+16]) ) , ek2n)
		tc_plain += ptext

		# exponentiate tweak for next block (multiply by two in finite field)
		ek2n_i = LEtoint(strtobuf(ek2n))           # Little Endian to python int
		ek2n_i = (ek2n_i << 1)			   # multiply by two using left shift
		if ek2n_i & (1<<128):			   # correct for carry
			ek2n_i ^= 0x87
		ek2n = buftostr(inttoLE(ek2n_i))	   # python into to Little Endian (ignoring bits >128)

	return tc_plain


################## CODE START ######################

# Usage
if len(sys.argv) != 3:
	print "pytruecrypt.py filename password"
	sys.exit(0)
	
# Open file and read header
inf = open(sys.argv[1], "rb")
tchdr = inf.read(131072)

# First 64 bytes are salt
salt = tchdr[0:64]
#sys.stderr.write( "SALT: "+binascii.hexlify(salt)+"\n")

# Generate header keys
pwhash= PBKDF2(sys.argv[2], salt, 64, count=2000, prf=lambda p,s: HMAC.new(p,s,RIPEMD).digest())
aeskey = pwhash[0:32]
xtskey = pwhash[32:64]
print "Hdr keys:", binascii.hexlify(aeskey+xtskey)

# Load hdr keys into pycrypto
aes = AES.new(aeskey, AES.MODE_ECB)
aesxts = AES.new(xtskey, AES.MODE_ECB)

# decrypt header
print "Plaintext header"
tchdr_plain = decrypt_sector(aes, aesxts, 0, tchdr, 64)

# dump header to screen
print hexdump(tchdr_plain)

# Dump rest of header - normally random data
#for i in range(1, 256):
#	tc_plain = decrypt_sector(aes, aesxts, i, tchdr[i*512:])
#	sys.stdout.write(tc_plain)

# Parse first few fields of header

# Parse header using python's struct and print out fields
print "Parsed header"
TCHDR = namedtuple('TCHDR', "Magic HdrVersion MinProgVer CRC Reserved HiddenVolSize VolSize DataStart DataSize Flags SectorSize Reserved2 CRC3 Keys")
hdr_decoded = struct.unpack(">4sH", tchdr_plain[0:6]) + struct.unpack("<H", tchdr_plain[6:8]) + struct.unpack(">I16sQQQQII120sI256s", tchdr_plain[8:448])
print

hdrstruct = TCHDR._make(hdr_decoded)

print hdrstruct

# Print Primary and Secondary keys for AES-XTS of main data
print "KEYS:", binascii.hexlify(hdrstruct.Keys[0:64])

# Load primary and secondary key and decrypt first sector
aes = AES.new(hdrstruct.Keys[0:32], AES.MODE_ECB)
aesxts = AES.new(hdrstruct.Keys[32:64], AES.MODE_ECB)

print
print "FIRST SECTOR"
# note IV for first sector = actual sector number (not minus header) = 256
print hexdump(decrypt_sector(aes, aesxts, 256, inf.read(512), 0))

