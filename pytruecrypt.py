import sys
from Crypto.Protocol.KDF import *
from Crypto.Hash import *
from Crypto.Cipher import AES
from galois import *
import binascii
import struct 

# Integer to little endian (int array)
def inttoLE(x):
	str=[]
	for i in range(16):
		str.append((x & (0xFF << i*8)) >> i*8)
	return str

# Little endian (int array) to integer
def LEtoint(x):
	y = 0
	for i in range(16):
		y = y + (x[i] << i*8)
	return y

# Integer array to string
def buftostr(x):
	return ''.join(map(chr, x))

# String to integer array
def strtobuf(x):
	return [ord(i) for i in x]

# XOR two strings
def xor(a,b):
	return ''.join([chr(ord(a[i])^ord(b[i])) for i in range(len(a))])

# Generate sector ek2(n)
def getXTSek2n(_aes, sector):
	return _aes.encrypt(buftostr(inttoLE(sector)))

# a^i precomputations - no need for galois here
alphatweaks = [1]
alphatweaks.extend([2 << i for i in range(32)])  #(for 32 blocks)

# Take sector ek2(n) and add tweak for block (a^i)
def getXTSek2na(ekn2, block):
	global alphatweaks
	return buftostr(inttoLE(gf2n_mul(LEtoint(strtobuf(ekn2)),alphatweaks[block],mod128)))

# Decrypts a sector, given pycrypto aes object for master key plus xts key
# Offset for partial sector decrypts (e.g. hdr)
def decrypt_block(aes, aesxts, sector, ciphertext, offset=0):
	ek2n = getXTSek2n(aesxts, sector)

	tc_plain = ''
	for i in range(offset, 512, 16):
	#	print i
		ek2na = getXTSek2na(ek2n, (i-offset)/16)
		#print "Tweak:", binascii.hexlify(ek2na)	

		ptext = xor( aes.decrypt(xor(ek2na, ciphertext[i:i+16]) ) , ek2na)
		tc_plain += ptext
	return tc_plain

# Usage
if len(sys.argv) != 3:
	print "pytruecrypt.py filename password"
	sys.exit(0)
	
# Open file
tchdr = open(sys.argv[1], "rb").read(512)

# First 64 bytes are salt
salt = tchdr[0:64]
#print "SALT: ",binascii.hexlify(salt)

# Generate header keys
pwhash= PBKDF2(sys.argv[2], salt, 64, count=2000, prf=lambda p,s: HMAC.new(p,s,RIPEMD).digest())
aeskey = pwhash[0:32]
xtskey = pwhash[32:64]

# Load hdr keys into pycrypto
aes = AES.new(aeskey, AES.MODE_ECB)
aesxts = AES.new(xtskey, AES.MODE_ECB)

# decrypt header
tchdr_plain = decrypt_block(aes, aesxts, 0, tchdr, 64)

# Parse first few fields of header
#print struct.unpack(">4cHH", tchdr_plain[0:8])

# dump header to screen
print tchdr_plain,

