from collections import namedtuple
import sys
from Crypto.Protocol.KDF import *
from Crypto.Hash import *
from Crypto.Cipher import AES
from galois import *
import binascii
import struct 

# hexdump print function
def hexdump(src, length=16):
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    lines = []
    for c in xrange(0, len(src), length):
        chars = src[c:c+length]
        hex = ' '.join(["%02x" % ord(x) for x in chars])
        printable = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or '.') for x in chars])
        lines.append("%04x  %-*s  %s\n" % (c, length*3, hex, printable))
    return ''.join(lines)

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
def decrypt_sector(aes, aesxts, sector, ciphertext, offset=0):
	ek2n = getXTSek2n(aesxts, sector)

	tc_plain = ''
	for i in range(offset, 512, 16):
	#	print i
		ek2na = getXTSek2na(ek2n, (i-offset)/16)
		#print "Tweak:", binascii.hexlify(ek2na)	

		ptext = xor( aes.decrypt(xor(ek2na, ciphertext[i:i+16]) ) , ek2na)
		tc_plain += ptext
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

