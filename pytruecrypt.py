import sys
from Crypto.Protocol.KDF import *
from Crypto.Hash import *
from Crypto.Cipher import AES
from galois import *
import binascii
import struct 

def inttoLE(x):
	str=[]
	for i in range(16):
		str.append((x & (0xFF << i*8)) >> i*8)
	return str

def LEtoint(x):
	y = 0
	for i in range(16):
		y = y + (x[i] << i*8)
	return y

def buftostr(x):
	return ''.join(map(chr, x))

def strtobuf(x):
	return [ord(i) for i in x]

def xor(a,b):
	return ''.join([chr(ord(a[i])^ord(b[i])) for i in range(len(a))])

def getXTSek2n(_aes, sector):
	return _aes.encrypt(buftostr(inttoLE(sector)))

alphatweaks = [1]
alphatweaks.extend([2 << i for i in range(32)])  #(for 32 blocks)
	
def getXTSe2kna(ekn2, block):
	global alphatweaks
	return buftostr(inttoLE(gf2n_mul(LEtoint(strtobuf(ekn2)),alphatweaks[block],mod128)))

def decrypt_block(aes, aesxts, sector, ciphertext, offset=0):
	ek2n = getXTSek2n(aesxts, sector)

	tc_plain = ''
	for i in range(offset, 512, 16):
	#	print i
		ek2na = getXTSe2kna(ek2n, (i-offset)/16)
		#print "Tweak:", binascii.hexlify(ek2na)	

		ptext = xor( aes.decrypt(xor(ek2na, ciphertext[i:i+16]) ) , ek2na)
		tc_plain += ptext
	return tc_plain

if len(sys.argv) != 3:
	print "pytruecrypt.py filename password"
	sys.exit(0)
	
#print alphatweaks
tchdr = open(sys.argv[1], "rb").read(512)

salt = tchdr[0:64]
#print "SALT: ",binascii.hexlify(salt)
pwhash= PBKDF2(sys.argv[2], salt, 64, count=2000, prf=lambda p,s: HMAC.new(p,s,RIPEMD).digest())
aeskey = pwhash[0:32]
xtskey = pwhash[32:64]

aes = AES.new(aeskey, AES.MODE_ECB)
aesxts = AES.new(xtskey, AES.MODE_ECB)

tchdr_plain = decrypt_block(aes, aesxts, 0, tchdr, 64)

#print struct.unpack(">4cHH", tchdr_plain[0:8])
print tchdr_plain,

