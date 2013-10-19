from collections import namedtuple
import sys
from Crypto.Protocol.KDF import *
from Crypto.Hash import *
from Crypto.Cipher import AES
import binascii
import struct 
from util import *

class PyTruecrypt:
	def __init__(self, filename, password):
		self.fn = filename
		self.pw = password
		self.valid = False

	def open(self):
		self.fd = open(self.fn, "rb")
		self.tchdr_ciphered = self.fd.read(512)
		self.salt = self.tchdr_ciphered[0:64]
		self.hdrkeys = None

		# Header key derivation
		pwhash = PBKDF2(self.pw, self.salt, 64, count=2000, prf=lambda p,s: HMAC.new(p,s,RIPEMD).digest())

		#Header keys
		self.hdrkeys = { 'key':pwhash[0:32], 'xtskey':pwhash[32:64] }
		
		#pycrypto objects
		self.hdraes = AES.new(self.hdrkeys['key'], AES.MODE_ECB)
		self.hdraesxts = AES.new(self.hdrkeys['xtskey'], AES.MODE_ECB)
		
		#decrypt header
		self.tchdr_plain = self._decrypt_sector(self.hdraes, self.hdraesxts, 0, self.tchdr_ciphered, 64)

		#check correct decryption
		if self.tchdr_plain[0:4] != "TRUE":
			return False

		#Decode header into struct/namedtuple
		TCHDR = namedtuple('TCHDR', "Magic HdrVersion MinProgVer CRC Reserved HiddenVolSize VolSize DataStart DataSize Flags SectorSize Reserved2 CRC3 Keys")
		self.hdr_decoded = TCHDR._make(struct.unpack(">4sH", self.tchdr_plain[0:6]) + struct.unpack("<H", self.tchdr_plain[6:8]) + struct.unpack(">I16sQQQQII120sI256s", self.tchdr_plain[8:448]))
	
		self.valid = True

		# Load primary and secondary key and decrypt first sector
		self.keys = {'key': self.hdr_decoded.Keys[0:32], 'xtskey': self.hdr_decoded.Keys[32:64]}
		self.mainaes = AES.new(self.keys['key'], AES.MODE_ECB)
		self.mainaesxts = AES.new(self.keys['xtskey'], AES.MODE_ECB)

		return True

	def getHeader(self):
		if not self.valid:
			return False
		return self.hdr_decoded._asdict()

	def getHeaderRaw(self):
		if not self.valid:
			return False
		return self.tchdr_plain

	def getPlainSector(self, sector):
		if not self.valid:
			return False
		self.fd.seek(self.hdr_decoded.DataStart + sector*512)
		return self._decrypt_sector(self.mainaes, self.mainaesxts, 256 + sector, self.fd.read(512))

	# Decrypts a sector, given pycrypto aes object for master key plus xts key
	# Offset for partial sector decrypts (e.g. hdr)
	def _decrypt_sector(self, aes, aesxts, sector, ciphertext, offset=0):
		# Encrypt IV to produce XTS tweak
		ek2n = aesxts.encrypt(inttoLE(sector))

		tc_plain = ''
		for i in range(offset, 512, 16):
			# Decrypt and apply tweak according to XTS scheme
			# pt = Dec(ct ^ ek2n) ^ ek2n
			ptext = xor( aes.decrypt( xor(ek2n, ciphertext[i:i+16]) ) , ek2n)
			tc_plain += ptext

			# exponentiate tweak for next block (multiply by two in finite field)
			ek2n_i = LEtoint(ek2n)		           # Little Endian to python int
			ek2n_i = (ek2n_i << 1)			   # multiply by two using left shift
			if ek2n_i & (1<<128):			   # correct for carry
				ek2n_i ^= 0x87
			ek2n = inttoLE(ek2n_i)			   # python into to Little Endian (ignoring bits >128)

		return tc_plain

	def getDeviceMapperTable(self, loopdevice):
		secstart = self.hdr_decoded.DataStart / 512
		size = self.hdr_decoded.DataSize / 512
		return "0 %d crypt aes-xts-plain64 %s %d %s %d" % (size, binascii.hexlify(self.keys['key']+self.keys['xtskey']), secstart, loopdevice, secstart)
		


