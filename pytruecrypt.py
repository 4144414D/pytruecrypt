# Truecrypt parsing library for Python by Gareth Owen
# https://github.com/drgowen/pytruecrypt/
# See LICENCE for licence details

# PyTruecrypt is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# PyTruecrypt is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with PyTruecrypt.  If not, see <http://www.gnu.org/licenses/>.

from collections import namedtuple
import sys
from Crypto.Protocol.KDF import *
from Crypto.Hash import RIPEMD, SHA512
from CryptoPlus.Hash import python_whirlpool as WHIRLPOOL
from Crypto.Cipher import AES
from CryptoPlus.Cipher import python_Twofish as TwoFish
from CryptoPlus.Cipher import python_Serpent as Serpent
import binascii
import struct 
import os
from util import *

class PyTruecrypt:
	def __init__(self, filename, veracrypt=False, encryption="aes", hash_func="default"):
		self.fn = filename
		self.veracrypt = veracrypt
		self.valid = False
		self.encryption = encryption
		
		#set defaults 
		if hash_func == "default" and not veracrypt:
			hash_func = 'ripemd'
		elif hash_func == "default" and veracrypt:
			hash_func = 'sha512'
		
		#create pycrypto hash object
		if hash_func == 'sha512':
			self.hash_func = SHA512
			self.hash_func_rounds = (1000 if not self.veracrypt else 500000) 
		elif hash_func == 'ripemd':
			self.hash_func = RIPEMD
			self.hash_func_rounds = (2000 if not self.veracrypt else 500000)
		elif hash_func == 'whirlpool':
			self.hash_func = WHIRLPOOL
			self.hash_func_rounds = (1000 if not self.veracrypt else 500000) 

	def open_with_key(self, key):
		if len(key) != 128:
			return False
		self.fd = open(self.fn, "r+b")
		self.keys =  {'key' : binascii.unhexlify(key[:64]),'xtskey' : binascii.unhexlify(key[64:])}
		self.mainenc = self._get_encryption_object(self.keys['key'])
		self.mainencxts = self._get_encryption_object(self.keys['xtskey'])
		self.open_with_key = True
		if not self.mainenc or not self.mainencxts: return False
	
	def open(self, password, hidden=False, decode=True, backup=False):
		self.pw = password
		self.fd = open(self.fn, "r+b")
		self.fd.seek(0, os.SEEK_END)
		size = self.fd.tell()
		if backup:
			self.fd.seek((size - 131072) if not hidden else (size - 65536))
		else:
			self.fd.seek(0 if not hidden else 65536)
		self.tchdr_ciphered = self.fd.read(512)
		self.salt = self.tchdr_ciphered[0:64]
		self.hdrkeys = None

		# Header key derivation
		pwhash = PBKDF2(self.pw, self.salt, 64, count=self.hash_func_rounds, prf=lambda p,s: HMAC.new(p,s,self.hash_func).digest())
        
		#Header keys
		self.hdrkeys = { 'key':pwhash[0:32], 'xtskey':pwhash[32:64] }
		
		#crypto objects
		self.hdrenc = self._get_encryption_object(self.hdrkeys['key'])
		self.hdrencxts = self._get_encryption_object(self.hdrkeys['xtskey'])
		if not self.hdrenc or not self.hdrencxts: return False
		
		#decrypt header
		self.tchdr_plain = self._decrypt_sector(self.hdrenc, self.hdrencxts, 0, self.tchdr_ciphered, 64)

		#check correct decryption
		magic_number = ("TRUE" if not self.veracrypt else "VERA")
		if self.tchdr_plain[0:4] != magic_number:
			self.valid = False

		if decode:
			#Decode header into struct/namedtuple
			TCHDR = namedtuple('TCHDR', "Magic HdrVersion MinProgVer CRC Reserved HiddenVolSize VolSize DataStart DataSize Flags SectorSize Reserved2 CRC3 Keys")
			self.hdr_decoded = TCHDR._make(struct.unpack(">4sH", self.tchdr_plain[0:6]) + struct.unpack("<H", self.tchdr_plain[6:8]) + struct.unpack(">I16sQQQQII120sI256s", self.tchdr_plain[8:448]))
			
			# Load primary and secondary key
			self.keys = {'key': self.hdr_decoded.Keys[0:32], 'xtskey': self.hdr_decoded.Keys[32:64]}
			self.mainenc = self._get_encryption_object(self.keys['key'])
			self.mainencxts = self._get_encryption_object(self.keys['xtskey'])
			if not self.mainenc or not self.mainencxts: return False
			self.valid = True
		self.checkCRC32()
		if self.valid and self.valid_HeaderCRC and self.valid_KeyCRC: 
			return True
		else:
			return False

	#decoded header is python dict
	def getHeader(self):
		if not self.valid:
			return False
		return self.hdr_decoded._asdict()

	# Raw plaintext header
	def getHeaderRaw(self):
		if not self.valid:
			return False
		return self.tchdr_plain

	# Gets plaintext sector from data section
	def getPlainSector(self, sector, secstart=0):
		if not (self.valid or (self.open_with_key and secstart > 0)):
			return False
		if self.valid: 
			secstart = self.hdr_decoded.DataStart / 512
		self.fd.seek((secstart + sector)*512)
		return self._decrypt_sector(self.mainenc, self.mainencxts, secstart + sector, self.fd.read(512))
		
	# Gets ciphertext sector from data input
	def getCipherSector(self, sector, plaintext, secstart=0):
		if not (self.valid or (self.open_with_key and secstart > 0)):
			return False
		if len(plaintext) != 512:
			return False
		if self.valid: 
			secstart = self.hdr_decoded.DataStart / 512
		return self._encrypt_sector(self.mainenc, self.mainencxts, secstart + sector, plaintext)
	
	# Writes ciphertext sector from data input
	def putCipherSector(self, sector, plaintext, secstart=0):
		if not (self.valid or (self.open_with_key and secstart > 0)):
			return False
		if len(plaintext) != 512:
			return False
		if self.valid: 
			secstart = self.hdr_decoded.DataStart / 512
		cipherSector = self.getCipherSector(sector, plaintext, secstart)
		self.fd.seek((secstart  + sector) * 512)
		self.fd.write(cipherSector)
		
	# get linux device mapper table to allow easy mounting
	def getDeviceMapperTable(self, loopdevice):
		if not self.valid:
			return False
		secstart = self.hdr_decoded.DataStart / 512
		size = self.hdr_decoded.DataSize / 512
		return "0 %d crypt aes-xts-plain64 %s %d %s %d" % (size, binascii.hexlify(self.keys['key']+self.keys['xtskey']), secstart, loopdevice, secstart)
	
	# checks if the CRC32 of bytes matches the target CRC32
	def calculateCRC32(self,bytes,target):
		if struct.pack('>I',binascii.crc32(bytes) & 0xffffffff) == target:
			return True
		else:
			return False
	
	# checks if the store CRC32 in the header matches the calculated CRC32 header
	def checkCRC32(self):
		if not self.valid:
			return False
		self.valid_HeaderCRC = self.calculateCRC32(self.tchdr_plain[:188],self.tchdr_plain[188:192])
		self.valid_KeyCRC = self.calculateCRC32(self.tchdr_plain[192:],self.tchdr_plain[8:12])

	# internal function
	def _get_encryption_object(self,key):
		if self.encryption == "aes":
			return AES.new(key, AES.MODE_ECB)
		elif self.encryption == "serpent":
			return Serpent.new(key, Serpent.MODE_ECB)
		elif self.encryption == "twofish":
			return TwoFish.new(key, TwoFish.MODE_ECB)
		else:
			return False
	
	# Decrypts a sector, given pycrypto aes object for master key plus xts key
	# Offset for partial sector decrypts (e.g. hdr)
	# internal function
	def _decrypt_sector(self, enc, encxts, sector, ciphertext, offset=0):
		# Encrypt IV to produce XTS tweak
		ek2n = encxts.encrypt(inttoLE(sector))

		tc_plain = ''
		for i in range(offset, 512, 16):
			# Decrypt and apply tweak according to XTS scheme
			# pt = Dec(ct ^ ek2n) ^ ek2n
			ptext = xor( enc.decrypt( xor(ek2n, ciphertext[i:i+16]) ) , ek2n)
			tc_plain += ptext
			ek2n = self._exponentiate_tweak(ek2n)
		return tc_plain
		
	def _encrypt_sector(self, enc, encxts, sector, plaintext, offset=0):
		# Encrypt IV to produce XTS tweak
		ek2n = encxts.encrypt(inttoLE(sector))

		tc_cipher = ''
		print hexdump(plaintext)
		for i in range(offset, 512, 16):
			# Decrypt and apply tweak according to XTS scheme
			# pt = Dec(ct ^ ek2n) ^ ek2n
			ctext = xor( enc.encrypt( xor(ek2n, plaintext[i:i+16]) ) , ek2n)
			tc_cipher += ctext
			ek2n = self._exponentiate_tweak(ek2n)
		return tc_cipher
	
	# exponentiate tweak for next block (multiply by two in finite field)
	def _exponentiate_tweak(self, ek2n):
		ek2n_i = LEtoint(ek2n)		       # Little Endian to python int
		ek2n_i = (ek2n_i << 1)			   # multiply by two using left shift
		if ek2n_i & (1<<128):			   # correct for carry
			ek2n_i ^= 0x87
		return inttoLE(ek2n_i)