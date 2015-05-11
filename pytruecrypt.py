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

class encObject:
	"""pycrypto objects used by PyTruecrypt"""
	def __init__(self, type):
		self.keys = None
		self.enc = None
		self.encxts = None
		self.type = type
	
	def set_keys(self, key):
		#keys = {'key' : binascii.unhexlify(key[:64]),'xtskey' : binascii.unhexlify(key[64:])}
		keys = {'key' : key[:32],'xtskey' : key[32:]}
		self.keys = keys
		self.enc = self._get_encryption_object(self.keys['key'])
		self.encxts = self._get_encryption_object(self.keys['xtskey'])
	
	def _get_encryption_object(self,key):
		if self.type == "aes":
			return AES.new(key, AES.MODE_ECB)
		elif self.type == "serpent":
			return Serpent.new(key, Serpent.MODE_ECB)
		elif self.type == "twofish":
			return TwoFish.new(key, TwoFish.MODE_ECB)
		else:
			return False

class PyTruecrypt:
	def __init__(self, filename, veracrypt=False, encryption=["aes"], hash_func="default"):
		self.fn = filename
		self.veracrypt = veracrypt
		self.valid = False
		self.encryption_mode = encryption
		
		#check viable encryption_mode chosen
		if self.encryption_mode not in [["aes"],["aes","twofish"],["aes","twofish","serpent"],["serpent"],["serpent","aes"],["serpent","twofish","aes"],["twofish"],["twofish","serpent"]]:
			print "Incorrect encryption mode selected"
			return False
		
		#create encryption objects, encryption must be a list of the cipher(s) used in order. Note that the TrueCrypt documentation is incorrect. 
		self.hdrenc = {}
		self.dataenc = {}
		for mode in encryption:
			if mode in ['aes','twofish','serpent']:
				self.hdrenc[mode] = encObject(mode)
				self.dataenc[mode] = encObject(mode)
		
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

	def open_with_key(self, aes_key=None, twofish_key=None, serpent_key=None):
		self.fd = open(self.fn, "r+b")
		if aes_key: self.enc['aes'].set_keys(aes_key)
		if twofish_key: self.enc['twofish'].set_keys(twofish_key)
		if serpent_key: self.enc['serpent'].set_keys(serpent_key)
		self.open_with_key = True
	
	def open(self, password, hidden=False, decode=True, backup=False):
		self.pw = password
		
		#open container as file object
		self.fd = open(self.fn, "r+b")
		self.fd.seek(0, os.SEEK_END)
		
		#get total size of container
		size = self.fd.tell()
		
		#seek to the correct location in the container to read the header
		if backup:
			self.fd.seek((size - 131072) if not hidden else (size - 65536))
		else:
			self.fd.seek(0 if not hidden else 65536)
		
		#read the encrypted header
		self.tchdr_ciphered = self.fd.read(512)
		
		#get the unencrypted salt for the header key
		self.salt = self.tchdr_ciphered[0:64]
		self.hdrkeys = None

		# Header key derivation
		pwhash = PBKDF2(self.pw, self.salt, 64*len(self.encryption_mode), count=self.hash_func_rounds, prf=lambda p,s: HMAC.new(p,s,self.hash_func).digest())
        
		#get header crypto keys from pwhash
		keys = []
		if len(self.encryption_mode) == 1:
			keys.append(pwhash[0:64])
		elif len(self.encryption_mode) == 2:
			keys.append(pwhash[32:64]+pwhash[96:128]) 
			keys.append(pwhash[0:32]+pwhash[64:96])
		elif len(self.encryption_mode) == 3:
			keys.append(pwhash[64:96]+pwhash[160:192])
			keys.append(pwhash[32:64]+pwhash[128:160]) 
			keys.append(pwhash[0:32]+pwhash[96:128])
		
		#create header crypto objects
		i = 0
		for mode in self.encryption_mode:
			self.hdrenc[mode].set_keys(keys[i])
			i = i + 1
			
		#decrypt header
		self.tchdr_plain = self._decrypt_sector(0,self.tchdr_ciphered,64,True)

		#check correct decryption
		magic_number = ("TRUE" if not self.veracrypt else "VERA")
		if self.tchdr_plain[0:4] != magic_number:
			#magic number is incorrect
			self.valid = False
		else:
			#magic number is correct
			self.valid = True
		
		#check crc values
		self.checkCRC32()
		
		if decode: 
			print 'yo'
			decodeHeader()
		
		if self.valid and self.valid_HeaderCRC and self.valid_KeyCRC: 
			return True
		else:
			return False
			
	def decodeHeader(self):
		#Decode header into struct/namedtuple
		print "PRINT HI"
		TCHDR = namedtuple('TCHDR', "Magic HdrVersion MinProgVer CRC Reserved HiddenVolSize VolSize DataStart DataSize Flags SectorSize Reserved2 CRC3 Keys")
		self.hdr_decoded = TCHDR._make(struct.unpack(">4sH", self.tchdr_plain[0:6]) + struct.unpack("<H", self.tchdr_plain[6:8]) + struct.unpack(">I16sQQQQII120sI256s", self.tchdr_plain[8:448]))
		
		#load primary and secondary key for each crypto
		keys = []
		if len(self.encryption_mode) == 1:
			keys.append(self.hdr_decoded.Keys[0:64])
		elif len(self.encryption_mode) == 2:
			keys.append(self.hdr_decoded.Keys[32:64]+self.hdr_decoded.Keys[96:128]) 
			keys.append(self.hdr_decoded.Keys[0:32]+self.hdr_decoded.Keys[64:96])
		elif len(self.encryption_mode) == 3:
			keys.append(self.hdr_decoded.Keys[64:96]+self.hdr_decoded.Keys[160:192])
			keys.append(self.hdr_decoded.Keys[32:64]+self.hdr_decoded.Keys[128:160]) 
			keys.append(self.hdr_decoded.Keys[0:32]+self.hdr_decoded.Keys[96:128])
		i = 0
		for mode in self.encryption_mode:
			self.dataenc[mode].set_keys(keys[i])
			i = i + 1
			
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
		return self._decrypt_sector(secstart + sector, self.fd.read(512))
		
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
	
	# checks if the CRC32 of bytes matches the target CRC32
	def calculateCRC32(self,bytes,target):
		if struct.pack('>I',binascii.crc32(bytes) & 0xffffffff) == target:
			return True
		else:
			return False
	
	# checks if the store CRC32 in the header matches the calculated CRC32 header
	def checkCRC32(self):
		self.valid_HeaderCRC = self.calculateCRC32(self.tchdr_plain[:188],self.tchdr_plain[188:192])
		self.valid_KeyCRC = self.calculateCRC32(self.tchdr_plain[192:],self.tchdr_plain[8:12])
	
	# Decrypts a sector, given one or more pycrypto objects for master key plus xts key
	# Offset for partial sector decrypts (e.g. hdr)
	# internal function, uses _single_decrypt_sector to decrypt data for each pycrypto object
	def _decrypt_sector(self, sector, ciphertext, offset=0, header=False):
		for mode in self.encryption_mode:
			if header:
				ciphertext = self._single_decrypt_sector(self.hdrenc[mode].enc, self.hdrenc[mode].encxts,sector,ciphertext,offset)
			else:
				ciphertext = self._single_decrypt_sector(self.dataenc[mode].enc, self.dataenc[mode].encxts,sector,ciphertext,offset)
		return ciphertext[offset:]
	
	def _encrypt_sector(self, sector, plaintext, offset=0, header=False):
		for mode in self.encryption_mode:
			if header:
				plaintext = self._single_encrypt_sector(self.hdrenc[mode].enc, self.hdrenc[mode].encxts,sector,plaintext,offset)
			else:
				plaintext = self._single_encrypt_sector(self.dataenc[mode].enc, self.dataenc[mode].encxts,sector,plaintext,offset)
		return plaintext[offset:]
	
	def _single_encrypt_sector(self, enc, encxts, sector, plaintext, offset=0):
		# Encrypt IV to produce XTS tweak
		ek2n = encxts.encrypt(inttoLE(sector))

		tc_cipher = '\x00' * offset #pad for offset
		print hexdump(plaintext)
		for i in range(offset, 512, 16):
			# Decrypt and apply tweak according to XTS scheme
			# pt = Dec(ct ^ ek2n) ^ ek2n
			ctext = xor( enc.encrypt( xor(ek2n, plaintext[i:i+16]) ) , ek2n)
			tc_cipher += ctext
			ek2n = self._exponentiate_tweak(ek2n)
		return tc_cipher
	
	# Decrypt ciphertext with individual crypto object
	# Internal function
	def _single_decrypt_sector(self, enc, encxts, sector, ciphertext, offset=0):
		# Encrypt IV to produce XTS tweak
		ek2n = encxts.encrypt(inttoLE(sector))

		tc_plain = '\x00' * offset #pad for offset
		for i in range(offset, 512, 16):
			# Decrypt and apply tweak according to XTS scheme
			# pt = Dec(ct ^ ek2n) ^ ek2n
			ptext = xor( enc.decrypt( xor(ek2n, ciphertext[i:i+16]) ) , ek2n)
			tc_plain += ptext
			ek2n = self._exponentiate_tweak(ek2n)
		return tc_plain
	
	# exponentiate tweak for next block (multiply by two in finite field)
	def _exponentiate_tweak(self, ek2n):
		ek2n_i = LEtoint(ek2n)		       # Little Endian to python int
		ek2n_i = (ek2n_i << 1)			   # multiply by two using left shift
		if ek2n_i & (1<<128):			   # correct for carry
			ek2n_i ^= 0x87
		return inttoLE(ek2n_i)