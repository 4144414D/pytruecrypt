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
	def __init__(self, filename="", veracrypt=False, encryption=["aes"], hash_func="default", fd=None):
		self.fn = filename
		self.veracrypt = veracrypt
		self.valid = False
		self.encryption_mode = encryption
		self.fd = fd

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
		if not self.fd:	self.fd = open(self.fn, "r+b")
		self.fd.seek(0, os.SEEK_END)
		self.size = self.fd.tell()
		if aes_key: self.dataenc['aes'].set_keys(aes_key)
		if twofish_key: self.dataenc['twofish'].set_keys(twofish_key)
		if serpent_key: self.dataenc['serpent'].set_keys(serpent_key)
		self.open_with_key = True

	def open(self, password, hidden=False, decode=True, backup=False, keyfiles=None):
		if keyfiles:
			self.pw = self.keyfile(password,keyfiles)
		else:
			self.pw = password

		#open container as file object
		if not self.fd:	self.fd = open(self.fn, "r+b")
		self.fd.seek(0, os.SEEK_END)

		#get total size of container
		self.size = self.fd.tell()

		#seek to the correct location in the container to read the header
		if backup:
			self.fd.seek((self.fd.size - 131072) if not hidden else (self.fd.size - 65536))
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
			self.decodeHeader()

		if self.valid and self.valid_HeaderCRC and self.valid_KeyCRC:
			return True
		else:
			return False

	# from "TrueCrypt 7.1a Source\Common\Crc.c"
	def truecrypt_crc(self, data, crc):
		# /* CRC polynomial 0x04c11db7 */
		crc_32_tab = [
		0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
		0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988, 0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
		0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
		0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
		0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172, 0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
		0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
		0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
		0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924, 0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
		0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
		0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
		0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e, 0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
		0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
		0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
		0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0, 0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
		0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
		0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
		0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a, 0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
		0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
		0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
		0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc, 0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
		0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
		0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
		0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236, 0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
		0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
		0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
		0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38, 0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
		0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
		0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
		0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2, 0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
		0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
		0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
		0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94, 0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d]

		# CRC = (CRC >> 8) ^ crc_32_tab[ (CRC ^ *data++) & 0xFF ];
		return (crc >> 8) ^ crc_32_tab[(crc ^ ord(data)) & 0xFF]

	def keyfile(self,password,keyfiles):
		#pad password with zero bytes until length of 64
		while len(password) < 64:
			password = password + '\x00'

		#fill keypool with zero bytes
		keyfilePool = []
		keyfilePoolCursor = 0
		for x in range(64):
			keyfilePool.append(0)

		total_processed = 0
		for keyfile in keyfiles:
			keyfilefd = open(keyfile,'rb')
			keyfilefd.seek(0)
			keyfiledata = keyfilefd.read(1048576) #read first 1MB
			keyfilefd.close()

			#stop processing if 1MB has been read
			if total_processed == 1048576: break

			#read each byte of keyfile, stopping at 1MB in total
			crc = 0xFFFFFFFF
			for x in range(len(keyfiledata)):
				total_processed += 1

				# from "TrueCrypt 7.1a Source\Common\Keyfiles.c"
				crc = self.truecrypt_crc(keyfiledata[x], crc) & 0xFFFFFFFF
				#keyPool[writePos++] += (unsigned __int8) (crc >> 24);
				keyfilePool[keyfilePoolCursor] = (keyfilePool[keyfilePoolCursor] + ((crc >> 24) & 0xFF)) % 256
				#keyPool[writePos++] += (unsigned __int8) (crc >> 16);
				keyfilePool[keyfilePoolCursor+1] = (keyfilePool[keyfilePoolCursor+1] + ((crc >> 16) & 0xFF)) % 256
				#keyPool[writePos++] += (unsigned __int8) (crc >> 8);
				keyfilePool[keyfilePoolCursor+2] = (keyfilePool[keyfilePoolCursor+2] + ((crc >> 8) & 0xFF)) % 256
				#keyPool[writePos++] += (unsigned __int8) crc;
				keyfilePool[keyfilePoolCursor+3] = (keyfilePool[keyfilePoolCursor+3] + ((crc) & 0xFF)) % 256
				keyfilePoolCursor += 4

				#reset cursor if needed
				if keyfilePoolCursor == 64: keyfilePoolCursor = 0

				#stop processing if 1MB has been read
				if total_processed == 1048576: break

		keyfilePoolString = ""
		for x in range(64):
			keyfilePoolString = keyfilePoolString + chr((keyfilePool[x] + ord(password[x])) % 256)

		return keyfilePoolString

	def decodeHeader(self):
		#Decode header into struct/namedtuple
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
		if self.valid and secstart == 0:
			secstart = self.hdr_decoded.DataStart / 512
		self.fd.seek((secstart + sector)*512)
		return self._decrypt_sector(secstart + sector, self.fd.read(512))

	# Gets ciphertext sector from data input
	def getCipherSector(self, sector, plaintext, secstart=0):
		if not (self.valid or (self.open_with_key and secstart > 0)):
			return False
		if len(plaintext) != 512:
			return False
		if self.valid and secstart == 0:
			secstart = self.hdr_decoded.DataStart / 512
		return self._encrypt_sector(secstart + sector, plaintext)

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
