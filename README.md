pytruecrypt
===========
  
Truecrypt volume parsing library by originally created by [Gareth Owen](https://github.com/drgowen/), University of Portsmouth, with additional features added by [Adam Swann](https://github.com/4144414d/).
  
Library status:
- Decrypts header (can dump raw decrypted header)
- Decodes header fields
- Can dump any decrypted sector
- Hidden volume support
- Veracrypt support
- Can decrypt using only recovered keys (no password required)
- Supports all encryption modes and hash functions offered by Truecrypt
- Can decrypt damaged containers if salt and header keys are recoverable 
- Easy to use - see example and source code for API

Examples:
- dump.py: Header and first sector decrypted hex dump
- image.py: Create decrypted dd image of container
- pw-check.py: Checks password against all available Truecrypt options
- pwcracker.py: Password cracker
- quick-container.py: Produces a working Truecrypt container in seconds
- reserved.py: Hides data within the reserved space of a container

Example Usage
-------------
Below are examples on how to use the example scripts.
####dump.py
dump.py will perform a hex dump of the decrypted header and first sector of a container. It also works with hidden volumes if given the -h option. 

    > dump <container>
    > dump example.tc
    > Enter password: password
	
    HEADER RAW ----------
    0000  54 52 55 45 00 05 07 00 5c 96 e9 4b 00 00 00 00   TRUE.......K....
    0010  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    0020  00 00 00 00 00 00 00 00 00 0c 00 00 00 00 00 00   ................
    0030  00 02 00 00 00 00 00 00 00 0c 00 00 00 00 00 00   ................
    0040  00 00 02 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    0050  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    0060  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    0070  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    0080  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    0090  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    00a0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    00b0  00 00 00 00 00 00 00 00 00 00 00 00 33 73 eb c2   ............3s..
    00c0  12 12 2c ee 8a ff 05 d5 2f ef d3 6e 49 a9 4a bb   ..,...../..nI.J.
    00d0  13 0e 08 f1 3a 93 73 2a 71 86 97 7d 40 70 af 62   ....:.s*q..}@p.b
    00e0  05 8e 6f 27 36 0c 64 06 6e 41 23 8f fe f8 33 65   ..o'6.d.nA#...3e
    00f0  6c 34 f9 54 f1 71 96 f9 36 9e f1 ab 62 75 c6 6b   l4.T.q..6...bu.k
    0100  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    0110  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    0120  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    0130  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    0140  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    0150  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    0160  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    0170  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    0180  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    0190  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    01a0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    01b0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    
    HEADER ------------
    Magic : TRUE
    HdrVersion : 5
    MinProgVer : 7
    CRC : 1553393995
    Reserved :                 
    HiddenVolSize : 0
    VolSize : 786432
    DataStart : 131072
    DataSize : 786432
    Flags : 0
    SectorSize : 512
    Reserved2 :                                                                                                                         
    CRC3 : 863235010
    Keys : 12122cee8aff05d52fefd36e49a94abb130e08f13a93732a7186977d4070af62058e6f27360c64066e41238ffef833656c34f954f17196f9369ef1ab6275c66b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    
    FIRST SECTOR-------
    0000  eb 3c 90 4d 53 44 4f 53 35 2e 30 00 02 01 02 00   .<.MSDOS5.0.....
    0010  02 00 02 00 06 f8 05 00 01 00 01 00 00 00 00 00   ................
    0020  00 00 00 00 00 00 29 dc 16 81 6a 4e 4f 20 4e 41   ......)...jNO NA
    0030  4d 45 20 20 20 20 46 41 54 31 32 20 20 20 00 00   ME    FAT12   ..
    0040  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    0050  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    0060  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    0070  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    0080  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    0090  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    00a0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    00b0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    00c0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    00d0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    00e0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    00f0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    0100  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    0110  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    0120  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    0130  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    0140  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    0150  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    0160  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    0170  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    0180  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    0190  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    01a0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    01b0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    01c0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    01d0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    01e0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
    01f0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 55 aa   ..............U.

####image.py
image is used to image a Truecrypt container for further analysis. The container can be open with a password or with keys extracted from memory.

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

#####Example usage:

    > image pwd <tc> <image> <mode> <password> [<hash>] [-vbh] [(-f -oBYTES -dBYTES)]
    > image key <tc> <image> <mode> [-aKEY -tKEY -sKEY] [(-oBYTES -dBYTES)]

######Scenario 1:
You wish to image a Truecrypt file "input1.tc" to an image named "output1.dd", 
it uses aes and ripemd. The password is "Scenario1". As ripemd is the default
for Truecrypt it does not need to be specified.

    > image pwd input1.tc output1.dd aes Scenario1 

######Scenario 2:
You wish to image a Truecrypt file "input2.tc" to an image named "output2.dd",
it uses aes-serpent and sha512. The password is "Scenario2". You wish to save 
time and use the short hand commands.

    > image pwd input2.tc output2.dd as Scenario2 s

######Scenario 3:
You wish to image a Truecrypt file "input3.tc" to an image named "output3.dd",
it uses aes-serpent. You know it contains a hidden volume and the password is 
"Scenario3".

    > image pwd input3.tc output3.dd aes-serpent Scenario3 --hidden

######Scenario 4:
You wish to image a Truecrypt file "input4.tc" to an image named "output4.dd",
it uses aes. You do not know the password but have extracted AES keys from 
memory. 

    > image key input4.tc output4.dd aes --aes bac01155a46547f00c3ddf9a4a765159fbe
    1f68d94bf11a3bd6910eedf26d867a63263c949812cd68b7dad91a8dfdacb96942b93cc1b21ffa
    feeb4791a0befa4


####pw-check.py
pw-check.py is used to check that a small list of passwords work against a container. It checks all options available in Truecrypt and allows you to confirm that normal and backup headers match. The -d option will print the decoded header to screen if successful, the -v option will also read Veracrypt files.  

    > pw-check <container> <password>
    > pw-check example.tc password
	password appears to be valid for a Truecrypt standard volume using the normal header using aes and ripemd
	password appears to be valid for a Truecrypt standard volume using the backup header using aes and ripemd

####pwcracker.py
pwcracker.py is an example password cracker for Truecrypt. Simply provide a word list and it will attempt to crack the container.

    > pwcracker <container> <wordlist>
    > pwcracker example.tc wordlist.txt
    > PW Found: password

####quick-container.py
quick-container.py produces a Truecrypt container quickly by skipping the first stage encryption setting. This is therefore similar to 'quick format' full disk encryption whereby the free space is not first encrypted. This means a hidden volume is very obvious and it's possible to track the ammount of encrypted data stored within a container. 

The containers are not formatted and once mounted will require a file system to be created. Containers are always created using AES and ripemd. 

    > quick-container <container> <password> <mb-size>
    > quick-container example password 1024
	
####reserved.py
reserved.py uses the free space in the Truecrypt header to hide additional data. This data is encrypted with the same password as the container itself. 

To hide a file:

    > reserved hide <container> <password> <file>
    > reserved hide example.tc password secret.txt
	
To read a hidden file:

    > reserved check <container> <password>
    > reserved check example.tc password
    > My secret file...

Prerequisites:
-------------
You must have pycryptoplus installed - https://github.com/doegox/python-cryptoplus

For many examples you must have docopt installed - http://docopt.org/
  
Truecrypt Documentation:
-------------

Very little as the code is generally compact. See the examples, and pyTruecrypt.py - the comments show how to use it. I am slowly expanding this section. 

###Truecrypt Basics
Truecrypt works in two main ways either as full disk encryption or using
encrypted containers on Windows, Linux, or OSX. On windows it is also
possible to encrypt the operating system with Truecrypt and boot into
windows. This is not possible on Linux or OSX but it can still use full
disk encryption on non OS disks.

###Algorithms
Truecrypt allows the following encryption schemes all working in XTS
mode. Where more than one encryption algorithm is used the data is
encrypted with each algorithm using different master keys.

- AES (default)
- Serpent
- Twofish
- AES - Twofish
- AES - Twofish - Serpent
- Serpent - AES
- Serpent - Twofish - AES

Three hash algorithms are available, these are:

- RIPEMD (default)
- SHA-512
- WHIRLPOOL


###Encryption in Truecrypt

Truecrypt uses each of the different encryption algorithms in XTS mode.
In short this means that same plain text data encrypted with the same
key but in a different location will produce a different cipher text.
For example a completely zeroed disk encrypted with XTS mode would look
completely random, each sector of zeros produces a different sector of
encrypted data. If ECB mode was used instead you would see a repeating
pattern where each sector of zeros produced the same sector of encrypted
data.

Truecrypt stores the master keys within the Truecrypt header and these
keys are not generated based on the password chosen for the container.
Instead the master keys are generated randomly when the container is
created and stored in the header, the header is then encrypted using the
password provided for by the user. Only by knowing the password to the
header can you successfully decrypt the header and get to the master
keys to decrypt the data.

This allows the user to change the password to a container. Rather then
needing to re-encrypt the whole container only the headers need to be
re-encrypted with the new password, the master keys remain the same.

This raises the obvious risk, if an attacker can decrypt the header at
any point in time they can use the master keys to decrypt data. I.E. A
container is created with a simple password, the attacker cracks this 
password and stores the master keys. Later the users changes the password
to the container in an effort to increase security, however the attacker 
already has the master keys and as such can decrypt the container. 


###Volumes

TrueCrypt allows the user to have a normal volume and a hidden volume.
The normal volume is designed to be well encrypted but if the TrueCrypt
volume is detected you would not be able to plausibly deny its
existence, and so rubber hose cryptanalysis could be used to get the
password from you. The hidden volume on the other hand is designed to
hide within the normal volume and would look like any other section of
random data, allowing you to plausibly deny it being there.

The layout of a container is shown in below. The first 256 sectors store 
the main headers, while the last 256 sectors store the backup headers 
should the main headers be damaged. Everything in-between is the data 
section of the container and will store the actual user data.

Almost everything within the container is encrypted so normal analysis
of the file will simply show ‘random’ data. Only the salts for each of
the headers are store in a decrypted form, however these are simply 64
bits of random data so should be impossible to tell them apart.

The normal and backup headers contain the same decrypted data however
they are encrypted with different salts. This means they will appear to
be completely different on the binary level.

The space in the headers (254 sectors in total) is seeded with random
data when the container is first created. This is one of the main
reasons it’s difficult to detect a hidden volume, with or without one
this sector will seemingly contain random data.

![Truecrypt Layout](https://raw.githubusercontent.com/4144414D/pytruecrypt/gh-pages/images/container-layout.png)

###Truecrypt Header v5

Truecrypt 7.1a uses the header version 5. This header is the same for
normal and hidden volumes and system encryption, the difference is
simply their location and flag bits.

####Header Elements

**1)  Salt - 64 Bytes**

    The salt is used when encrypting the header. This is randomly
    generated data and so will look as if it’s encrypted.

**2)  File Signature - 4 Bytes**

    The ASCII string ‘TRUE’. This is used to check if the header has
    been decrypted correctly.

**3)  Header Version - 2 Bytes**

    The version of Truecrypt header in use, for 7.1a this will always be
    [\\x00\\x05](\x00\x05).

**4)  Truecrypt Version - 2 Bytes**

    The minimum version of Truecrypt needed to use the volume. For 7.1a
    this is always be [\\x00\\x07](\x00\x07).

**5)  Key CRC - 4 Bytes*

    A CRC32 value for the bytes 256-511 of the header. I.E. the master
    keys. This is also used to confirm if the Truecrypt header has been
    decrypted correctly.

**6)  Reserved Space - 16 Bytes**

    16 Bytes of [\\x00](\x00) which aren’t used in the header.

**7)  Size of Hidden Volume - 8 Bytes**

    The size in bytes of the hidden volume. This is set to zero in a
    non-hidden volume.

**8)  Size of Hidden Volume - 8 Bytes**

    The size in bytes of the volume.

**9)  Offset to Data - 8 Bytes**

    The is the byte offset from the start of the data. If this header is
    for a normal (non-hidden) container this should be
    [\\x00\\x00\\x00\\x00\\x00\\x02\\x00\\x00](\x00\x00\x00\x00\x00\x02\x00\x00).
    This is 131072 bytes, or sector 256.

**10) Size of Data - 8 Bytes**

    The total size in bytes of the data portion of the container.

**11) Flag Bits - 4 Bytes**

    Used to determine what type of container is in use. Bit 0 is set for
    system encryption, while bit 1 is set for non-system in place
    encryption. The other bits are not used.

**12) Reserved Space - 120 Bytes**

    Further space in the header which isn’t used.

**13) Header CRC - 4 Bytes**

    A CRC32 value for the bytes 64-251 of the header.

**14) Master Keys - 64 Bytes each**

    The remaining space is devoted to the master keys. If multiple
    encryption algorithms are used then multiple keys will be present.
	
![Truecrypt Header](https://raw.githubusercontent.com/4144414D/pyTruecrypt/gh-pages/images/header-layout.png)
