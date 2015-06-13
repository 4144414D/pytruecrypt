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
image is used to image a truecrypt container for further analysis. The container can be open with a password or with keys extracted from memory.

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
You wish to image a TrueCrypt file "input1.tc" to an image named "output1.dd", 
it uses aes and ripemd. The password is "Scenario1". As ripemd is the default
for TrueCrypt it does not need to be specified.

    > image pwd input1.tc output1.dd aes Scenario1 

######Scenario 2:
You wish to image a TrueCrypt file "input2.tc" to an image named "output2.dd",
it uses aes-serpent and sha512. The password is "Scenario2". You wish to save 
time and use the short hand commands.

    > image pwd input2.tc output2.dd as Scenario2 s

######Scenario 3:
You wish to image a TrueCrypt file "input3.tc" to an image named "output3.dd",
it uses aes-serpent. You know it contains a hidden volume and the password is 
"Scenario3".

    > image pwd input3.tc output3.dd aes-serpent Scenario3 --hidden

######Scenario 4:
You wish to image a TrueCrypt file "input4.tc" to an image named "output4.dd",
it uses aes. You do not know the password but have extracted AES keys from 
memory. 

    > image key input4.tc output4.dd aes --aes bac01155a46547f00c3ddf9a4a765159fbe
    1f68d94bf11a3bd6910eedf26d867a63263c949812cd68b7dad91a8dfdacb96942b93cc1b21ffa
    feeb4791a0befa4


####pw-check.py
pw-check.py is used to check that a small list of passwords work against a container. It checks all options available in Truecrypt and allows you to confirm that normal and backup headers match. The -d option will print the decoded header to screen if successful, the -v option will also read Veracrypt files.  

    > pw-check <container> <password>
    > pw-check example.tc password
	password appears to be valid for a TrueCrypt standard volume using the normal header using aes and ripemd
	password appears to be valid for a TrueCrypt standard volume using the backup header using aes and ripemd

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

Very little as the code is generally compact. See the examples, and pytruecrypt.py - the comments show how to use it.
