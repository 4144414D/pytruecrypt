pytruecrypt
===========
  
Truecrypt volume passing library by Gareth Owen, University of Portsmouth  
  
Current status: Dumps decrypted header - Can dump any decrypted sector if you take keys from header - see code for example.  
  
TODO: Restructure into library, header passing, add more options  
  
Example usage:  
  
pytruecrypt.py file password  
  
Example:  

	[gho@gho-ubook pytruecrypt]$ python2.7 pytruecrypt.py ../test.tc abc123 | hd  
	000000: 54 52 55 45 00 05 07 00  43 70 7f 07 00 00 00 00   TRUE....Cp......  
	000010: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   ................  
	000020: 00 00 00 00 00 00 00 00  00 4c 00 00 00 00 00 00   .........L......  
	000030: 00 02 00 00 00 00 00 00  00 4c 00 00 00 00 00 00   .........L......  
	000040: 00 00 02 00 00 00 00 00  00 00 00 00 00 00 00 00   ................  
	000050: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   ................  
	--more zeroes--  
	0000b0: 00 00 00 00 00 00 00 00  00 00 00 00 02 84 05 54   ...............T  
	0000c0: cb b9 59 ed 2c 6c 0f c4  ba e2 77 af e4 a8 f5 93   ..Y.,l....w.....  
	0000d0: 2c e9 42 2d 91 55 e8 43  1a 20 db 80 30 20 21 0c   ,.B-.U.C. ..0 !.  
	0000e0: 20 88 ec 66 d8 95 60 6a  4f ff db da 2c 4d 53 aa    ..f..`jO...,MS.  
	0000f0: 5b f1 5a c6 87 06 95 62  4c ac 61 ca 0f 21 89 15   [.Z....bL.a..!..  
	--more zeroes--  
	000100: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   ................  

