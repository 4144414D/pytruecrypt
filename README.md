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

And using struct to pass the fields:

	TCHDR(Magic='TRUE', HdrVersion=5, MinProgVer=7,  
	CRC=684324914, Reserved='\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',  
	HiddenVolSize=0, VolSize=4980736, DataStart=131072,  
	DataSize=4980736, Flags=0, SectorSize=512, Reserved2='\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',  
	CRC3=2168932094,  
	Keys='f.\x96\tW\xbb~\x82\xf8\xfc\x82{U\x84\xec\xac\xdb\x1f\xa9d|\xafF\xd5&\x9a\xee8\xb9S\x7f&0\xa1u\x0cV\xc9-\xc6~h\t)\t\x80\xb0\xd7\xca\xc8\xc8\xc8\x0eo\x8d\xbd\x8d\x80\xcd"\xd0\xa6\x8c\x99\xdb\xd6\xca\xc1R\x00,\x97\xedq\xa9\x83}!Bd\xf9/\t\x84\xbd\x05TU\x1d\xa1\xc3\xb1&\rk\\~\xec\x14\x0f\x19\xbb\x8bi\x8a~\xa2M$\xfe\xf5\xb8y\xf6\xa1\xe5\x15\xa9\xaai\xe7l\xec_:\xdce\x94\'e"=L|\x0b\xc3\x01\xfb\x14\x05\x14\xd8\x15v\x10t\x1d\x9f\xc6\x97\x8fY\xf2jT(\xaa\x13qo\x8f\xab\xd4\t\xa1\xc1\xa5<\n\n\xd58\x07\xcfdH\x9b+\xc4^\xcfO\xe6\xa5wbZt#\xed\xefI\x0cx\x9f\x08\xb7\x89\xee\xc4\xa0\xc3\x7fe\xb9\x92jDS@\xea\x8bk\x043\x0b\xdc!\x95\x9a\xd7\xd4\x0b\x07\xeaS\xa8)\xf2\x1cY$%\xff\xc7\'s\xd0\x9f%\xf2\xa1C\x90\x92/\x14z]1\xb2\xfaY\xbb+e')  

