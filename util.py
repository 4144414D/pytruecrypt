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
# Note: must output 128bit block (ignoring higher significant bytes) otherwise breaks xts code
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

