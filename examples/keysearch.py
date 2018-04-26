"""
keyseaerch helps locate data by attempting to decrypt sectors with supplied
keys and seeing how random the resutls are.

Encryption modes can be assigned long or short hand where:
aes      = a
twofish  = t
serpent  = s

For example 'aes-twofish' can be shortened to 'at' and aes-twofish-serpent
to ats.

GitHub: https://github.com/4144414D/pytruecrypt

Usage:
 image <source> [-mMODE -aKEY -tKEY -sKEY -oNUM]
 image --help

Options:
 --help                       Show this screen
 -a key, --aes key            AES Key
 -t key, --twofish key        Twofish Key
 -s key, --serpent key        Serpent Key
 -o num, --offset num         Decrypt as offset number num [default: 256]
 -m MODE, --mode mode         Encryption mode to use [default: aes]
"""

from pytruecrypt import *
from docopt import docopt
import os
import binascii
import time
from util import *
import numpy as np
import math

def checkkey(mode,key,name):
    if key != None:
        #check if key is required but not supplied
        if (name not in mode):
            print "ERROR " + name + " key is not required for the selected encryption mode"
        #check key is correct length
        elif (len(key) == 128):
            try:
                #try to convert hex to bin
                return binascii.unhexlify(key) #good outcome
            except TypeError:
                print "ERROR " + name + " key invalid and contains non hex characters [0-f]"
        #if key is incorrect length give an error
        elif (len(key) != 128):
            print "ERROR " + name + " key is not the correct length"
    else:
        #check if key is required but not supplied
        if (name in mode):
            print "ERROR " + name + " key is required for the selected encryption mode but not supplied"
    return False #everything else is a fail


#jaradc - https://gist.github.com/jaradc/eeddf20932c0347928d0da5a09298147
def entropy(data):
   """ Computes entropy of label distribution. """
   labels = list(data)
   n_labels = 512.0

   value,counts = np.unique(labels, return_counts=True)
   probs = counts / n_labels

   n_classes = np.count_nonzero(probs)

   ent = 0.

   # Compute entropy
   for i in probs:
     ent -= i * math.log(i, 2)
   return ent

if __name__ == '__main__':
    arguments = docopt(__doc__)

    #check crypto options
    if arguments['--mode'] in ["a","at","ats","s","sa","sta","t","ts"]:
        #viable short hand mode chosen, convert to long hand, this is dumb
        arguments['--mode'] = arguments['--mode'].replace('a','1').replace('t','2').replace('s','3')
        arguments['--mode'] = arguments['--mode'].replace('1','aes-').replace('2','twofish-').replace('3','serpent-')[:-1]
    elif arguments['--mode'] not in ["aes","aes-twofish","aes-twofish-serpent","serpent","serpent-aes","serpent-twofish-aes","twofish","twofish-serpent"]:
        print "ERROR Please choose a viable crypto mode:"
        for line in ["aes","aes-twofish","aes-twofish-serpent","serpent","serpent-aes","serpent-twofish-aes","twofish","twofish-serpent"]:
            print "\t"+line
        exit(1)

    #split long hand into list
    arguments['--mode'] = arguments['--mode'].split('-')

    #check keys are viable if required
    key_count = 0
    aes_key = None
    twofish_key = None
    serpent_key = None
    aes_key = checkkey(arguments['--mode'],arguments['--aes'],'aes')
    twofish_key = checkkey(arguments['--mode'],arguments['--twofish'],'twofish')
    serpent_key = checkkey(arguments['--mode'],arguments['--serpent'],'serpent')
    if not (aes_key or twofish_key or serpent_key): exit(1)

    #check source file exists
    if not os.path.isfile(arguments['<source>']):
        print "ERROR",
        print arguments['<source>'],
        print "does not exist"
        exit(1)

    #use PyTruecrypt to open source
    tc = PyTruecrypt(arguments['<source>'], encryption=arguments['--mode'])

    #open source with keys
    tc.open_with_key(aes_key,twofish_key,serpent_key)

    offset = int(arguments['--offset'])
    tick = 0

    for x in range(0,tc.size,512):
        tc.fd.seek(x)
        cipher = tc.fd.read(512)
        sector = x/512
        plain = tc._decrypt_sector(offset,cipher)
        ent = entropy(plain)
        if ent < 7:
            print
            print "Possible result at sector: {}".format(str(sector))
            print hexdump(plain)
            pause = raw_input("Press enter to contiune...")
        tick += 1
        if tick == 128:
            tick = 0
            percentage = (float(100) / tc.size) * x
            print "\rSearching... {}%".format(percentage),
    print "\rSearching... 100%                                 "
