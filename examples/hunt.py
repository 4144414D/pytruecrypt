"""
hunt will search a file and attempt to decrypt each sector as if it we're a
header. This has not been optimised and will run quite slowly particularly if
the --all option is used. If you are scanning a lot of data and need better
please contact me and I'll do my best to improve this. This is very CPU
intensive and currently only uses a single core.

This searches for the typical locations of normal containers. It can be modified
to look for hidden containers. Please contact me if needed.

GitHub: https://github.com/4144414D/pytruecrypt
Email: adam@nucode.co.uk

Usage:
  hunt <file> <passwords>... [-da] --chain=<n>

Options:
  -h, --help              Show this screen.
  -d, --dump              Dump decrypted header if successful.
  -a, --all               Search for all TrueCrypt options. Very slow.
  -c n, --chain n         Search using chain of entropy, n is number of sectors.
"""

from pytruecrypt import *
from util import *
from docopt import docopt
import binascii
import tempfile
import os
import sys
import time
import math
import pickle

#http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html
def entropy(data):
  if not data:
    return 0
  entropy = 0
  for x in range(256):
    p_x = float(data.count(chr(x)))/len(data)
    if p_x > 0:
      entropy += - p_x*math.log(p_x, 2)
  return entropy

def test_sector(hash_options, crypto_options, passwords, data, sector_num):
    #create memory backed temp file
    t = tempfile.SpooledTemporaryFile(1024)
    t.write(data)
    for password in passwords:
        #loop for each hash option
        for hash in hash_options:
            #loop for each crypto option
            for crypto in crypto_options:
                tc = PyTruecrypt(encryption=crypto,hash_func=hash,fd=t)
                tc.open(password)
                if tc.valid or (entropy(tc.tchdr_plain) < 3):
                    r = open('results.txt','a')
                    if tc.valid:
                        print 'Sector {}: Fully vaild header found'.format(sector_num)
                        r.write('Sector {}: Fully vaild header found\n'.format(sector_num))
                    else:
                        print 'Sector {}: Low entropy decrypted sector, possible damaged header'.format(sector_num)
                        r.write('Sector {}: Low entropy decrypted sector, possible damaged header\n'.format(sector_num))
                    print "\tHash Option: {}".format(hash)
                    r.write("\tHash Option: {}\n".format(hash))
                    print "\tCrypto Option: {}".format(crypto)
                    r.write("\tCrypto Option: {}\n".format(crypto))
                    print "\tPassword: {}".format(password)
                    r.write("\tPassword: {}\n".format(password))
                    print ""
                    r.write("\n")
                    print "Decrypted Header:"
                    r.write("Decrypted Header:\n")
                    print hexdump(tc.tchdr_plain)
                    r.write(hexdump(tc.tchdr_plain))
                    print
                    r.write('\n')

                    s = open("PS{}.dd".format(sector_num),'wb')
                    s.write(data)
                    s.close

def chain_search(source_entropy,target):
    target = int(target)
    chains = []
    cur_start = -1
    cur_len = -1
    tick = 0
    for x in range(len(source_entropy)):
        tick += 1
        if tick == 512:
            tick = 0
            percentage = (float(100) / len(source_entropy)) * x
            print "\rFinding chains... {}%".format(percentage),
        if source_entropy[x] > 7:
            #contiune chain or start new chain
            if cur_len > -1:
                #contiune chain
                cur_len += 1
            else:
                #start new chain
                cur_start = x
                cur_len = 0
        else:
            #end chain or skip
            if cur_len > -1:
                #end chain
                if cur_len >= target:
                    #append current chain to list
                    chains.append([cur_start,cur_len])
                #reset chaiin stats
                cur_start = -1
                cur_len = -1
            else:
                #skip one entropy sector
                pass
    print "\rFinding chains... 100%          "
    return chains

def search_range(start,end,f,hash_options,crypto_options,passwords):
    f.seek(start)
    for x in range(start,end,512):
        data = f.read(512)
        sector_num = x / 512
        print "Testing Sector: {}".format(sector_num)
        test_sector(hash_options, crypto_options, passwords, data, sector_num)

def test_chains(chains,f,hash_options,crypto_options,passwords):
    for chain in chains:
        chain_sector = chain[0]
        chain_len = chain[1]

        #calc start location
        search_start = (chain_sector - 8) * 512
        search_size = (chain_sector + 8) * 512
        search_range(search_start, search_size, f,hash_options,crypto_options,passwords)

        #calc start location, searching for the typical location of a normal
        #backup header and not a hidden header. Changing the -256 will change
        #this or increasing the search size will aloow it to be found however
        #this will be slow
        search_end = (chain_sector + chain_len - 256 - 8) * 512
        search_size = (chain_sector + chain_len - 256 + 8) * 512
        search_range(search_end, search_size, f,hash_options,crypto_options,passwords)

def save(obj, path):
    with open(path, 'wb') as f:
        pickle.dump(obj, f, pickle.HIGHEST_PROTOCOL)

def load(path):
    with open(path, 'rb') as f:
        return pickle.load(f)

def main(arguments):
    arguments = docopt(__doc__)
    if arguments['--all']:
        hash_options = ['ripemd','sha512','whirlpool']
        crypto_options = [["aes"],["aes","twofish"],["aes","twofish","serpent"],
        ["serpent"],["serpent","aes"],["serpent","twofish","aes"],["twofish"],
        ["twofish","serpent"]]
    else:
        hash_options = ['ripemd']
        crypto_options = [["aes"]]

    #open file and find total size
    f = open(arguments['<file>'], 'rb')
    f.seek(0, os.SEEK_END)
    f.tell()
    size = f.tell()
    f.seek(0)

    if os.path.isfile("ent.pickle"):
        print "Loading source entropy from ent.pickle"
        source_entropy = load("ent.pickle")
    else:
        source_entropy = []
        #run entropy calculations
        tick = 0
        for x in range(0,size,512):
            tick += 1
            if tick == 512:
                tick = 0
                percentage = (float(100) / size) * x
                print "\rCalculating source entropy... {}%".format(percentage),
            data = f.read(512)
            sector_entropy = entropy(data)
            source_entropy.append(sector_entropy)
        save(source_entropy, 'ent.pickle')
        print "\rCalculating source entropy... 100%          "

    #convert chain MB into number of sectors
    target =  int(arguments['--chain']) * 1024 * 1024 / 512

    chains = chain_search(source_entropy,target)
    if len(chains) > 0:
        test_chains(chains,f,hash_options,crypto_options,arguments['<passwords>'])

if __name__ == '__main__':
    arguments = docopt(__doc__)
    main(arguments)
