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
  hunt <file> <passwords>... (--chain=<n>|--brute) [-a] [--ent=<log>]

Options:
  -h, --help              Show this screen.
  -a, --all               Search for all TrueCrypt options. Very slow.
  -b, --brute             Test all sectors. Extremely slow.
  -c n, --chain n         Search using chain of high entropy, n is number of sectors.
  -e log, --ent log       Save the full calculated entropy to log file.
"""

from pytruecrypt import *
from util import *
from docopt import docopt
import tempfile
import os
import sys
import time
import math
import pickle
from bitarray import bitarray
import numpy as np

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
                        print 'Sector {}: Fully valid header found'.format(sector_num)
                        r.write('Sector {}: Fully valid header found\n'.format(sector_num))
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
        if tick == 500:
            tick = 0
            percentage = (float(100) / len(source_entropy)) * x
            print "\rFinding chains... {}%".format(percentage),
        if source_entropy[x]:
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
                cur_len += 1
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
    search_size = 8

    for chain in chains:
        chain_sector = chain[0]
        chain_len = chain[1]

        #calc start location
        search_start = (chain_sector - search_size) * 512
        search_end = (chain_sector + search_size) * 512
        search_range(search_start, search_end, f,hash_options,crypto_options,passwords)

        #calc start location, searching for the typical location of a normal
        #backup header and not a hidden header. Changing the -256 will change
        #this or increasing the search size will aloow it to be found however
        #this will be slow
        search_start = (chain_sector + chain_len - 256 - search_size) * 512
        search_end = (chain_sector + chain_len - 256 + search_size) * 512
        search_range(search_start, search_end, f,hash_options,crypto_options,passwords)

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
    size = f.tell()
    f.seek(0)

    #print "Starting..."
    if arguments['--brute']:
           search_range(0,size,f,hash_options,crypto_options,arguments['<passwords>'])
    else:
        if arguments['--ent']:
            entropy_log = open(arguments['--ent'],'w')
        pickle_file = arguments['<file>']+'.entropy'
        if os.path.isfile(pickle_file):
            print "Loading source entropy from {}".format(pickle_file)
            source_entropy = load(pickle_file)
        else:
            source_entropy = bitarray()
            #run entropy calculations
            tick = 0
            for x in range(0,size,512):
                tick += 1
                if tick == 1000:
                    tick = 0
                    percentage = (float(100) / size) * x
                    print "\rCalculating source entropy... {}%".format(percentage),
                data = f.read(512)
                sector_entropy = entropy(data)
                if sector_entropy > 7:
                    source_entropy.append(True)
                else:
                    source_entropy.append(False)
                if arguments['--ent']:
                    entropy_log.write("{}\n".format(sector_entropy))

            if arguments['--ent']:
                entropy_log.close()
            print "\rCalculating source entropy... 100%          "
            print "Saving {}... ".format(pickle_file),
            save(source_entropy, pickle_file)
            print "done"

        target = int(arguments['--chain'])

        chains = chain_search(source_entropy,target)
        if len(chains) > 0:
            test_chains(chains,f,hash_options,crypto_options,arguments['<passwords>'])
        else:
            print "No chains found."

if __name__ == '__main__':
    arguments = docopt(__doc__)
    main(arguments)
