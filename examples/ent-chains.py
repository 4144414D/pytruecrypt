"""
ent-chains looks for chains of high entropy data.

GitHub: https://github.com/4144414D/pytruecrypt
Email: adam@nucode.co.uk

Usage:
  ent-chains <file> --chain=<n> [--ent=<x>]

Options:
  -h, --help            Show this screen.
  -c n, --chain n       n is number of sectors in a row required for a chain.
  -e x, --ent x         x is the value to use as 'high' entropy [default: 7.4].

"""

from docopt import docopt
import math
from bitarray import bitarray
import os
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

def main(arguments):
    f = open(arguments['<file>'], 'rb')
    f.seek(0, os.SEEK_END)
    size = f.tell()
    f.seek(0)

    source_entropy = bitarray()
	#run entropy calculations
    tick = 0
    target = float(arguments['--ent'])
    for x in range(0,size,512):
        tick += 1
        if tick == 1000:
            tick = 0
            percentage = (float(100) / size) * x
            print "\rCalculating source entropy... {}%".format(percentage),
        data = f.read(512)
        if entropy(data) > target:
            source_entropy.append(True)
        else:
            source_entropy.append(False)
    print "\rCalculating source entropy... 100%          "

    target = int(arguments['--chain'])

    chains = chain_search(source_entropy,target)
    if len(chains) > 0:
        print 
        print "start\tlen"
        for chain in chains:
            print "{}\t{}".format(chain[0],chain[1])
    else:
        print "No chains found."

if __name__ == '__main__':
    arguments = docopt(__doc__)
    main(arguments)
