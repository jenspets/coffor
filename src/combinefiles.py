#!/usr/bin/env python3

from itertools import combinations
import itertools
import argparse
import subprocess

RDEXE = '/usr/bin/radiff2'

if '__main__' == __name__:
    parser = argparse.ArgumentParser(description='Print combinations of filenames given as inputs')
    parser.add_argument('names', metavar='Source', type=str, nargs='+', help='Source files to to compare')
    parser.add_argument('--alg', '-s', action='count', default=0, help='Algorithm for comparison')
    parser.add_argument('--target', '-t', type=str, nargs=1, help='Target file for comparing the sources') 
    args = parser.parse_args()

    if args.alg == 0:
        args.alg = 3 

    if not args.target:
        for i in combinations(args.names, 2):
            # print(i[0], i[1])
            so = subprocess.run([f'{RDEXE}', f'-{args.alg*"s"}', '-c', f'{i[0]}', f'{i[1]}'], stdout=subprocess.PIPE)
            out = so.stdout.decode('utf-8')
            outl = [x.strip() for x in out.split('\n')]
            print(f'{outl[0]}, {outl[1]}, {i[0]}, {i[1]}')

    if args.target:
        lines = []
        diffs = []
        for s in args.names:
            so = subprocess.run([f'{RDEXE}', f'-{args.alg*"s"}', '-c', f'{args.target[0]}', f'{s}'], stdout=subprocess.PIPE)
            out = so.stdout.decode('utf-8')
            outl = [x.strip() for x in out.split('\n')]
            lines.append(f'{s}, {args.target[0]}, {outl[0]}, {outl[1]}')
            sim  = float(outl[0].split(':')[1].strip())
            dist = int(outl[1].split(':')[1].strip())
            page = s[-10:-6]
            diffs.append([page, sim, dist])
            
        # lines.sort()
        # for l in lines:
        #    print(l)
        for d in diffs:
            print(d)
        print('pages <- c('+','.join([f'0x{x[0]}' for x in diffs])+')')
        print('diffs <- c('+','.join([str(x[1]) for x in diffs])+')')
        print('dists <- c('+','.join([str(x[2]) for x in diffs])+')')
