#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host rockyoudle-1.play.hfsc.tf --port 10000
from pwn import *
import string
import copy

# Set up pwntools for the correct architecture
context.update(arch='i386')
exe = './path/to/binary'

import sys
import re

# FLAG: midnight{quend4ev3r4ndev3r}

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141 EXE=/tmp/executable
host = args.HOST or 'rockyoudle-1.play.hfsc.tf'
port = int(args.PORT or 10000)
flag_pattern = r'midnight\{[^\}]+\}'

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

def load_rockyou():
    with log.progress("Retrieving dict") as prog_rockyou:

        prog_rockyou.status("Open file")
        with open('rockyou.txt', "r") as file:

            prog_rockyou.status("Clean-up")
            l = [line.strip().replace(" ","").upper() for line in file]
            l = [w for w in l if w.isalnum()]
        prog_rockyou.success(f"{len(l)} words")

    return l


def filter_rockyou(dic, subset, cont, blacklist):

    # remove words that dont have all our contenders
    with log.progress(f"Filtering dict") as prog_filter:

        new_l = []
        f_cont = [item for item in cont if item is not None]
        for w in dic:
            if all(e in w for e in f_cont):
                new_l.append(w)
        # print("1", len(new_l))
        prog_filter.status(f"1. removed words that dont have all our contenders. New size: {len(new_l)}")

        # remove words based on the contenders position
        new_l4 = []
        for w in new_l:
            app = True
            for l_w, l_c in zip(w, cont):
                if l_c == None:
                    continue
                elif l_w == l_c:
                    app = False
            if app:
                new_l4.append(w)

        prog_filter.status(f"2. removed words based on the contenders position. New size: {len(new_l4)}")
        # print("2", len(new_l4))



        # remove words that have blacklisted elements
        new_l2 = [word for word in new_l4 if all(char not in word for char in blacklist)]
        # print("3", len(new_l2))
        prog_filter.status(f"3. removed words that have blacklisted letters. New size: {len(new_l2)}")

        # remove words that are not correct
        new_l3 = []       
        for w in new_l2:
            i = 0
            for l_w, l_s in zip(w, subset):
                if l_s == None:
                    i+=1
                    continue
                elif l_w != l_s:
                    # i+=1
                    break
                else:
                    i+=1

            if len(w) == i:
                new_l3.append(w)

        prog_filter.status(f"4. removed words that are not correct. New size: {len(new_l3)}")
        prog_filter.success(f"New size: {len(new_l3)}")

        return new_l3




def split_string(string, max_size):
    return [string[i:i+max_size] for i in range(0, len(string), max_size)]

def attempt(word, cont, size):

    global DICT
    word_idx = []
    for idx, w in enumerate(word):
        if w is None:
            word_idx.append(idx)

    # debug=False
    # if None not in word:
    #     debug = True

    global GLOB_CONT
    for w in cont:
        if None not in word:
            break

        if w is None:
            continue

        already_checked_pos = GLOB_CONT[w]
        available_pos = [x for x in word_idx if x not in already_checked_pos]
        
        if not available_pos:
            log.critical(f"{word}, {cont}, {word_idx}, {w}, {already_checked_pos}, {available_pos}")
            continue

        pos = available_pos[0]
        word[pos] = w
        word_idx.remove(pos)
        GLOB_CONT[w].append(pos)

    

    while len(word) < size:
        if not DICT:
            DICT = NUMS + COMON + filtered_alphabet
        word.append(DICT.pop(0))

    for idx, w in enumerate(word):
        if not DICT:
            DICT = NUMS + COMON + filtered_alphabet
        if w is None:
            word[idx] = DICT.pop(0)

    
    word_str = ''.join(word)

    log.info(f"Attempting {word_str}")
    io.sendline(word_str.encode())
    io.recvuntil(b': ').decode()
    res = io.recvuntil(b'\n\n').decode()
    
    subset = []
    contenders = []
    blacklist = []
    i=0
    # print(res)
    for c in res.split():
        if c == EMPTY:
            subset.append(None)
            blacklist.append(word[i])
            contenders.append(None)

        elif c == WRONG_POS:
            contenders.append(word[i])
            subset.append(None)

        elif c == CORRECT:
            contenders.append(None)
            subset.append(word[i])
        else:
            break
        
        i += 1
    
    assert len(word) == len(subset) == len(contenders)

    # if debug:
    #     print(res, word_str, subset, contenders)

    return subset, contenders, blacklist



# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
# gdbscript = '''
# continue
# '''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

EMPTY = '□'
WRONG_POS = '◩'
CORRECT = '▣'
HP = '█'
COMON = ['E', 'T', 'A', 'O', 'I', 'N', 'S', 'H', 'R', 'D']
NUMS = [str(i) for i in range(10)]
ALPHABET = list(string.ascii_uppercase)
filtered_alphabet = [letter for letter in ALPHABET if letter not in COMON]

global DICT
DICT = NUMS + COMON + filtered_alphabet
dic_main = load_rockyou()

global GLOB_CONT
GLOB_CONT = {}
for w in DICT:
    GLOB_CONT[w] = []


io = start()
logo = io.recvuntil(b'lets play: ')
size_secret = io.recvuntil(b'\n\n').decode().count(EMPTY)


dic = [word for word in dic_main if len(word) == size_secret]
log.info(f"Filtered words of len {size_secret} dict size is {len(dic)}")
io.recvuntil(b'> ').decode()

# used to keep track of wwhere we treid to put the contenders

subs = []
cont = []
rounds = 0
while DICT:
    subs, cont, black = attempt(subs, cont, size_secret)
    try:
        ans = io.recvuntil(b'> ').decode()
    except EOFError:
        log.failure("HP 0")
        sys.exit()

    if 'correct' in ans:
        
        log.success(f"\033[1mRound {rounds}, found without dict.\033[0m HP:{ans.count(HP)} - Solution:{''.join(subs)}")
        size_secret = ans.count(EMPTY)

        if rounds == 41:
            log.success(f"FLAG: {re.findall(flag_pattern, ans)[0]}")
            sys.exit()
        
        dic = [word for word in dic_main if len(word) == size_secret]
        DICT = NUMS + COMON + filtered_alphabet
        GLOB_CONT = {}
        for w in DICT:
            GLOB_CONT[w] = []
        subs = []
        cont = []
        rounds += 1

        continue


    # Remove blacklists from the dict and contenders
    DICT = [char for char in DICT if char not in black]
    DICT = [char for char in DICT if char not in cont]

    # Reffill DICT if it was empty (in case of duplicates)
    if not DICT:
        DICT = NUMS + COMON + filtered_alphabet


    dic = filter_rockyou(dic, subs, cont, black)
    if len(dic) < 15:

        with log.progress(f"\033[1mRound {rounds}.\033[0m Remaining words in dict: {len(dic)}. Attempting filtered bruteforce") as prog_fin:
            idx=0
            while True and dic:
                idx+=1

                subs = [c for c in dic.pop(0)]
                prog_fin.status(f"{idx}:{''.join(subs)}")
                subs, cont, black = attempt(subs, cont, size_secret)
                

                try:
                    check = io.recvuntil(b'> ').decode()
                except EOFError:
                    log.failure("HP 0")
                    sys.exit()

                if 'correct' in check:

                    prog_fin.success(f"Correct \033[1m{''.join(subs)}\033[0m at try no. {idx}. HP:{check.count(HP)}")
                    if rounds == 41:
                        log.success(f"FLAG: {re.findall(flag_pattern, check)[0]}")
                        sys.exit()
                        break
                    size_secret = check.count(EMPTY)
                    rounds +=1
                    break
                
                else:
                    dic = filter_rockyou(dic, subs, cont, black)


            dic = [word for word in dic_main if len(word) == size_secret]
            DICT = NUMS + COMON + filtered_alphabet
            GLOB_CONT = {}
            for w in DICT:
                GLOB_CONT[w] = []
            subs = []
            cont = []
