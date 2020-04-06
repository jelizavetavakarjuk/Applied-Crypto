#!/usr/bin/env python3
import os, sys       # do not use any other imports/libraries
# took 5.5 hours (please specify here how much time your solution required)

def bn(b):
    # b - bytes to encode as integer
    # your implementation here
    i = 0
    for byte in b:
        i = i << 8
        i = i | byte
    return i

def nb(i, length):
    # i - integer to encode as bytes
    # length - specifies in how many bytes the number should be encoded
    # your implementation here
    b = b''
    for _ in range(length):
        y = i & 255
        i = i >> 8
        b = bytes([y]) + b
    return b

def encrypt(pfile, kfile, cfile):
    # your implementation here
    b = open(pfile, 'rb').read()
    length = len(b)

    k = os.urandom(length)
    key_file = open(kfile, 'wb')
    key_file.write(k)
    key_file.close()

    b = bn(b)
    k = bn(k)
    c = b ^ k

    c = nb(c, length)

    file = open(cfile, 'wb')
    file.write(c)
    file.close()
    pass

def decrypt(cfile, kfile, pfile):
    # your implementation here
    c = open(cfile, 'rb').read()
    length = len(c)
    k = open(kfile, 'rb').read()

    c = bn(c)
    k = bn(k)
    p = c ^ k

    p = nb(p, length)

    file = open(pfile, 'wb')
    file.write(p)
    file.close()
    pass

def usage():
    print("Usage:")
    print("encrypt <plaintext file> <output key file> <ciphertext output file>")
    print("decrypt <ciphertext file> <key file> <plaintext output file>")
    sys.exit(1)

if len(sys.argv) != 5:
    usage()
elif sys.argv[1] == 'encrypt':
    encrypt(sys.argv[2], sys.argv[3], sys.argv[4])
elif sys.argv[1] == 'decrypt':
    decrypt(sys.argv[2], sys.argv[3], sys.argv[4])
else:
    usage()
