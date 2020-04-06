#!/usr/bin/python3

import datetime, os, sys, codecs
from pyasn1.codec.der import decoder

# $ sudo apt-get install python3-crypto
sys.path = sys.path[1:] # removes script directory from aes.py search path
from Crypto.Cipher import AES          # https://www.dlitz.net/software/pycrypto/api/current/Crypto.Cipher.AES-module.html
from Crypto.Util.strxor import strxor  # https://www.dlitz.net/software/pycrypto/api/current/Crypto.Util.strxor-module.html#strxor
from hashlib import pbkdf2_hmac
import hashlib, hmac # do not use any other imports/libraries

# took 9 hours (please specify here how much time your solution required)

# ASN1 encoder
def nb(i):
    # i - integer to encode as string of bytes
    # length - specifies in how many bytes the number should be encoded
    # your implementation here
    b = b''
    if i == 0:
        return b'\x00'

    while i > 0:
        b = bytes([i & 255]) + b
        i = i >> 8
    return b

def bn(b):
    # b - bytes to encode as integer
    # your implementation here
    i = 0
    for byte in b:
        i = i << 8
        i = i | byte
    return i

def nb_oid(i):
    # i - integer to encode as string of bytes
    # length - specifies in how many bytes the number should be encoded
    # your implementation here
    b = b''
    if i == 0:
        return b'\x00'

    while i > 0:
        b = bytes([i & 127]) + b
        i = i >> 7
    return b

def asn1_len(value_bytes):
    # helper function - should be used in other functions to calculate length octet(s)
    # value_bytes - bytes containing TLV value byte(s)
    # returns length (L) byte(s) for TLV
    L = 0
    if len(value_bytes) < 128:
       L = bytes([len(value_bytes)])
       return L

    L = nb(len(value_bytes))
    L = len(L)
    L = bytes([L | 128]) + nb(len(value_bytes))
    return L

def asn1_null():
    # returns DER encoding of NULL
    return bytes([0x05]) + bytes([0x00])

def asn1_octetstring(octets):
    # octets - arbitrary byte string (e.g., b"abc\x01")
    # returns DER encoding of OCTETSTRING
    return bytes([0x04]) + asn1_len(octets) + octets

def asn1_integer(i):
    # i - arbitrary integer (of type 'int' or 'long')
    # returns DER encoding of INTEGER
    integer = i
    i = nb(i)
    shift_length = (8 * len(i)) - 1
    # get most significant bit of the most significant byte
    integer = integer >> shift_length
    if integer == 1:
        i = bytes([0x00]) + i
    else:
        i = i
    return bytes([0x02]) + asn1_len(i) + i

def asn1_objectidentifier(oid):
    # oid - list of integers representing OID (e.g., [1,2,840,123123])
    # returns DER encoding of OBJECTIDENTIFIER
    length = len(oid)
    first_byte = bytes([40 * oid[0] + oid[1]])

    if length > 2:
        other_bytes = b''
        for x in range(2, length):
            if oid[x] > 127:
                bytestr = nb_oid(oid[x])
                for i in range(len(bytestr) - 1):
                    number = bytestr[i] | 128
                    other_bytes = other_bytes + nb(number)
                other_bytes = other_bytes + bytes([bytestr[len(bytestr) - 1]])
            else:
                other_bytes += nb(oid[x])
        oid = first_byte + other_bytes
    else:
        oid = first_byte
    return bytes([0x06]) + asn1_len(oid) + oid

def asn1_sequence(der):
    # der - DER bytes to encapsulate into sequence
    # returns DER encoding of SEQUENCE
    return bytes([0x30]) + asn1_len(der) + der

def calculate_hmac(filename, hash_alg, key):
    hmac_new = hmac.new(key, None, hash_alg)

    chunksize = 512
    file = open(filename, 'rb')
    while True:
        chunk = file.read(chunksize)
        if not chunk:
            break
        hmac_new.update(chunk)
    file.close()

    return hmac_new

def mac(filename, key):
    algorithm_id = [1,3,14,3,2,26]

    hmac_new = calculate_hmac(filename, hashlib.sha1, key)
    digest = hmac_new.digest()

    asn1_digest = asn1_sequence(
        asn1_sequence(asn1_objectidentifier(algorithm_id) + asn1_null())
        + asn1_octetstring(digest))

    return asn1_digest


# this function benchmarks how many PBKDF2 iterations
# can be performed in one second on the machine it is executed
def benchmark():

    # measure time for performing 10000 iterations
    iter = 10000
    salt = os.urandom(8)
    password = os.urandom(10)
    start = datetime.datetime.now()
    key = pbkdf2_hmac('sha1', password, salt, iter, 36)
    stop = datetime.datetime.now()
    time = (stop - start).total_seconds()

    # extrapolate to 1 second
    iter = int(iter / time)
    print("[+] Benchmark: %s PBKDF2 iterations in 1 second" % (iter))

    return iter # returns number of iterations that can be performed in 1 second

def AES_encrypt(pfile, aes_key, IV_current, cfile):
    temp_file = open(cfile+'.tmp', 'ab')

    cipher = AES.new(aes_key)

    chunk_size = 16
    file = open(pfile, 'rb')
    ciphertext = b''
    padding_size = 0
    while True:
        plaintext = file.read(chunk_size)
        if not plaintext:
            break
        chunk_length = len(plaintext)
        padding_size = 16 - chunk_length
        if padding_size > 0:
            plaintext = plaintext + bytes([padding_size]) * padding_size
        ciphertext = cipher.encrypt(strxor(plaintext, IV_current))
        temp_file.write(ciphertext)
        IV_current = ciphertext

    if padding_size == 0:
        padding_block = bytes([16]) * 16
        ciphertext = cipher.encrypt(strxor(padding_block, IV_current))
        temp_file.write(ciphertext)

    file.close()
    temp_file.close()

def encrypt(pfile, cfile):
    # benchmarking
    iter = benchmark()

    # asking for password
    password = input("[?] Enter password: ").encode()

    # derieving key
    salt = os.urandom(8)
    IV = os.urandom(16)

    key = pbkdf2_hmac('sha1', password, salt, iter, 36)

    aes_key = key[0:16]
    hmac_key = key[16:36]

    # encrypting and writing ciphertext in temporary file
    AES_encrypt(pfile, aes_key, IV, cfile)

    # calculating HMAC digest, result is der encoded
    asn1_digest = mac(cfile+'.tmp', hmac_key)

    # writing DER structure in cfile
    asn1_encinfo = asn1_sequence(asn1_sequence(asn1_octetstring(salt) + asn1_integer(iter)
                                            + asn1_integer(36))
                            + asn1_sequence(asn1_objectidentifier([2,16,840,1,101,3,4,1,2])
                                            + asn1_octetstring(IV))
                            + asn1_digest)

    cipher_file = open(cfile, 'wb')
    cipher_file.write(asn1_encinfo)
    cipher_file.close()

    # writing temporary ciphertext file to cfile
    temp_file = open(cfile+'.tmp', 'rb')
    chunk_size = 512
    cipher_file = open(cfile, 'ab')
    while True:
        cipher_block = temp_file.read(chunk_size)
        if not cipher_block:
            break
        cipher_file.write(cipher_block)
    cipher_file.close()
    temp_file.close()

    # deleting temporary ciphertext file
    os.unlink(cfile+'.tmp')

    pass

def calc_header_length(cfile):
    length_info = open(cfile, 'rb').read(10)
    # additional bytes to the length of sequence itself: byte that shows type
    # and bytes that show the length
    info_bytes = 2
    length_byte = length_info[1] # take second byte as first was type
    msb =  length_byte >> 7
    if msb == 0:
        # the length value is stored in one byte (length_byte)
        header_length = length_byte + info_bytes
    # for longer values
    else:
        # to calculate how many length bytes follow
        length_bytes = length_byte ^ 128
        info_bytes = info_bytes + length_bytes
        # calculate actual length of sequence
        length_value = length_info[2:(2+length_bytes)]
        header_length = bn(length_value) + info_bytes

    return header_length

def AES_decrypt(cfile, aes_key, IV_current, pfile):
    plain_file = open(pfile, 'ab')
    cipher = AES.new(aes_key)

    chunk_size = 16
    length_counter = 0
    file = open(cfile+'.tmp', 'rb')
    plaintext = b''
    while True:
        ciphertext = file.read(chunk_size)
        if not ciphertext:
            break
        plaintext = strxor(cipher.decrypt(ciphertext), IV_current)
        plain_file.write(plaintext)
        IV_current = ciphertext
        length_counter += 1

    plain_file.close()
    plaintext_length = 16*length_counter
    # remove the last block in oredr to rewrite it without the padding
    os.truncate(pfile, plaintext_length-16)

    plain_file = open(pfile, 'ab')
    ls_byte = plaintext[15]
    # remove padding
    plaintext = plaintext[0:(16-ls_byte)]
    plain_file.write(plaintext)
    plain_file.close()

def decrypt(cfile, pfile):
    # reading DER structure
    # finding out the length of header
    header_length = calc_header_length(cfile)

    # reading ciphertext from the file by 16 byte chunks
    temp_file = open(cfile+'.tmp', 'ab')
    ciphertext = open(cfile, 'rb')
    ciphertext.seek(header_length)
    while True:
        cipher_block = ciphertext.read(16)
        if not cipher_block:
            break
        temp_file.write(cipher_block)

    temp_file.close()
    ciphertext.close()

    der = open(cfile, 'rb').read(header_length)
    salt = bytes(decoder.decode(der)[0][0][0])
    iter = int(decoder.decode(der)[0][0][1])
    IV_current = bytes(decoder.decode(der)[0][1][1])
    digest = bytes(decoder.decode(der)[0][2][1])
    # to return digest value in hexadecimal format
    digest = codecs.encode(digest, 'hex').decode()

    # asking for password
    password = input("[?] Enter password: ").encode()

    # derieving key
    key = pbkdf2_hmac('sha1', password, salt, iter, 36)
    aes_key = key[0:16]
    hmac_key = key[16:36]

    # first pass over ciphertext to calculate and verify HMAC
    hmac_new = calculate_hmac(cfile+'.tmp', hashlib.sha1, hmac_key)
    calculated_digest = hmac_new.hexdigest()

    if calculated_digest == digest:
        # second pass over ciphertext to decrypt
        AES_decrypt(cfile, aes_key, IV_current, pfile)

    else:
        print('[-] HMAC verification failure: wrong password or modified ciphertext!')

    os.unlink(cfile+'.tmp')

    pass

def usage():
    print("Usage:")
    print("-encrypt <plaintextfile> <ciphertextfile>")
    print("-decrypt <ciphertextfile> <plaintextfile>")
    sys.exit(1)


if len(sys.argv) != 4:
    usage()
elif sys.argv[1] == '-encrypt':
    encrypt(sys.argv[2], sys.argv[3])
elif sys.argv[1] == '-decrypt':
    decrypt(sys.argv[2], sys.argv[3])
else:
    usage()
