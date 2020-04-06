#!/usr/bin/python3

import codecs, hashlib, sys
from pyasn1.codec.der import decoder
sys.path = sys.path[1:] # don't remove! otherwise the library import below will try to import your hmac.py
import hmac # do not use any other imports/libraries

# took 8 hours (please specify here how much time your solution required)

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


def calculate_hmac(filename, hash_alg):
    key = input("[?] Enter key: ").encode()

    hmac_new = hmac.new(key, None, hash_alg)

    chunksize = 512
    file = open(filename, 'rb')
    while True:
        chunk = file.read(chunksize)
        # feed chunks sequentially
        hmac_new.update(chunk)
        if not chunk:
            break
    file.close()

    return hmac_new

def verify(filename):
    print("[+] Reading HMAC DigestInfo from", filename+".hmac")

    der = open(filename+'.hmac', 'rb').read()
    oid = str(decoder.decode(der)[0][0][0])
    digest = bytes(decoder.decode(der)[0][1])
    # to return digest value in hexadecimal format
    digest = codecs.encode(digest, 'hex').decode()


    if oid == "1.2.840.113549.2.5":
        print("[+] HMAC-MD5 digest: ", digest)
        hmac_new = calculate_hmac(filename, hashlib.md5)
        digest_calculated  = hmac_new.hexdigest()
        print("[+] Calculated HMAC-MD5: ", digest_calculated)
    elif oid == "1.3.14.3.2.26":
        print("[+] HMAC-SHA1 digest: ", digest)
        hmac_new = calculate_hmac(filename, hashlib.sha1)
        digest_calculated  = hmac_new.hexdigest()
        print("[+] Calculated HMAC-SHA1: ", digest_calculated)
    elif oid == "2.16.840.1.101.3.4.2.1":
        print("[+] HMAC-SHA256 digest: ", digest)
        hmac_new = calculate_hmac(filename, hashlib.sha256)
        digest_calculated  = hmac_new.hexdigest()
        print("[+] Calculated HMAC-SHA256: ", digest_calculated)

    if digest_calculated != digest:
        print("[-] Wrong key or message has been manipulated!")
    else:
        print("[+] HMAC verification successful!")


def mac(filename):
    algorithm_id = [2,16,840,1,101,3,4,2,1]

    hmac_new = calculate_hmac(filename, hashlib.sha256)
    digest = hmac_new.digest()

    asn1_digest = asn1_sequence(
        asn1_sequence(asn1_objectidentifier(algorithm_id) + asn1_null())
        + asn1_octetstring(digest))

    print("[+] Calculated HMAC-SHA256:", hmac_new.hexdigest())

    print("[+] Writing HMAC DigestInfo to", filename+".hmac")

    open(filename+'.hmac', 'wb').write(asn1_digest)


def usage():
    print("Usage:")
    print("-verify <filename>")
    print("-mac <filename>")
    sys.exit(1)

if len(sys.argv) != 3:
    usage()
elif sys.argv[1] == '-mac':
    mac(sys.argv[2])
elif sys.argv[1] == '-verify':
    verify(sys.argv[2])
else:
    usage()
