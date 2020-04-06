#!/usr/bin/env python3

import codecs, hashlib, os, sys # do not use any other imports/libraries
from pyasn1.codec.der import decoder

# took 7 hours (please specify here how much time your solution required)

def nb(i, length=False):
    # converts integer to bytes
    b = b''
    if length==False:
        length = (i.bit_length()+7)//8
    for _ in range(length):
        b = bytes([i & 0xff]) + b
        i >>= 8
    return b

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


def bn(b):
    # converts bytes to integer
    i = 0
    for char in b:
        i <<= 8
        i |= char
    return i

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

def pem_to_der(content):
    # converts PEM content to DER
    if  b'PRIVATE' in content:
        content = content[32:(len(content)-31)]
        content = codecs.decode(content, 'base64')
    elif b'PUBLIC' in content:
        content = content[27:(len(content)-26)]
        content = codecs.decode(content, 'base64')
    return content

def bitstring_to_byte(bitstr):
    # bitstr - string containing bitstring (e.g., "10101")
    # returns DER encoding of BITSTRING
    length = len(bitstr)

    # convert bitstring to integer
    i = 0
    for bit in bitstr:
        i <<= 1
        if bit == '1':
            i |= 1

    bitstr = nb(i, int(length / 8))
    return bitstr

def get_pubkey(filename):
    # reads public key file and returns (n, e)

    # decode the DER to get public key DER structure, which is encoded as BITSTRING
    file = open(filename, 'rb')
    content = file.read()
    file.close()

    content = pem_to_der(content)
    pubkey = str(decoder.decode(content)[0][1])

    # remove all unnecessary characters from pubkey string to get fromat '01100'
    pubkey = pubkey.replace(', ', '')
    pubkey = pubkey.replace(')', '')
    pubkey = pubkey.replace('(', '')

    # convert BITSTRING to bytestring
    pubkey = bitstring_to_byte(pubkey)

    # decode the bytestring (which is actually DER) and return (n, e)
    n = decoder.decode(pubkey)[0][0]
    e = decoder.decode(pubkey)[0][1]
    pubkey = [n,e]
    return int(pubkey[0]), int(pubkey[1])

def get_privkey(filename):
    # reads private key file and returns (n, d)
    file = open(filename, 'rb')
    content = file.read()
    file.close()

    content = pem_to_der(content)
    privkey = decoder.decode(content)
    return int(privkey[0][1]), int(privkey[0][3])

def pkcsv15pad_encrypt(plaintext, n):
    # pad plaintext for encryption according to PKCS#1 v1.5
    # calculate number of bytes required to represent the modulus n
    n_bytes_len = len(nb(n))

    # plaintext must be at least 11 bytes smaller than the modulus
    plaintext_len = len(plaintext)
    padding_size = n_bytes_len - plaintext_len

    # generate padding bytes
    padding = b''
    if padding_size >= 11:
        #add padding
        padding_size = padding_size - 3
        for a in range(padding_size):
            padding_byte = os.urandom(1)
            while padding_byte == bytes([0x00]):
                padding_byte = os.urandom(1)
            padding = padding + padding_byte
        padded_plaintext = bytes([0x00]) + bytes([0x02]) + padding + bytes([0x00]) + plaintext
    else:
        print('[-] Incorrect length of plaintext')
        sys.exit(1)

    return padded_plaintext

def pkcsv15pad_sign(plaintext, n):
    # pad plaintext for signing according to PKCS#1 v1.5
    # calculate byte length of modulus n
    n_bytes_len = len(nb(n))

    # plaintext must be at least 3 bytes smaller than modulus
    plaintext_len = len(plaintext)
    padding_size = n_bytes_len - plaintext_len

    # generate padding bytes
    padding = b''
    if padding_size >= 3:
        #add padding
        padding_size = padding_size - 3
        padding = bytes([0xFF])*padding_size
        padded_plaintext = bytes([0x00]) + bytes([0x01]) + padding + bytes([0x00]) + plaintext
    else:
        print('[-] Incorrect length of plaintext')
        sys.exit(1)

    return padded_plaintext

def pkcsv15pad_remove(plaintext):
    # removes PKCS#1 v1.5 padding
    plaintext = plaintext[1:] # cut out the first padding byte
    index = plaintext.find(bytes([0x00])) # find the place where 0x00 appears, that place will be the end of padding
    plaintext = plaintext[(index+1):]
    return plaintext

def encrypt(keyfile, plaintextfile, ciphertextfile):
    key = get_pubkey(keyfile)
    n = key[0]
    e = key[1]

    file = open(plaintextfile, 'rb')
    plaintext = file.read()
    file.close()
    plaintext = pkcsv15pad_encrypt(plaintext, n)
    m = bn(plaintext)

    c = pow(m, e, n)
    ciphertext = nb(c)

    file = open(ciphertextfile, 'wb')
    file.write(ciphertext)
    file.close()
    pass

def decrypt(keyfile, ciphertextfile, plaintextfile):
    key = get_privkey(keyfile)
    n = key[0]
    d = key[1]

    file = open(ciphertextfile, 'rb')
    ciphertext = file.read()
    file.close()
    c = bn(ciphertext)

    m = pow(c, d, n)
    plaintext = nb(m)
    plaintext = pkcsv15pad_remove(plaintext)

    file = open(plaintextfile, 'wb')
    file.write(plaintext)
    file.close()

    pass

def digestinfo_der(filename):
    # returns ASN.1 DER encoded DigestInfo structure containing SHA256 digest of file
    hash = hashlib.sha256()

    chunksize = 512
    file = open(filename, 'rb')
    while True:
        chunk = file.read(chunksize)
        if not chunk:
            break
        hash.update(chunk)
    file.close()

    digest = hash.digest()

    der = asn1_sequence((asn1_sequence(asn1_objectidentifier([2,16,840,1,101,3,4,2,1])
                                        + asn1_null())
                                        + asn1_octetstring(digest)))
    return der

def sign(keyfile, filetosign, signaturefile):
    key = get_privkey(keyfile)
    n = key[0]
    d = key[1]

    der = digestinfo_der(filetosign)
    msg_to_sign = pkcsv15pad_sign(der, n)
    msg_to_sign = bn(msg_to_sign)

    signature = pow(msg_to_sign, d, n)
    modulus_len = len(nb(n))
    signature = nb(signature, modulus_len)

    file = open(signaturefile, 'wb')
    file.write(signature)
    file.close()

    pass
    # Warning: make sure that signaturefile produced has the same
    # length as the modulus (hint: use parametrized nb()).

def verify(keyfile, signaturefile, filetoverify):
    # prints "Verified OK" or "Verification failure"
    key = get_pubkey(keyfile)
    n = key[0]
    e = key[1]

    file = open(signaturefile, 'rb')
    signature =  file.read()
    file.close()
    signature = bn(signature)

    digest_info = pow(signature, e, n)
    digest_info = nb(digest_info)
    digest_info = pkcsv15pad_remove(digest_info)

    actual_digest_info = digestinfo_der(filetoverify)

    if digest_info == actual_digest_info:
        print('[+] Verified OK')
    else:
        print('[-] Verification failure')

    pass

def usage():
    print("Usage:")
    print("encrypt <public key file> <plaintext file> <output ciphertext file>")
    print("decrypt <private key file> <ciphertext file> <output plaintext file>")
    print("sign <private key file> <file to sign> <signature output file>")
    print("verify <public key file> <signature file> <file to verify>")
    sys.exit(1)

if len(sys.argv) != 5:
    usage()
elif sys.argv[1] == 'encrypt':
    encrypt(sys.argv[2], sys.argv[3], sys.argv[4])
elif sys.argv[1] == 'decrypt':
    decrypt(sys.argv[2], sys.argv[3], sys.argv[4])
elif sys.argv[1] == 'sign':
    sign(sys.argv[2], sys.argv[3], sys.argv[4])
elif sys.argv[1] == 'verify':
    verify(sys.argv[2], sys.argv[3], sys.argv[4])
else:
    usage()
