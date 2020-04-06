#!/usr/bin/env python3

import argparse, codecs, hashlib, os, sys # do not use any other imports/libraries
from pyasn1.codec.der import decoder, encoder

# took 8 hours (please specify here how much time your solution required)


# parse arguments
parser = argparse.ArgumentParser(description='issue TLS server certificate based on CSR', add_help=False)
parser.add_argument("private_key_file", help="Private key file (in PEM or DER form)")
parser.add_argument("CA_cert_file", help="CA certificate (in PEM or DER form)")
parser.add_argument("csr_file", help="CSR file (in PEM or DER form)")
parser.add_argument("output_cert_file", help="File to store certificate (in PEM form)")
args = parser.parse_args()

def nb(i, length=False):
    # converts integer to bytes
    b = b''
    if length==False:
        length = (i.bit_length()+7)//8
    for _ in range(length):
        b = bytes([i & 0xff]) + b
        i >>= 8
    return b

def bn(b):
    # converts bytes to integer
    i = 0
    for char in b:
        i <<= 8
        i |= char
    return i

#==== ASN1 encoder start ====
# put your DER encoder functions here
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

def asn1_boolean(bool):
    # BOOLEAN encoder has been implemented for you
    if bool:
        bool = b'\xff'
    else:
        bool = b'\x00'
    return bytes([0x01]) + asn1_len(bool) + bool

def asn1_null():
    # returns DER encoding of NULL
    return bytes([0x05]) + bytes([0x00])

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

def asn1_bitstring(bitstr):
    # bitstr - string containing bitstring (e.g., "10101")
    # returns DER encoding of BITSTRING
    length = len(bitstr)

    if length == 0:
        return bytes([0x03]) + bytes([0x01]) + bytes([0x00])

    # add padding to bitstring
    padding_len = (8 - (length % 8)) % 8
    bitstr = bitstr + '0' * padding_len

    # convert padded bitstring to integer
    i = 0
    for bit in bitstr:
        i <<= 1
        if bit == '1':
            i |= 1

    bitstr = bytes([padding_len]) + nb(i, int(len(bitstr) / 8))
    return bytes([0x03]) + asn1_len(bitstr) + bitstr

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

def asn1_set(der):
    # der - DER bytes to encapsulate into set
    # returns DER encoding of SET
    return bytes([0x31]) + asn1_len(der) + der

def asn1_printablestring(string):
    # string - bytes containing printable characters (e.g., b"foo")
    # returns DER encoding of PrintableString
    return bytes([0x13]) + asn1_len(string) + string

def asn1_utctime(time):
    # time - bytes containing timestamp in UTCTime format (e.g., b"121229010100Z")
    # returns DER encoding of UTCTime
    return bytes([0x17]) + asn1_len(time) + time

def asn1_tag_explicit(der, tag):
    # der - DER encoded bytestring
    # tag - tag value to specify in the type octet
    # returns DER encoding of original DER that is encapsulated in tag type
    # 10100000 is a0 in hex (context-defined, constructed + 00000)
    return bytes([0xa0 | tag]) + asn1_len(der) + der

def asn1_bitstring_der(bytestr):
    bytestr = bytes([0x00]) + bytestr
    return bytes([0x03]) + asn1_len(bytestr) + bytestr


#==== ASN1 encoder end ====

def pem_to_der(content):
    # converts PEM content (if it is PEM) to DER
    if content.startswith(b'-----'):
        content = content.replace(b'-----BEGIN PRIVATE KEY-----', b'')
        content = content.replace(b'-----END PRIVATE KEY-----', b'')
        content = content.replace(b'-----BEGIN RSA PRIVATE KEY-----', b'')
        content = content.replace(b'-----END RSA PRIVATE KEY-----', b'')
        content = content.replace(b'-----BEGIN CERTIFICATE REQUEST-----', b'')
        content = content.replace(b'-----END CERTIFICATE REQUEST-----', b'')
        content = content.replace(b'-----BEGIN CERTIFICATE-----', b'')
        content = content.replace(b'-----END CERTIFICATE-----', b'')
        content = codecs.decode(content, 'base64')
    return content

def get_privkey(filename):
    # reads private key file and returns (n, d)
    file = open(filename, 'rb')
    content = file.read()
    file.close()

    content = pem_to_der(content)
    privkey = decoder.decode(content)
    return int(privkey[0][1]), int(privkey[0][3])

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

def digestinfo_der(m):
    # returns ASN.1 DER encoded DigestInfo structure containing SHA256 digest of m
    hash = hashlib.sha256()
    hash.update(m)
    digest = hash.digest()

    der = asn1_sequence((asn1_sequence(asn1_objectidentifier([2,16,840,1,101,3,4,2,1])
                                        + asn1_null())
                                        + asn1_octetstring(digest)))
    return der

def sign(m, keyfile):
    # sign DigestInfo of message m
    key = get_privkey(keyfile)
    n = key[0]
    d = key[1]

    der = digestinfo_der(m)
    msg_to_sign = pkcsv15pad_sign(der, n)
    msg_to_sign = bn(msg_to_sign)

    signature = pow(msg_to_sign, d, n)
    modulus_len = len(nb(n))
    signature = nb(signature, modulus_len)

    return signature


def get_subject_cn(csr_der):
    # return CommonName value from CSR's Distinguished Name
    x = 0
    while True:
        content = str(decoder.decode(csr_der)[0][0][1][x][0][0])
        if content == '2.5.4.3':
            break
        x += 1
    subject_cn = str(decoder.decode(csr_der)[0][0][1][x][0][1])
    # looping over Distinguished Name entries until CN found
    return subject_cn

def get_subjectPublicKeyInfo(csr_der):
    # returns DER encoded subjectPublicKeyInfo from CSR
    return  encoder.encode(decoder.decode(csr_der)[0][0][2])

def get_subjectName(cert_der):
    # return subject name DER from CA certificate
    return encoder.encode(decoder.decode(cert_der)[0][0][5])

def issue_certificate(private_key_file, issuer, subject, pubkey):
    # receives CA private key filename, DER encoded CA Distinguished Name,
    # constructed DER encoded subject's Distinguished Name, DER encoded subjectPublicKeyInfo

    # returns X.509v3 certificate in PEM format
    validity = asn1_sequence(asn1_utctime(b'200318000000Z') + asn1_utctime(b'200618000000Z'))
    basic_constraints = asn1_sequence(asn1_objectidentifier([2,5,29,19])
                                        + asn1_boolean(True)
                                        + asn1_octetstring(asn1_sequence(asn1_boolean(False))))

    key_usege = asn1_sequence(asn1_objectidentifier([2,5,29,15])
                                + asn1_boolean(True)
                                + asn1_octetstring(asn1_bitstring('100000000')))

    extended_key_usege = asn1_sequence(asn1_objectidentifier([2,5,29,37])
                                        + asn1_boolean(True)
                                        + asn1_octetstring(asn1_sequence(
                                                            asn1_objectidentifier([1,3,6,1,5,5,7,3,1]))))

    extensions = asn1_sequence(basic_constraints + key_usege + extended_key_usege)
    tbs_certificate_der = asn1_sequence(asn1_tag_explicit(asn1_integer(2), 0)
                                        + asn1_integer(1234567890)
                                        + asn1_sequence(asn1_objectidentifier([1,2,840,113549,1,1,11]) + asn1_null())
                                        + issuer
                                        + validity
                                        + subject
                                        + pubkey
                                        + asn1_tag_explicit(extensions, 3))

    signature = sign(tbs_certificate_der, private_key_file)

    der = asn1_sequence(tbs_certificate_der
                        + asn1_sequence(asn1_objectidentifier([1,2,840,113549,1,1,11]) + asn1_null())
                        + asn1_bitstring_der(signature))

    encoded_der = codecs.encode(der, 'base64')
    header = b'-----BEGIN CERTIFICATE-----\n'
    footer = b'-----END CERTIFICATE-----'
    pem = header + encoded_der + footer
    return pem

# obtain subject's CN from CSR
csr_der = pem_to_der(open(args.csr_file, 'rb').read())
subject_cn_text = get_subject_cn(csr_der)

print("[+] Issuing certificate for \"%s\"" % (subject_cn_text))

# obtain subjectPublicKeyInfo from CSR
pubkey = get_subjectPublicKeyInfo(csr_der)

# construct subject name DN
subject = encoder.encode(decoder.decode(csr_der)[0][0][1])
subject_cn_bytes = bytes(subject_cn_text, 'utf-8')
subject = asn1_sequence(asn1_set(asn1_sequence(asn1_objectidentifier([2,5,4,3]) + asn1_printablestring(subject_cn_bytes))))

# get subject name DN from CA certificate
CAcert = pem_to_der(open(args.CA_cert_file, 'rb').read())
CAsubject = get_subjectName(CAcert)

# issue certificate
cert_pem = issue_certificate(args.private_key_file, CAsubject, subject, pubkey)
open(args.output_cert_file, 'wb').write(cert_pem)
