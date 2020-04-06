#!/usr/bin/env python
import sys   # do not use any other imports/libraries

# took 16 hours (please specify here how much time your solution required)

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

def nb_len(i, length):
    # i - integer to encode as bytes
    # length - specifies in how many bytes the number should be encoded
    # your implementation here
    b = b''
    for _ in range(length):
        y = i & 255
        i = i >> 8
        b = bytes([y]) + b
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

    bitstr = bytes([padding_len]) + nb_len(i, int(len(bitstr) / 8))
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

# figure out what to put in '...' by looking on ASN.1 structure required (see slides)
asn1 = asn1_tag_explicit(asn1_sequence(asn1_set(asn1_integer(5) + asn1_tag_explicit(asn1_integer(200), 2) + asn1_tag_explicit(asn1_integer(65407), 11))
                                       + asn1_boolean(True)
                                       + asn1_bitstring("110")
                                       + asn1_octetstring(b"\x00\x01" + b"\x02" * 49)
                                       + asn1_null()
                                       + asn1_objectidentifier([1, 2, 840, 113549, 1])
                                       + asn1_printablestring(b"hello.")
                                       + asn1_utctime(b"150223010900Z")), 0)

open(sys.argv[1], 'wb').write(asn1)
