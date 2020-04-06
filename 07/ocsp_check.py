#!/usr/bin/env python3

import codecs, datetime, hashlib, re, sys, socket # do not use any other imports/libraries
from urllib.parse import urlparse
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import namedtype, univ

# sudo apt install python3-pyasn1-modules
from pyasn1_modules import rfc2560, rfc5280

# took 10 hours (please specify here how much time your solution required)

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
    # converts PEM encoded X.509 certificate (if it is PEM) to DER
    if content.startswith(b'-----'):
        content = content.replace(b'-----BEGIN CERTIFICATE-----', b'')
        content = content.replace(b'-----END CERTIFICATE-----', b'')
        content = codecs.decode(content, 'base64')
    return content

def get_name(cert):
    # get subject DN from certificate
    name = encoder.encode(decoder.decode(cert)[0][0][5])
    return name

def get_key(cert):
     # get subjectPublicKey from certificate
     # SubjectPublicKeyInfo->subjectPublicKey
    subjectPublicKey = encoder.encode(decoder.decode(cert)[0][0][6][1])
    return subjectPublicKey

def get_serial(cert):
    # get serial from certificate
    serial = int(decoder.decode(cert)[0][0][1])
    return serial

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

def produce_request(cert, issuer_cert):
    # make OCSP request in ASN.1 DER form
    issuer_dn = get_name(issuer_cert)
    hash = hashlib.sha1()
    hash.update(issuer_dn)
    digest = hash.digest()
    issuerNameHash = asn1_octetstring(digest)

    # hash of subjectPublicKey BIT STRING content (not whole der structure)
    # get signature bitstring
    issuer_key = str(decoder.decode(issuer_cert)[0][0][6][1])
    # convert bitstring to bytestring to feed into hash alg
    issuer_key = bitstring_to_byte(issuer_key)
    hash2 = hashlib.sha1()
    hash2.update(issuer_key)
    digest2 = hash2.digest()
    issuerKeyHash = asn1_octetstring(digest2)

    algorithmID = asn1_sequence(asn1_objectidentifier([1,3,14,3,2,26]) + asn1_null())
    serialNumber = asn1_integer(get_serial(cert))
    certID = asn1_sequence(algorithmID + issuerNameHash + issuerKeyHash + serialNumber)

    print("[+] Querying OCSP for serial:", get_serial(cert))

    # construct entire OCSP request
    request = asn1_sequence(certID)
    requestList = asn1_sequence(request)
    tbsRequest = asn1_sequence(asn1_tag_explicit(asn1_integer(2), 0)
                                + requestList)

    OCSPRequest = asn1_sequence(tbsRequest)

    return OCSPRequest

def send_req(ocsp_req, ocsp_url):
    # send OCSP request to OCSP responder

    # parse ocsp responder url
    host = urlparse(ocsp_url).netloc
    path = urlparse(ocsp_url).path

    print("[+] Connecting to %s..." % (host))
    # connect to host
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, 80))

    # send HTTP POST request
    line_1 = b'POST ' + bytes(path, 'utf-8') + b' HTTP/1.1\r\n'
    line_2 = b'Host: ' + bytes(host, 'utf-8') + b'\r\n'
    line_3 = b'Content-Type: application/ocsp-request\r\n'
    # convert length value to string and then to bytes
    line_4 = b'Content-Length: ' + bytes(str(len(ocsp_req)), 'utf-8') + b'\r\n'
    line_5 = b'Connection: close'
    post_request = line_1 + line_2 + line_3 + line_4 + line_5 + b'\r\n\r\n' + ocsp_req

    s.send(post_request)

    # read HTTP response header
    header = b''
    while True:
        info = s.recv(1)
        if info == b'':
            print('Connection is broken')
            sys.exit(1)
        header += info
        if header[-4:] == b'\r\n\r\n':
            break
    # get HTTP response length
    length = int(re.search('content-length:\s*(\d+)\s', header.decode(), re.S+re.I).group(1))

    # read HTTP response body
    ocsp_resp = b''
    for _ in range(length):
        body = s.recv(1)
        # check if connection is broken
        if body == b'':
            print('Connection is broken')
            sys.exit(1)
        ocsp_resp += body

    return ocsp_resp

def get_ocsp_url(cert):
    # get OCSP url from certificate's AIA extension

    # pyasn1 syntax description to decode AIA extension
    class AccessDescription(univ.Sequence):
      componentType = namedtype.NamedTypes(
        namedtype.NamedType('accessMethod', univ.ObjectIdentifier()),
        namedtype.NamedType('accessLocation', rfc5280.GeneralName()))

    class AuthorityInfoAccessSyntax(univ.SequenceOf):
      componentType = AccessDescription()

    # looping over certificate extensions
    for seq in decoder.decode(cert)[0][0][7]:
        if str(seq[0])=='1.3.6.1.5.5.7.1.1': # look for AIA extension
            ext_value = bytes(seq[1])
            for aia in decoder.decode(ext_value, asn1Spec=AuthorityInfoAccessSyntax())[0]:
                if str(aia[0])=='1.3.6.1.5.5.7.48.1': # ocsp url
                    return str(aia[1].getComponentByName('uniformResourceIdentifier'))

    print("[-] OCSP url not found in certificate!")
    exit(1)

def get_issuer_cert_url(cert):
    # get CA certificate url from certificate's AIA extension (hint: see get_ocsp_url())
    # pyasn1 syntax description to decode AIA extension
    class AccessDescription(univ.Sequence):
      componentType = namedtype.NamedTypes(
        namedtype.NamedType('accessMethod', univ.ObjectIdentifier()),
        namedtype.NamedType('accessLocation', rfc5280.GeneralName()))

    class AuthorityInfoAccessSyntax(univ.SequenceOf):
      componentType = AccessDescription()

    for seq in decoder.decode(cert)[0][0][7]:
        if str(seq[0])=='1.3.6.1.5.5.7.1.1': # look for AIA extension
            ext_value = bytes(seq[1])
            for aia in decoder.decode(ext_value, asn1Spec=AuthorityInfoAccessSyntax())[0]:
                if str(aia[0])=='1.3.6.1.5.5.7.48.2': # caIssuers
                    return str(aia[1].getComponentByName('uniformResourceIdentifier'))

    print("[-] caIssuers url not found in certificate!")
    exit(1)
    pass

def download_issuer_cert(issuer_cert_url):
    print("[+] Downloading issuer certificate from:", issuer_cert_url)

    # parse ocsp responder url
    url = urlparse(issuer_cert_url)
    # connect to host
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((url.netloc, 80))

    # sent HTTP GET request
    get_request = b'GET ' + bytes(url.path, 'utf-8') + b' HTTP/1.1\r\n' + b'Host: ' + bytes(url.netloc, 'utf-8') + b'\r\n' + b'Connection: close' + b'\r\n\r\n'

    s.send(get_request)

    # read HTTP response header
    header = b''
    while True:
        info = s.recv(1)
        if info == b'':
            print('Connection is broken')
            sys.exit(1)
        header += info
        if header[-4:] == b'\r\n\r\n':
            break

    # get HTTP response length
    length = int(re.search('content-length:\s*(\d+)\s', header.decode(), re.S+re.I).group(1))

    # read HTTP response body
    issuer_cert = b''
    for _ in range(length):
        body = s.recv(1)
        # check if connection is broken
        if body == b'':
            print('Connection is broken')
            sys.exit(1)
        issuer_cert += body

    return issuer_cert

# parses OCSP response
def parse_ocsp_resp(ocsp_resp):
    ocspResponse, _ = decoder.decode(ocsp_resp, asn1Spec=rfc2560.OCSPResponse())
    responseStatus = ocspResponse.getComponentByName('responseStatus')
    assert responseStatus == rfc2560.OCSPResponseStatus('successful'), responseStatus.prettyPrint()
    responseBytes = ocspResponse.getComponentByName('responseBytes')
    responseType = responseBytes.getComponentByName('responseType')
    assert responseType == rfc2560.id_pkix_ocsp_basic, responseType.prettyPrint()

    response = responseBytes.getComponentByName('response')

    basicOCSPResponse, _ = decoder.decode(
        response, asn1Spec=rfc2560.BasicOCSPResponse()
    )

    tbsResponseData = basicOCSPResponse.getComponentByName('tbsResponseData')

    response0 = tbsResponseData.getComponentByName('responses').getComponentByPosition(0)

    producedAt = datetime.datetime.strptime(str(tbsResponseData.getComponentByName('producedAt')), '%Y%m%d%H%M%SZ')
    certID = response0.getComponentByName('certID')
    certStatus = response0.getComponentByName('certStatus').getName()
    thisUpdate = datetime.datetime.strptime(str(response0.getComponentByName('thisUpdate')), '%Y%m%d%H%M%SZ')

    # let's assume that certID in response matches the certID sent in the request

    # let's assume that response signed by trusted responder

    print("[+] OCSP producedAt:", producedAt)
    print("[+] OCSP thisUpdate:", thisUpdate)
    print("[+] OCSP status:", certStatus)

cert = pem_to_der(open(sys.argv[1], 'rb').read())

ocsp_url = get_ocsp_url(cert)
print("[+] URL of OCSP responder:", ocsp_url)

issuer_cert_url = get_issuer_cert_url(cert)
issuer_cert = download_issuer_cert(issuer_cert_url)

ocsp_req = produce_request(cert, issuer_cert)
ocsp_resp = send_req(ocsp_req, ocsp_url)
parse_ocsp_resp(ocsp_resp)
