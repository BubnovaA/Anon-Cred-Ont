from bn256 import *
from collections import namedtuple
from hashlib import sha256
import uuid

#Data structures are specified as named tuples
#Issuer’s public key
IssuerPublicKey = namedtuple('ipk', [
    'AttributeNames',
    'HAttrs',
    'pHRand',
    'pHSk',
    'pw',
    'p_g1',
    'p_g2',
    'C',
    'S'])
#Credential request
CredRequest = namedtuple('CredRequest', [
    'Nym',
    'IssuerNonce',
    'Attrs',
    'C',
    'S'])
#Credential
Credential = namedtuple('Credential', [
    'A',
    'B',
    'e',
    's',
    'Attrs'])
#zero knowledge proof
Proof = namedtuple('Proof', [
    'APrime',
    'ABar',
    'BPrime',
    'ProofC',
    'ProofSSk',
    'ProofSE',
    'ProofSR2',
    'ProofSR3',
    'ProofSSPrime',
    'ProofSAttrs',
    'ProofNonce',
    'Nym'])

#generates nonce using the uuid4 () function. The function is the use of 16 bytes for os.urandom (), converting them into an integer
def getNonce():
    nonce = uuid.uuid4()
    return nonce.int

#returns the hash value of attribute
def encodeAttrs(Attrs):
    return int(sha256(str(Attrs).encode()).hexdigest(),16) % order

#returns a hash value of the string
def hashStr(string):
    return int(sha256(string.encode()).hexdigest(),16) % order

#returns a hash value of the list
def formList(listG):
    return [item for sublist in list(map(g_marshall, listG)) for item in sublist]

#converts an array of curve points to a one-dimensional array of point coordinates    
def hashList(listC):
    string = (''.join(list(map('{0:b}'.format,listC))))
    h = sha256(string.encode())
    return int(h.hexdigest(),16)

#Fermat’s little theorem.
#Let p be a prime number and x ∈Fp, then x^p−2 = x^−1.
#return modular multiplicative inverse of an integer x
def inverse_mod(x, modp):
    return pow(x, modp-2, modp)



