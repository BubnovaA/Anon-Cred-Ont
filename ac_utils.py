from bn256 import *
from collections import namedtuple
from hashlib import sha256
import time

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

CredRequest = namedtuple('CredRequest', [
    'Nym',
    'IssuerNonce',
    'Attrs',
    'C',
    'S'])

Credential = namedtuple('Credential', [
    'A',
    'B',
    'e',
    's',
    'Attrs'])

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



def GetNonce():
    return int(time.time() * 1000)

def encodeAttrs(Attrs):
    return int(sha256(str(Attrs).encode()).hexdigest(),16) % order

def HashStr(string):
    return int(sha256(string.encode()).hexdigest(),16) % order

def FormList(listG):
    return [item for sublist in list(map(g_marshall, listG)) for item in sublist]
    
def HashList(listC):
    string = (''.join(list(map('{0:b}'.format,listC))))
    h = sha256(string.encode())
    return int(h.hexdigest(),16)

#Fermat’s little theorem.
#Let p be a prime number and x ∈Fp, then x^p−2 = x^−1.
def inverse_mod(x, modp):
    return pow(x, modp-2, modp)



