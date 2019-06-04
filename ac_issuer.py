from bn256 import *
from random import randrange
from collections import namedtuple
import ac_utils as utils
from functools import reduce

"""
In an anonymous credential scheme there are three participants: issuer, user(prover), verifier.
Issuer creates a certificate to user which contains a list of user's attributes and issuer's signature(use BBS+ signature).
This protocol is formally called credential issuance protocol.
"""
class Issuer:
    def __init__(self):
        pass

    #For the given array of attribute’s names AttributeNames generates the issuer’s key pair
    #g1gen is a generator of G1. g2gen is a generator of G2
    #https://github.com/ontio/ontology-crypto/wiki/Anonymous-Credential#2-setup-of-issuers-key-pair
    def genKeyPair( self, AttributeNames ) :
        assert isinstance(AttributeNames,(list, tuple)) 
        self.AttributeNames = AttributeNames
        
        x, w = g2_random(2)  # x =  random element x from Zp, w =  g2^x
        g1bar = g1_random()   # random element _g1 from G1
        g2bar = gpow(g1bar, x)  # _g2 = _g1^x

        
        r = randrange(2, order)  # r = rand(Zp)
        t1 = gpow (g2gen, r)  # t1 = g2^r
        t2 = gpow (g1bar, r)  # t2 = _g1^r
        
        """
        The protocol we give is a standard sigma protocol. It consists three steps, namely, commit, challenge, response
        P = t1 || t2 || g2 ||_g1 || w ||_g2    //join them together in binary format
        C = hash_to_int(P)                       //C is challenge
        """
        C = utils.hashList(utils.formList([t1,t2,g2gen,g1bar,w,g2bar]))
        """
        S = (r + C * x) mod order               //response to verifier
        """
        S = (r + C * x) % order
        """
        Sample an array of elements from G1 for AttributeNames.
        For each attribute in AttributeNames, compute HAttrs[i] = random(G1)
        """
        HAttrs = [g1_random() for i in range(len(AttributeNames))]
        #Sample two random elements from G1: HRand and HSk.
        HRand, HSk = g1_random(), g1_random() 
        """
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
        """
        #Set issuer's public key ipk = (w, _g1, _g2, π, HAttrs, AttributeNames, HRand, HSk), and private key isk = x.
        self.ipk = utils.IssuerPublicKey(AttributeNames,HAttrs,HRand,HSk,w,g1bar,g2bar,C,S)    
        self.isk = x
        
    #Returns the issuer’s public key
    def getIssuerPublicKey (self):
        return self.ipk

    #Returns the issuer’s Nonce
    def getNonce ():
        return utils.getNonce()
    
    #Issuer verifies the credential request by verifying the zero-knowledge proof
    #Returns a boolean. Verifies the credential request by verifying the zero-knowledge proof
    def verifyPoK (self, CredRequest):
        """
        _t1 = Hsk^S * Nym^(-c)
        _P=_t1||Hsk||Nym||nonce
        _C=hash_to_int(_P)
        if C==_C {
                return True
        } else {
                return False
                }
        """
        t1bar = pointadd(gpow(self.ipk.pHSk, CredRequest.S) , gpow(pointneg(CredRequest.Nym),CredRequest.C) )
        listC = utils.formList([t1bar, self.ipk.pHSk, CredRequest.Nym])
        listC.append(CredRequest.IssuerNonce)
        Cbar = utils.hashList(listC)
       
        if CredRequest.C==Cbar: return True
        else: return False

    #Issuer issues a credential to the user
    #Generates a credentials for a user, by signing the commitment of the secret key, together with the attribute values
    #https://github.com/ontio/ontology-crypto/wiki/Anonymous-Credential#32-issue-credential
    def genCredential (self, CredRequest) :
        if self.verifyPoK (self, CredRequest):
            """
            Sample two random elements e, s from Zp
            Compute B = g1 * HRand^s * Nym * MulAll(HAttrs[i]^(Attrs[i]))
            Compute A = B^(1/(e+x))
            Compute B = g1  HRand^s  Nym  MulAll(HAttrs[i]^(Attrs[i]))
            Compute A = B^(1/(e+x))
            Return credential (A, B, e, s, Attrs)
            """
            e, s = randrange(2, order) , randrange(2, order)
            sumattr = reduce(pointadd, list(map(lambda x,y: gpow(x,y), self.ipk.HAttrs, CredRequest.Attrs)))
            B = reduce(pointadd,[g1gen, gpow(self.ipk.pHRand, s),CredRequest.Nym, sumattr])
            #A = pow (B, 1/(e+x))  A^(e+x)=B  find the inverse of the number and calculate multiplication
            A = gpow(B, utils.inverse_mod((e+self.isk), order))
            """
            Credential = namedtuple('Credential', [
                                    'A',
                                    'B',
                                    'e',
                                    's',
                                    'Attrs'])
            """
            AnonCredential = utils.Credential(A, B, e, s, CredRequest.Attrs) 
            return AnonCredential
        else:
            return False
            print('Proof of knowledge is not verified')
        
        
        
        
        
        
