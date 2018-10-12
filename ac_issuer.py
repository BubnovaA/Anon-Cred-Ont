from bn256 import *
from random import randrange
from collections import namedtuple
import ac_utils as utils
from functools import reduce

class Issuer:
    def __init__(self):
        pass
     
    def genKeyPair( self, AttributeNames ) :
        assert isinstance(AttributeNames,(list, tuple))
        self.AttributeNames = AttributeNames
        
        x, w = g2_random(2)  # x =  random element x from Zp, w =  g2^x
        g1bar = g1_random()   # random element _g1 from G1
        g2bar = gpow(g1bar, x)  # _g2 = _g1^x

        
        r = randrange(2, order)  
        t1 = gpow (g2gen, r)
        t2 = gpow (g1bar, r)
        
        C = utils.hashList(utils.formList([t1,t2,g2gen,g1bar,w,g2bar]))
        S = (r + C * x) % order
        HAttrs = [g1_random() for i in range(len(AttributeNames))] 
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
        self.ipk = utils.IssuerPublicKey(AttributeNames,HAttrs,HRand,HSk,w,g1bar,g2bar,C,S)    
        self.isk = x
        
    
    def getIssuerPublicKey (self):
        return self.ipk
    
    def getNonce ():
        return utils.getNonce()
    
    #Issuer verifies the credential request by verifying the zero-knowledge proof   
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
    def genCredential (self, CredRequest) :
        if self.verifyPoK (self, CredRequest):
            """
            Sample two random elements e, s from Zp.
            Compute B = g1 · HRand^s · Nym · MulAll(HAttrs[i]^(Attrs[i]))
            Compute A = B^(1/(e+x)).
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
        
        
        
        
        
        
