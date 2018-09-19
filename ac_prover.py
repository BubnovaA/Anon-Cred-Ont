from collections import namedtuple
from bn256 import *
import ac_utils as utils
from functools import reduce
from random import randrange

class Prover:
    def __init__(self, AttrValue):
        self._AttrValue = AttrValue
      
    #User creates a Credential Request using the public key of the issuer, user secret, and the nonce as input
    #The request consists of a commitment to the user secret (can be seen as a public key) and a zero-knowledge proof of knowledge of the user secret key    
    def genCredRequest( self, IssuerPublicKey, IssuerNonce):
        iAttributeValues = list(map(utils.encodeAttrs,self._AttrValue))
                
        self.ipk = IssuerPublicKey 
        sk = randrange(2, order)
        Nym = gpow(self.ipk.pHSk, sk)
        r = randrange(2, order)
        t1 = gpow (self.ipk.pHSk, r)
        listC = utils.FormList([t1,self.ipk.pHSk,Nym])
        listC.append(IssuerNonce)
        C = utils.HashList(listC)
        S = (r + C * sk) % order
                  
        self.CredRequest = utils.CredRequest(Nym, IssuerNonce, iAttributeValues, C, S)    
        self._mastersecret = sk
        return self.CredRequest

    #The user verifies the issuer's signature and stores the credential
    def verifySig(self, Credential):
        if pair(Credential.A, pointadd(gpow(g2gen, Credential.e), self.ipk.pw))!=pair(Credential.B,g2gen):
            return False
        sumattr =reduce(pointadd,  list(map(lambda x,y: gpow(x,y), self.ipk.HAttrs, self.CredRequest.Attrs)))
        Bprime = reduce(pointadd,[g1gen, gpow(self.ipk.pHRand, Credential.s),self.CredRequest.Nym, sumattr])
        if utils.HashList(utils.FormList([Credential.B])) != utils.HashList(utils.FormList([Bprime])) :
            return False
        else: return True
        
    def setCredential (self, Credential):
        if self.verifySig(Credential):
            self.Credential = Credential
            return True
        else: return False

    #Predicate example: [0,1,0,1,1] 0 - attribute not disclosed (hidden), 1 - attribute disclosed (reveal)
    def setAttributePredicate (self, Predicate):
        if (len(Predicate))!=(len(self._AttrValue)):
            print ('Predicate length does not match number of attributes')
            return False    
        DI = [[],[]]       
        for i in range(len(Predicate)):
            DI[0].append (Predicate[i])
            DI[1].append (0) if Predicate[i] == 0 else DI[1].append (self.Credential.Attrs[i])
        
        return DI
        
    
    #The prover is in possession of an anonymous credential,
    #and he can selectively disclose some attributes while hiding the other attributes.
    def genProof (self, Predicate):
        self.DI = self.setAttributePredicate(Predicate)
        if self.DI :
            r1 = randrange(2, order)
            # A' = A^r1
            APrime = gpow (self.Credential.A, r1)
            # _A = A'^(-e) * B^r1
            ABar = pointadd(gpow (pointneg(APrime), self.Credential.e), gpow(self.Credential.B, r1)) #
            # r3 = 1/r1
            r3 = utils.inverse_mod(r1, order) 
            r2 = randrange(2, order)
            # B' = B^r1 * HRand^(-r2)
            BPrime = pointadd(gpow (self.Credential.B, r1), gpow (pointneg(self.ipk.pHRand), r2))
            # s' = s - r2*r3
            sPrime = (self.Credential.s - r2*r3 ) % order
            r_e, r_r2, r_r3, r_cs, r_sk = [randrange(2, order) for i in range(5)]
            E = gpow (self.ipk.pHSk, r_sk)
            t1 = pointadd (gpow (APrime, r_e) , gpow (self.ipk.pHRand, r_r2))

            mai = []        
            rai = []
            sai = []
            for i in range(len(self.DI[0])):
                if self.DI[0][i] == 0 :
                    r = randrange(2, order) 
                    rai.append ( r )
                    sai.append ( self.Credential.Attrs[i] )
                    mai.append ( gpow (self.ipk.HAttrs[i], r))

            mullall = reduce ( pointadd, mai)
            t2 = reduce ( pointadd, [gpow (BPrime, r_r3), gpow (self.ipk.pHRand, r_cs ), pointneg (E), mullall])
            listCp = [APrime, ABar, BPrime, self.CredRequest.Nym, t1, t2, g1gen, self.ipk.pHRand]
            listCp += self.ipk.HAttrs
            listCp.append(self.ipk.pw)
            Nonce = utils.GetNonce()
            listC = [ Nonce ]
            listC += utils.FormList(listCp)
            listC += [item for sublist in self.DI for item in sublist]
            c = utils.HashList(listC) 
            
            s_sk = (r_sk + c*self._mastersecret) % order
            sai = list(map(lambda x,y: (x - c*y) % order, rai, sai))
            s_e = (r_e - c*self.Credential.e) % order 
            s_r2 = (r_r2 + c*r2) % order 
            s_r3 = (r_r3 + c*r3) % order
            s_cs = (r_cs - c*sPrime) % order
           
            self.Proof = utils.Proof(APrime, ABar, BPrime, c, s_sk, s_e, s_r2, s_r3, s_cs, sai, Nonce, self.CredRequest.Nym)

            return self.DI, self.Proof 
        else : return False


    
