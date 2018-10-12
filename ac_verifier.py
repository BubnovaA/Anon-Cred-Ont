from collections import namedtuple
import ac_utils as utils
from bn256 import *
import time
from functools import reduce

class Verifier:
    
    def verifyProof (AttributePredicate, Proof, PublicKey):
        #check A'!=1 in G1
        if Proof.APrime.is_infinity() :
            return False
        #check if e(A', w) == e(_A, g2); if false, return false. This is zk-PoK for A
        if (pair(Proof.APrime,PublicKey.pw))!=(pair(Proof.ABar,g2gen)):
            return False
        #~t1 = A'^s_e · HRand^s_r2 · (_A/B')^(-c) . This is zk-PoK for e, r2.
        t1tilde = reduce (pointadd, [gpow (Proof.APrime, Proof.ProofSE), gpow(PublicKey.pHRand, Proof.ProofSR2) , gpow (pointneg(Proof.ABar), Proof.ProofC), gpow (Proof.BPrime, Proof.ProofC)])
        """
        ~t2 : (B')^s_r3 · HRand^s_s' · HSk^(-s_sk) · MulAll(hi^(-s_ai)) · (g1·MulAll(hi^ai))^(-c)
        the i above, first MulAll( ) belongs to _D, where D[i]==0(false)
        the i above, second MulAll( ) belongs to D, where D[i]==1(true)
        This is ZKPoK for r3, s', gsk, ai of _D
        """
        first = []        
        second = []
        for i in range(len(AttributePredicate[0])):
             first.append ((PublicKey.HAttrs[i])) if AttributePredicate[0][i] == 0 else second.append (gpow(PublicKey.HAttrs[i],AttributePredicate[1][i])) #(pointneg(PublicKey.HAttrs[i])
        
        allmulfirst = reduce (pointadd, list(map(gpow, first, Proof.ProofSAttrs)))
        allmulsec = gpow (pointneg(pointadd(g1gen, reduce (pointadd, second))) , Proof.ProofC)
        t2tilde = reduce (pointadd, [gpow (Proof.BPrime, Proof.ProofSR3), gpow (PublicKey.pHRand, Proof.ProofSSPrime), gpow (pointneg(PublicKey.pHSk), Proof.ProofSSk) , allmulfirst, allmulsec])
        
        listH = [Proof.APrime, Proof.ABar, Proof.BPrime, Proof.Nym, t1tilde, t2tilde, g1gen, PublicKey.pHRand]
        listH += PublicKey.HAttrs
        listH.append(PublicKey.pw)
        listC = [Proof.ProofNonce]
        listC += utils.formList (listH)
        listC += [item for sublist in AttributePredicate for item in sublist]
        CPrime = utils.hashList(listC)

        if Proof.ProofC == CPrime :
            return True
        else : return False


    def verifyIssuerPoK(ipk):
        """
        π = PoK{x: w = g2^x && _g2 = _g1^x} = (C, S)
        _t1 = g2^S * w^(-c)
        _t2 = _g1^S * _g2^(-c)
        _P = _t1 || _t2 || g2 || _g1 || w || _g2
        _C = hash_to_int(_P)    
        if C == _C {
        return true
        } else {
        return false
        } 
        """
        t1bar = pointadd(gpow(g2gen, ipk.S), pointneg(gpow(ipk.pw, ipk.C)))
        t2bar = pointadd(gpow(ipk.p_g1, ipk.S) , gpow(pointneg(ipk.p_g2),ipk.C))
        Cbar = utils.hashList(utils.formList([t1bar, t2bar, g2gen, ipk.p_g1, ipk.pw, ipk.p_g2]))
        if ipk.C==Cbar: return True
        else: return False
        

        
        
        
        
        
        
