import ac_issuer
import ac_prover
import ac_verifier


def main():
    print('Test protocol')
    issuer = ac_issuer.Issuer
    issuer.genKeyPair(issuer,['Name', 'Age' , 'TelNumber'])
    print('IPK :')
    ipk = issuer.getIssuerPublicKey(issuer)
    print(ipk)
       
    prover = ac_prover.Prover(['UserName1', 31, 55555])
    nonce = issuer.getNonce()
    Request = prover.genCredRequest(ipk, nonce)
    print('REQUEST : ')
    print (Request)
    
    Credential = issuer.genCredential(issuer, Request)
    if Credential:
        if prover.setCredential (Credential):
            print('CREDENTIAL issued to the user:')
            print(Credential)
        else: print ('Error sig')    
    else:
        print('Error gen credential')
    
    Predicate = (0,1,0)
    print('Predicat for ', ipk.AttributeNames, ' : ', Predicate)
    
    DI, Proof = prover.genProof(Predicate)   
    print('PROOF: ', Proof )
    print('DI', DI)

    
    verifier = ac_verifier.Verifier
    print('VERIFY Proof = ', verifier.verifyProof(DI, Proof, ipk))


if __name__ == "__main__":
    main()
    
