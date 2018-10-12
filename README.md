---


---

<h1 id="anonymous-credential">Anonymous Credential</h1>
<p>This repository contains a Python library for implementing anonymous credential scheme.</p>
<h2 id="introduction">Introduction</h2>
<p>In an anonymous credential scheme there are three participants: issuer, user(prover), verifier.<br>
Issuer creates a certificate to user which contains a list of user’s attributes and issuer’s signature (use BBS+ signature). This protocol is formally called credential issuance protocol.<br>
The user who is in possession of that credential can selectively disclose some parts to some verifier. This protocol is formally called credential presentation protocol.</p>
<h2 id="module-description">Module description</h2>
<h3 id="ac_utils">ac_utils</h3>
<p>Module containing data structures and utility functions.<br>
Data structures are specified as named tuples:<br>
Issuer’s public key:</p>
<pre><code>IssuerPublicKey = namedtuple('ipk', [
    'AttributeNames',	#array of string
    'HAttrs',			#one G1-element for one attribute
    'pHRand',			#a random G1 point
    'pHSk',				#a random G1 point to encode user's secret key 
    'pw',				#element from G2  
    'p_g1',				#point of G1
    'p_g2',				#point of G1
    'C',				#integer   (challenge)
    'S'])				#integer   (response)
</code></pre>
<p>Credential request:</p>
<pre><code>CredRequest = namedtuple('CredRequest', [
    'Nym',			#G1 point (commitment to user's master secret)
    'IssuerNonce',	#integer  (nonce)
    'Attrs',		#array of integer  (encoded attributes)
    'C',			#integer   (challenge)
    'S'])			#integer   (response)
</code></pre>
<p>Credential :</p>
<pre><code>Credential = namedtuple('Credential', [
    'A',			#point of G1
    'B',			#point of G1
    'e',			#integer
    's',			#integer
    'Attrs'])		#array of integer
</code></pre>
<p><strong>Utility function:</strong></p>

<table>
<thead>
<tr>
<th>name</th>
<th>result type</th>
<th>description</th>
</tr>
</thead>
<tbody>
<tr>
<td>getNonce()</td>
<td><em>integer</em></td>
<td>generates nonce using the uuid4 () function. The function is the use of 16 bytes for os.urandom (), converting them into an integer</td>
</tr>
<tr>
<td>encodeAttrs(Attrs)</td>
<td><em>integer</em></td>
<td>returns the hash value of attribute</td>
</tr>
<tr>
<td>hashStr(string)</td>
<td><em>integer</em></td>
<td>returns a hash value of the string</td>
</tr>
<tr>
<td>hashList(listC)</td>
<td><em>integer</em></td>
<td>returns a hash value of the list</td>
</tr>
<tr>
<td>formList(listG)</td>
<td><em>list</em></td>
<td>converts an array of curve points to a one-dimensional array of point coordinates</td>
</tr>
<tr>
<td>inverse_mod(x, modp)</td>
<td><em>integer</em></td>
<td>return modular multiplicative inverse of an integer x</td>
</tr>
</tbody>
</table><h3 id="ac_issuer">ac_issuer</h3>
<p>Module containing Issuer class<br>
Сlass method:</p>

<table>
<thead>
<tr>
<th>name</th>
<th>description</th>
</tr>
</thead>
<tbody>
<tr>
<td>genKeyPair (self, AttributeNames)</td>
<td>for the given array of attribute’s names AttributeNames generates the issuer’s key pair</td>
</tr>
<tr>
<td>getIssuerPublicKey (self)</td>
<td>returns the issuer’s public key</td>
</tr>
<tr>
<td>getNonce ()</td>
<td>returns the issuer’s Nonce</td>
</tr>
<tr>
<td>verifyPoK (self, CredRequest)</td>
<td>returns a boolean. Verifies the credential request by verifying the zero-knowledge proof</td>
</tr>
<tr>
<td>genCredential (self, CredRequest)</td>
<td>generates a credentials for a user, by signing the commitment of the secret key, together with the attribute values</td>
</tr>
</tbody>
</table><h3 id="ac_prover">ac_prover</h3>
<p>Module containing Prover class.<br>
The Prover class is initialized with a set of attributes values.<br>
Сlass method:</p>

<table>
<thead>
<tr>
<th>name</th>
<th>description</th>
</tr>
</thead>
<tbody>
<tr>
<td>genCredRequest (self, IssuerPublicKey, IssuerNonce)</td>
<td>generates a Credential Request using the public key of the issuer, user secret, and the nonce as input. The request consists of a commitment to the user secret (can be seen as a public key) and a zero-knowledge proof of knowledge of the user secret key</td>
</tr>
<tr>
<td>verifySig (self, Credential)</td>
<td>returns a boolean indicating whether a signature is valid for the given Credential</td>
</tr>
<tr>
<td>setCredential (self, Credential)</td>
<td>it internally sets credentials (obtained from an issuer)</td>
</tr>
<tr>
<td>setAttributePredicate (self, Predicate)</td>
<td>for the input predicate (example [0,1,0,1,1] 0 - attribute not disclosed (hidden), 1 - attribute disclosed (reveal)) , return (D, I): attribute predicate, describe what attributes will be disclosed. If D[j]==1, I[j]=attrs[j]=aj, else I[j]=null</td>
</tr>
<tr>
<td>genProof (self, Predicate)</td>
<td>generate the selectively disclosure proof  (zero knowledge proof)</td>
</tr>
</tbody>
</table><h3 id="ac_verifier">ac_verifier</h3>
<p>Module containing Verifier class.<br>
Сlass method:</p>

<table>
<thead>
<tr>
<th>name</th>
<th>description</th>
</tr>
</thead>
<tbody>
<tr>
<td>verifyProof (AttributePredicate, Proof, PublicKey)</td>
<td>returns a boolean indicating whether a signature and Proof of Knowledge (PoK)  is valid for the given AttributePredicate, Proof, PublicKey</td>
</tr>
<tr>
<td>verifyIssuerPoK (ipk)</td>
<td>returns a boolean indicating whether a Proof of Knowledge (PoK) is valid for the given public key</td>
</tr>
</tbody>
</table><h2 id="usage">Usage</h2>
<p>For instance:</p>
<pre><code>import ac_issuer
import ac_prover
import ac_verifier

def testprotokol():
    print('Test protocol')
    issuer = ac_issuer.Issuer
    issuer.genKeyPair(issuer,['Name', 'Age' , 'TelNumber'])
    print('IPK :')
    ipk = issuer.getIssuerPublicKey(issuer)
    print(ipk)
    prover = ac_prover.Prover(['UserName1', 18, 55555])
    Request = prover.genCredRequest(ipk, issuer.getNonce())
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
</code></pre>

