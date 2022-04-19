import json
import hashlib
import time
#from cryptography.fernet import Fernet
import random
from Crypto.PublicKey import RSA



print("Hello World")
#n = random.randint(1, 100000000000000000000)
# n =69
# print(n)
# slicedNonce = str(n)[0:-5]
# print(slicedNonce)
# byteNonce = n.to_bytes(64, 'big')
# print(byteNonce)
# randomHash = hashlib.sha256(byteNonce).hexdigest()
# print(randomHash)
# slicedHash = str(randomHash)[0: -10]
# print(slicedHash)

keyPair = RSA.generate(2048)
print(f"Modulus:  (n={hex(keyPair.n)})")
print(f"Public exponent:  (e={hex(keyPair.e)})")
print(f"Private exponent: (d={hex(keyPair.d)})")
print(keyPair.d)
# RSA sign the message
msg = b'A message for signing'
from hashlib import sha512
hash = int.from_bytes(sha512(msg).digest(), byteorder='big')
signature = pow(hash, keyPair.d, keyPair.n)
print("Signature:", hex(signature))

#So we raise the thing inversely, and check the signature
hashFromSignature = pow(signature, keyPair.e, keyPair.n)
print("Signature valid:", hash == hashFromSignature)
#print(hashlib.sha256().hexdigest())

