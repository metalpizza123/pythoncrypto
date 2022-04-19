import json
import hashlib
import time
#from cryptography.fernet import Fernet
import random
from Crypto.PublicKey import RSA


#n = random.randint(1, 100000000000000000000)
n ="hashtransaction"
difficulty = 60
print(n)
slicedNonce = str(n)[0:-5]
print(slicedNonce)
bytetransactions = bytes(n,'utf-8')
print(bytetransactions)
randomHash = hashlib.sha256(bytetransactions).hexdigest()
print(randomHash)
slicedHash = str(randomHash)[0: -(difficulty)]
print(slicedHash)
shalimit=(pow(2,64))-1
print ("shalimit is " + str(shalimit))
hashed = False;

while (hashed == False):

    guess = random.randint(0, shalimit)
    print ("guess is "+ str(guess))
    byteGuess = guess.to_bytes(64, 'big')
    hashGuess = hashlib.sha256(byteGuess).hexdigest()
    slicedGuess = str(hashGuess)[0: -(difficulty)]
    if slicedGuess == slicedHash:
        print("gotcha")
        hashed = True
print("success")
print ("guess is " + str(guess))
print (hashGuess)
print (randomHash)

