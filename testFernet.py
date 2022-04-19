import base64

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

passwd1 = input("Please enter a password: ").encode()
print(passwd1)
#saltInt=  random.randint(1,10000000000000000).to_bytes(8,'big')
#ow we create a key derivation function
saltInt = (7073445242781733).to_bytes(8,'big')

encryptedpassword = "gAAAAABiXKi67kN3KQkh_hYK9buuOJwdZ3dcjfU7JX5dqEfxYbC5zccUG1BXPN1jAjgfcO19lQouTW8GKmB2TFFxSa75owR-SCjKbyWxnt3skbuQqO_hNLrUUEfgTf_u7KCqf2RP9bfl9ep7CC-MymvUDk0SGqvdjQKRi_NPhI-Biw0c3oyCbxaNVraKCnVYtWFOWrOejKvwj_GpINwx446ctaVTI7cLCIkmP4cqmbF-7jTsFji3KwfOar2yFZGO9VurI0H2yp_P2ZF-gMRfBvhhwG2NWQ02d263lfTrsv7w00ScA1ud6A50iLmajw4G3-t8p--R6EnhUKCm2fvIr-aiAY3x771I9_YmFBS-WyeMrwlojwb4VN3gA6NYLt32AAVT-3Y7hnEaMb3vUcLP8V-7PD7DTugOoYogObUSOdJKg9mvTNxKjSU0sdzzOYMLBIRqS68892r0QKXXAsJWr_qTyk_7l0Jq0_IPk7HTsmyUkz-ugQbn-5FH19Gdgs_DIpUIdTdLTgVonvLTH0JqfLS6db9D7yidViBFmfbtYDESFyP8PD4RKlSf3J_ThojqhgliAuh8ia5O3oY4osps3jA5_Nih9cW06b3rUiB-VcGOotIJKQ-uopOQ8PwnIb2B4RAB6CN7Iq7YufUuSszAN2U5wRjxVQeTRm0oz7pkk4v0NepQzrhxpCTZhF-ikcxH2PHtT5rVPHRCTH5wk6mCAAFL-NjT289_etn6jkK7DQ5SJ-jhCNAZGkq2wImP5spYewFhqOzAmv61VMZbS1wS7mRmVFm1SS0vIf1Shtb_U6zDqLwRIB2hjpMi6CxRYAODqnljYVNuvXGSV8j7ie4hdRYluI8LRdxtrOTlb95foBNfaOw5JlGb7uGtWCXDvVQ095xUL690gIKq"

keyDerivationFunction = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=saltInt,
    iterations=390000,
)

key1 = base64.urlsafe_b64encode(keyDerivationFunction.derive(passwd1))
userpasswd = Fernet(key1)

#encrypted = userpasswd.encrypt(checkHash)
#print(encrypted)
#print(encrypted.decode('utf-8'))


passwd2 = input("Please enter a password: ").encode()
keyDerivationFunction2 = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=saltInt,
    iterations=390000,
)

key2 = base64.urlsafe_b64encode(keyDerivationFunction2.derive(passwd2))

userpasswd2 = Fernet(key2)
unencrypted = userpasswd2.decrypt(encryptedpassword.encode('utf-8'))

print(unencrypted)
print(unencrypted.decode('utf-8'))

privatekey = int(unencrypted)
modulus = 25781883341205928431811287234943162633690571100219559724085484378986751100726553568291376959428455752083837724525448425694571841560631563319638807105139500206290351928639054039015794100989784486226884085398823497165377707067086693246458167195477523956144786715434099981607183779232189144071348172314099906872585745610121737796737319404495642786663350560206145645710067197204276105574099430440993238310626045302071414388765986018882263630804276437453445717979256305502659710252050590900866661124522600107629645646149720829379271689812409362900257236546838342821045142359695631586735956130543186134077163162179180073857
checkhash = 12024156294555180732005844832097113443503277044582063141648746021690130378796332603841399401410351985970835314455057167756360444433466122797691207686159097

sig = pow(checkhash,privatekey,modulus)
print("sig is " + str(sig))


