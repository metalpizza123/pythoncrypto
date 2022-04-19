import os
import hashlib
import random
import secrets

def searchJSON(name,type):
    if type == "ledger":
        filename = "ledger"
        relativedir = "currencies/" +str(name)
    elif type == "account":
        relativedir = "accounts"
        filename = str(name)
    elif type == "block":
        relativedir = "currencies/" +str(name)
        filename = str(name) + "block"
    absolutedir = os.path.dirname(__file__)
    relativedir = "accounts"
    combinedPath = os.path.join(absolutedir,relativedir)
    result =[]
    print(combinedPath)
    print(filename)
    for root, dir, files in os.walk(combinedPath):
        for file in files:
            if file.startswith(filename) and file.endswith(".json"):
                print(os.path.join(root, file))
                result.append(os.path.join(root, file))
    print (result)
    return result

path = searchJSON("boris","account")
print("help")
print(path)

newPrivateAddress = secrets.token_urlsafe()
print (newPrivateAddress)

