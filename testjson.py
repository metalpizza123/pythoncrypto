import json
import hashlib
import time
from cryptography.fernet import Fernet
import random
import os
from Crypto.PublicKey import RSA
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64
import secrets
from types import SimpleNamespace


maindir= os.path.dirname(__file__)
name = "john"
Account = open('accounts/julian.json','r+')
print(Account)
data = json.load(Account)
print(data)
print(data.get("name"))
print(data.get("pubkeyexponent"))


def print_hi(name):
    # Use a breakpoint in the code line below to debug your script.
    print(f'Hi, {name}')  # Press Ctrl+8 to toggle the breakpoint.


def login(nick, pwd):
    enterName = nick
    enterPwd = pwd
    accounts = searchJSON(enterName, "account")
    if len(accounts) > 1:
        print("There seems to be 2 accounts associated with your nick.")
        return False
    elif len(accounts) == 0:
        print("There seems to be no accounts associated with your nick")
        return False
    else:
        # print(accounts[0])
        accountfile = open(accounts[0], "r")
        accountdata = json.load(accountfile)
        accountfile.close()
        print("account id is " + accountdata.get("accountid"))
        check = verifyUnlock(accountdata, enterPwd)
        if check == False:
            print("Wrong Username/Password")
            return False
        elif check == True:
            print("Username/Password accepted")
            return accountdata


def verifyUnlock(acct, passwd):
    salt = acct.get("saltInt")
    encryptedkey = acct.get("AESprivatekeyexponent")
    signature = acct.get("accountsignature")
    modulus = acct.get("rsamodulus")
    accounthash = acct.get("accounthash")
    saltInt = salt.to_bytes(8, 'big')
    keyDerivationFunction = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=saltInt,
        iterations=390000,
    )
    key = base64.urlsafe_b64encode(keyDerivationFunction.derive(passwd.encode('utf-8')))
    unlocker = Fernet(key)
    unencryptedPrivatekey = unlocker.decrypt(encryptedkey.encode('utf-8'))
    checkhash = int.from_bytes(hashlib.sha256(accounthash.encode('utf-8')).digest(), byteorder='big')
    hashFromSignature = pow(checkhash, int(unencryptedPrivatekey), modulus)
    print("Signature validity:", signature == hashFromSignature)
    return (signature == hashFromSignature)


def createAccount(type):
    unique = False
    while (unique == False):
        enterName = input("Please enter a username: ")
        accounts = searchJSON(enterName, "account")
        if len(accounts) > 0:
            print("Sorry, there already exists a user with that nick")
        else:
            unique = True
    enterPasswd = input("Please enter a password: ")
    newAcct = Account(enterPasswd, enterName, type)
    newAcct.printDetails()
    saveAccountDetails(newAcct)
    print("Now log in with your details")


def saveAccountDetails(acct):
    jsonStr = json.dumps(acct.__dict__, indent=4)
    # print(jsonStr)
    # pretty print just if you'd like to see the output first
    enterName = acct.name
    absolutedir = os.path.dirname(__file__)
    relativedir = "accounts"
    filename = enterName + ".json"
    # print(filename)
    combinedPath = os.path.join(absolutedir, relativedir, filename)
    with open(combinedPath, "w") as write_file:
        json.dump((acct.__dict__), write_file, indent=4)
    write_file.close()


def saveBlockDetails(block):
    jsonStr = json.dumps(block.__dict__, indent=4)
    # print(jsonStr)
    # pretty print just if you'd like to see the output first
    absolutedir = os.path.dirname(__file__)
    relativedir = "currencies/" + str(block.currency)
    filename = str(block.currency) + "block" + str(block.id) + ".json"
    # print(filename)
    combinedPath = os.path.join(absolutedir, relativedir, filename)
    with open(combinedPath, "w") as write_file:
        json.dump((block.__dict__), write_file, indent=4)
    write_file.close()


def saveLedgerDetails(ledger):
    jsonStr = json.dumps(ledger.__dict__, indent=4)
    # print(jsonStr)
    # pretty print just if you'd like to see the output first
    currencyName = ledger.currencyname
    absolutedir = os.path.dirname(__file__)
    relativedir = "currencies/" + str(currencyName)
    filename = currencyName + "ledger.json"
    # print(filename)
    combinedPath = os.path.join(absolutedir, relativedir, filename)
    with open(combinedPath, "w") as write_file:
        json.dump((ledger.__dict__), write_file, indent=4)
    write_file.close()


def searchJSON(name, type):
    if type == "ledger":
        filename = "ledger"
        relativedir = "currencies/" + str(name)
    elif type == "account":
        relativedir = "accounts"
        filename = str(name)
    elif type == "block":
        relativedir = "currencies/" + str(name)
        filename = str(name) + "block"
    absolutedir = os.path.dirname(__file__)
    combinedPath = os.path.join(absolutedir, relativedir)
    result = []
    for root, dir, files in os.walk(combinedPath):
        for file in files:
            if file.startswith(filename) and file.endswith(".json"):
                result.append(os.path.join(root, file))
    return result


def fetchNewestUnconfirmedBlockID(currency):
    blocklist = fetchDataFromLedger(currency, "blocklist")
    print(blocklist)
    lastconfirmedID = max(blocklist)
    print(lastconfirmedID)
    nextUnconfirmedID = lastconfirmedID + 1
    id = fetchDataFromBlock(nextUnconfirmedID, currency, "id")
    return id


def accountCoreLoop():
    loggedin = False
    while loggedin == False:
        enterName = input("Please enter account username: ")
        enterPwd = input("Please enter account password: ")
        response = login(enterName, enterPwd)
        if response != False:
            loggedin = True
            acct = response
    print('Nice')
    print(acct.get("name"))
    while loggedin == True:
        print("enter")
        exit()


# Create a class for transactions
def dictTransaction(amount, sender, recipient, modulus, publickey, currencyName, formattedprivatekey):
    currentTime = str(time.time())
    dict = {}
    saltInt = random.randint(1, 10000000000000000)
    dict.update({"id": (currentTime + "___" + str(recipient) + "___" + str(sender))})
    dict.update({"salt": saltInt})
    dict.update({"amount": amount})
    dict.update({"sender": sender})
    dict.update({"recipient": recipient})
    dict.update({"publickey": publickey})
    dict.update({"modulus": modulus})
    dict.update({"currency": currencyName})

    sign = pow(saltInt, formattedprivatekey, modulus)
    dict.update({"signature": sign})
    # Signature of transaction

    hashable = (str(dict["id"]) + str(dict["amount"]) + str(dict["sender"]) + str(dict["recipient"]) +
                str(dict["publickey"]) + str(dict["currency"] + str(dict["signature"])))
    hash = hashlib.sha256((hashable).encode('utf-8')).hexdigest()
    print("hash")
    dict.update({"hash": hash})
    # Hash of transaction +signature

    print("Transaction ID is " + str(dict["id"]))
    print("Hash is " + str(hash))
    print("Signature is " + str(dict["signature"]))
    return dict


def fetchDataFromBlock(id, currency, data):
    blocklist = searchJSON(currency, "block")
    name = currency + "block" + str(id) + ".json"
    confirmedBlock = ""
    for item in blocklist:
        if item.endswith(name):
            confirmedBlock = item
    filedata = open(confirmedBlock, 'r')
    formattedData = json.load(filedata)
    hash = formattedData.get(data)
    return hash


def updateBlockListofLedger(currency, blockid, blockhash, transactions):
    return True


class Block:
    def __init__(self, id, currency):
        if id == 0:
            previousHash = "firstblock"
        else:
            previousHash = fetchDataFromBlock(id - 1, currency, "blockhash")
        self.difficulty = 60
        self.nonce = ""
        self.currency = currency
        self.id = id
        self.previousHash = previousHash
        self.previousID = id - 1
        self.transactions = []
        self.miner = ""
        self.confirmed = False
        self.hashable = (str(self.currency) + str(self.id) + str(self.previousHash) + str(self.difficulty))
        self.blockhash = hashlib.sha256(self.hashable.encode('utf-8')).hexdigest()
        # The lower the difficulty, the harder it is.
        # In this example, it'll slice off the last 60, so you only need to match the first 4 chars
        # But for demo purposes, let's set it to 60, so we only need to guess 1 in 16^4, or 1 in 65536

    def updateTransactions(self, transaction):
        self.transactions.append(transaction)
        hashable = self.hashable.encode('utf-8')
        print("hashable = " + str(hashable))
        for x in self.transactions:
            print("Hash of transaction is" + x["hash"])
            digest = hashable + (x["hash"]).encode('utf-8')
            hashable = hashlib.sha256(digest).hexdigest()
            print("New hashable is " + str(hashable))
        self.blockhash = hashable
        return True;

    def rerunBlockHash(self):
        hashable = self.hashable
        for x in self.transactions:
            hashable = hashlib.sha256(hashable + x.hash).hexdigest()
        self.blockhash = hashable
        return True


def updateTransactions(block, transaction):
    block.transactions.append(transaction)
    return True;


class Account:
    def __init__(self, passwd, name, type):
        keyPair = RSA.generate(2048)
        self.saltInt = random.randint(1, 10000000000000000)
        key = generateFernetKey(self.saltInt, passwd)
        userlock = Fernet(key)
        encryptedPrivateKey = userlock.encrypt(str(keyPair.d).encode('utf-8')).decode('utf-8')
        # print(encryptedPrivateKey)
        self.accountid = str(secrets.token_urlsafe(32))
        # print("id is" + str(secrets.token_urlsafe(32)))
        self.name = name
        self.type = type
        self.rsamodulus = keyPair.n
        self.pubkeyexponent = keyPair.e
        self.AESprivatekeyexponent = encryptedPrivateKey
        if self.type == "masterserve":
            currencyName = input("Please name your currency:")
            self.startingamount = int(input("Please input your starting amount:"))
            self.wallets = []
            self.currencyName = currencyName
        elif self.type == "normalnode":
            self.wallets = []
        self.accounthash = ("A message for signing " + name + str(self.accountid))
        checkHash = int.from_bytes(hashlib.sha256(self.accounthash.encode('utf-8')).digest(), byteorder='big')
        # print("checkHash is " + str(checkHash))
        # print("encryptedKey is " + str(encryptedPrivateKey))
        # print("modulus  is " + str(keyPair.n))
        self.accountsignature = pow(checkHash, keyPair.d, keyPair.n)
        # print ("private key is" + str(keyPair.d))

    def printDetails(self):
        print(self.accountid)
        print(self.name)
        print(self.type)
        print(self.wallets)
        print(self.saltInt)
        print(self.rsamodulus)
        print(self.pubkeyexponent)
        print(self.accounthash)
        print(self.AESprivatekeyexponent)
        print(self.accountsignature)

    def addWallet(self, currency):
        walletAddress = str(secrets.token_urlsafe(32))
        currency = currency
        self.wallets.append((currency, walletAddress))


class Ledger:
    def __init__(self, currency, masteraccount):
        self.currency = currency
        self.masteraccountaddress = masteraccount
        self.transactionlist = []


def checkBalance(address, currency):
    return ""


def createNewLedgerDirectory(currencyName):
    absolutedir = os.path.join(os.path.dirname(__file__), "currencies")
    relativedir = str(currencyName)
    combinedPath = os.path.join(absolutedir, relativedir)
    print(combinedPath)
    isExist = os.path.exists(combinedPath)
    if isExist == False:
        os.makedirs(combinedPath)
        return True
    else:
        return False


class Ledger:
    def __init__(self, currencyname, masteraddress):
        self.currencyname = currencyname
        self.masteraddress = masteraddress
        self.blocklist = []

    def addtransaction(self, block):
        self.blocklist.append(block)


def generateFernetKey(saltInt, pw):
    encodedPw = pw.encode()
    saltByte = saltInt.to_bytes(8, 'big')
    keyDerivationFunction = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=saltByte,
        iterations=390000,
    )
    key = base64.urlsafe_b64encode(keyDerivationFunction.derive(encodedPw))
    return key


def createCurrency():
    print("You'll need to create a starting main account for distribution")
    unique = False
    while (unique == False):
        enterName = input("Please enter a username: ")
        accounts = searchJSON(enterName, "account")
        if len(accounts) > 0:
            print("Sorry, there already exists a user with that nick")
            exit()
        else:
            unique = True
    enterPwd = input("Please enter account password: ")
    newmasteraccount = Account(enterPwd, enterName, "masterserve")
    currencyName = newmasteraccount.currencyName
    maxCurrency = newmasteraccount.startingamount
    print(newmasteraccount.currencyName)
    newmasteraccount.addWallet(newmasteraccount.currencyName)

    LedgerCreate = createNewLedgerDirectory(currencyName)
    if LedgerCreate == False:
        print("There already exists a currency with that name")
        exit()
    # Ledger is still python class
    saveAccountDetails(newmasteraccount)
    # But account is now saved
    print("Now login to your account to generate first transaction to yourself")
    enterName = input("Please enter account username: ")
    enterPwd = input("Please enter account password: ")
    openAccount = login(enterName, enterPwd)
    if openAccount == False:
        exit()
    startingamount = openAccount.get("startingamount")
    masteraddress = openAccount.get("wallets")[0][1]
    print("master address " + masteraddress)

    newLedger = Ledger(currencyName, masteraddress)
    print("Ledger created with " + currencyName)
    # Create first block
    id = 0
    newBlock = Block(id, currencyName)
    print("First block created")
    # First transaction is from master to master,
    firstTransaction = createTransaction(openAccount, currencyName, masteraddress, startingamount, enterPwd)
    print(firstTransaction)
    print(type(firstTransaction))
    print("id of transaction" + str(firstTransaction["id"]))
    jsonStr = json.dumps(firstTransaction)
    print("New transaction is")
    print(type(firstTransaction))
    print(jsonStr)
    # add transaction to first block
    newBlock.updateTransactions(firstTransaction)
    jsonStr = json.dumps(newLedger.__dict__, indent=4)
    print("New Ledger is")
    print(jsonStr)
    jsonStr = json.dumps(newBlock.__dict__, indent=4)
    print("New Block is")
    print(jsonStr)
    saveBlockDetails(newBlock)
    saveLedgerDetails(newLedger)
    # since block isn't confirmed, let's hash the first block
    # Here are the block details
    hash = fetchDataFromBlock(id, currencyName, "blockhash")
    print("hash is " + str(hash))


def minerMode(currency):
    id = fetchNewestUnconfirmedBlockID(currency)
    blockHash = fetchDataFromBlock(id, currency, "blockhash")
    print("Fetch hash is " + str(blockHash))
    difficulty = fetchDataFromBlock(id, currency, "difficulty")
    nonce = mine(blockHash, difficulty)
    flag = confirmBlockNonce(currency, id, nonce)
    # Now update the block, create a new blank block, and
    if flag:
        confirmBlock(currency, id, nonce)


def fetchDataFromLedger(currency, data):
    absolutedir = os.path.join(os.path.dirname(__file__), "currencies")
    relativedir = str(currency)
    filename = str(currency) + "ledger.json"
    totalpath = os.path.join(absolutedir, relativedir, filename)
    print(totalpath)
    isExist = os.path.exists(totalpath)
    if isExist == True:
        filedata = open(totalpath, 'r')
        formattedData = json.load(filedata)
        print(formattedData)
        value = formattedData.get(data)
    print(value)
    return value


def mine(hash, difficulty):
    hashed = False;
    shalimit = (pow(2, 64)) - 1
    slicedHash = str(hash)[0: -(difficulty)]
    while (hashed == False):
        guess = random.randint(0, shalimit)
        print("guess is " + str(guess))
        byteGuess = guess.to_bytes(64, 'big')
        hashGuess = hashlib.sha256(byteGuess).hexdigest()
        slicedGuess = str(hashGuess)[0: -(difficulty)]
        if slicedGuess == slicedHash:
            print("gotcha")
            hashed = True
    print("success")


def createTransaction(acct, currencyName, recipient, amount, pwd):
    # first fetch the privatekey
    saltByte = (acct.get("saltInt").to_bytes(8, 'big'))
    keyDerivationFunction = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=saltByte,
        iterations=390000,
    )
    key = base64.urlsafe_b64encode(keyDerivationFunction.derive(pwd.encode('utf-8')))
    userpasswd = Fernet(key)
    encryptedPrivateKey = acct.get("AESprivatekeyexponent")
    unencryptedPrivateKey = userpasswd.decrypt(encryptedPrivateKey.encode('utf-8'))
    print("private key is" + str(unencryptedPrivateKey))
    formattedprivatekey = int.from_bytes(unencryptedPrivateKey, byteorder='big')
    publickey = acct.get("pubkeyexponent")
    # we know private key is valid since they just logged in
    modulus = acct.get("rsamodulus")
    walletList = acct.get("wallets")
    for wallet in walletList:
        if wallet[0] == currencyName:
            sender = wallet[1]
    newTransaction = dictTransaction(amount, sender, recipient, modulus, publickey, currencyName, formattedprivatekey)
    return newTransaction


def openAccount(name):
    listAccounts = searchJSON(name, "account")
    if len(listAccounts) != 1:
        print("no account with that name")
        return False
    else:
        enterPasswd = input("Please enter a password: ")
        acct = openJSON(listAccounts[0])
    return acct


def confirmBlockNonce(currency, id, nonceguess):
    hash = fetchDataFromBlock(id, currency, "blockhash")
    difficulty = fetchDataFromBlock(id, currency, "difficulty")
    byteGuess = nonceguess.to_bytes(64, 'big')
    hashGuess = hashlib.sha256(byteGuess).hexdigest()
    slicedGuess = str(hashGuess)[0: -(difficulty)]
    slicedHash = str(hash)[0: -(difficulty)]
    # quick check if it's valid
    if slicedGuess == slicedHash:
        return True
    else:
        return False


def confirmBlock(currency, id, nonce):
    searchJSON()

def openJSON(path):
    account = open(path, 'w')
    accountData = json.load(Account)
    return accountData


def coreloop():
    print("1) Create an account \n")
    print("2) Login to account \n")
    print("3) Check ledger of accepted transactions for a currency\n")
    print("4) Create new currency\n")
    print("5) Exit\n")
    chooseFunction = input("Please choose a function:")
    print(chooseFunction)
    if chooseFunction == "1":
        print("Please create an account")
        createAccount("normalnode")
        coreloop()
    elif chooseFunction == "2":
        accountCoreLoop()
    elif chooseFunction == "3":
        ledgerCheck()
    elif chooseFunction == "4":
        createCurrency()
    elif chooseFunction == "5":
        exit()

minerMode("vodka")
# hash=fetchHash(str(id),currency)
# guess = mine(hash,60)
# print(guess)
# byteGuess = guess.to_bytes(64, 'big')
# print(hashlib.sha256(byteGuess).hexdigest())