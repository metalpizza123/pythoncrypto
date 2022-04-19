import json
import hashlib
import time
import random
import os
from Crypto.PublicKey import RSA
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64
import secrets


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


def saveJSON(dict, path):
    with open(path, "w") as write_file:
        json.dump((dict), write_file, indent=4)
    write_file.close()


def saveRegister(currency, userlist):
    absolutedir = os.path.dirname(__file__)
    relativedir = "currencies/" + str(currency)
    filename = str(currency) + "register.json"
    # print(filename)
    combinedPath = os.path.join(absolutedir, relativedir, filename)
    with open(combinedPath, "w") as write_file:
        json.dump((userlist), write_file, indent=4)
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
    elif type == "register":
        relativedir = "currencies/" + str(name)
        filename = str(name) + "register"
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
    if len(blocklist) == 0:
        return 0
    lastconfirmedID = max(blocklist)
    nextUnconfirmedID = lastconfirmedID + 1
    print("nextunconfirmedID is " + str(nextUnconfirmedID))
    confirmedBlock = fetchDataFromBlock(nextUnconfirmedID, currency, "confirmed")
    if confirmedBlock == True:
        print("No new unconfirmed Blocks")
        return False
    else:
        return nextUnconfirmedID


def accountCoreLoop():
    loggedin = False
    while loggedin == False:
        enterName = input("Please enter account username: ")
        enterPwd = input("Please enter account password: ")
        response = login(enterName, enterPwd)
        if response != False:
            loggedin = True
            acct = response
    if loggedin == False:
        exit()
    print('Nice, welcome ' + str((acct.get("name"))))
    while loggedin == True:
        print("1) Send currency using address \n")
        print("2) Add Wallet \n")
        print("3) Check balance of a specific currency \n")
        print("4) Mine \n")
        print("5) Exit \n")
        chooseFunction = input("Please choose a function:")
        print(chooseFunction)
        if chooseFunction == "1":
            sendcurrency(acct)
        elif chooseFunction == "2":
            addWallet(acct)
        elif chooseFunction == "3":
            accountCheckBalance(acct)
        elif chooseFunction == "4":
            startminer(acct)
        elif chooseFunction == "5":
            coreloop()


def accountCheckBalance(acct):
    chooseCurrency = input("Please enter the name of currency you'd like to add a wallet for: ")
    absolutedir = os.path.join(os.path.dirname(__file__), "currencies")
    relativedir = str(chooseCurrency)
    combinedPath = os.path.join(absolutedir, relativedir)
    isExist = os.path.exists(combinedPath)
    if isExist == False:
        print("No currency with that name exists \n \n")
        return
    elif isExist == True:
        if chooseCurrency not in acct["wallets"]:
            print("You don't have a wallet for this currency in this account")
            return
    balance = getBalance(acct, chooseCurrency)
    print("Your balance is " + str(balance) + " " + str(chooseCurrency) + " in this account")
    return balance


def sendcurrency(acct):
    chooseCurrency = input("Please enter the name of currency you'd like send: ")
    absolutedir = os.path.join(os.path.dirname(__file__), "currencies")
    relativedir = str(chooseCurrency)
    combinedPath = os.path.join(absolutedir, relativedir)
    isExist = os.path.exists(combinedPath)
    if isExist == False:
        print("No currency with that name exists \n \n")
        return
    balance = getBalance(acct, chooseCurrency)
    print("You have " + str(balance) + " to send")
    recipientaddr = chooseRecipient(chooseCurrency)
    valid = False
    while valid == False:
        value = int(input("Please enter how much " + str(chooseCurrency) + " you'd like to send: "))
        if value > balance:
            print("Your balance isn't high enough for you to spend that amount")
        else:
            valid = True
    enterpasswd = input("Please enter account password to verify transaction")
    newTransaction = createTransaction(acct, chooseCurrency, recipientaddr, value, enterpasswd)
    success = updateBlockwithTransaction(newTransaction, chooseCurrency)
    if success:
        print("Transaction successful!")
        return
    else:
        print("There's been an error")
        return


def updateBlockwithTransaction(dictTransaction, currency):
    absolutedir = os.path.join(os.path.dirname(__file__), "currencies")
    relativedir = str(currency)
    blockID = fetchNewestUnconfirmedBlockID(currency)
    filename = currency + "block" + str(blockID) + ".json"
    combinedPath = os.path.join(absolutedir, relativedir, filename)
    # print(combinedPath)
    data = openJSON(combinedPath)
    data["transactions"].append(dictTransaction)
    hashable = data["hashable"].encode('utf-8')
    for x in data["transactions"]:
        digest = hashable + (x["hash"]).encode('utf-8')
        hashable = hashlib.sha256(digest).hexdigest()
    data["blockhash"] = hashable
    saveJSON(data, combinedPath)
    return True


def chooseRecipient(currency):
    userlistdict = getListofRecipients(currency)
    for x, y in userlistdict.items():
        print("Name:" + str(x) + "\n" + "WalletAddress:" + str(y))
    choicerecipient = input("Please enter the name of recipient you'd like to send to: ")
    recipient = choicerecipient
    recipientaddress = userlistdict[choicerecipient]
    recipientaddr = recipientaddress
    return recipientaddr


def getListofRecipients(currency):
    absolutedir = os.path.join(os.path.dirname(__file__), "currencies")
    relativedir = str(currency)
    filename = currency + "register.json"
    path = os.path.join(absolutedir, relativedir, filename)
    data = openJSON(path)
    # generate list of users, search their wallets
    userfilepathlist = searchJSON("", "account")
    userlistdict = {}
    for userpath in userfilepathlist:
        userdata = openJSON(userpath)
        if currency in userdata["wallets"]:
            userlistdict[userdata["name"]] = userdata["wallets"][currency]
    # print(userlistdict)
    return userlistdict


def startminer(acct):
    # some basic checks to see if the currency's directory exists, and if you've an address
    chooseCurrency = input("Please enter the name of currency you'd like mine for: ")
    absolutedir = os.path.join(os.path.dirname(__file__), "currencies")
    relativedir = str(chooseCurrency)
    combinedPath = os.path.join(absolutedir, relativedir)
    isExist = os.path.exists(combinedPath)
    if isExist == False:
        print("No currency with that name exists \n \n")
        return
    if chooseCurrency not in acct["wallets"]:
        print("You don't have a wallet for this currency")
        return
    else:
        minerAddress = acct["wallets"][chooseCurrency]
        print("Mining to this address " + str(minerAddress))
    minerMode(chooseCurrency, minerAddress)


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


def getBalance(acct, currency):
    # first we need to get their wallet for this currency
    walletaddress = acct["wallets"][currency]
    # We then have to painstakingly go through each block, fetch a HUGE list of transactions
    # Then check whether
    # total add is ALL money that has CONFIRMED to go in
    # total spend is ALL money, including UNCONFIRMED that goes out
    blockList = searchJSON(currency, "block")
    allconfirmedtransactionlist = []
    allunconfirmedtransactionlist = []
    for blockfilepath in blockList:
        data = openJSON(blockfilepath)
        transactionlist = data["transactions"]
        if data["confirmed"] == True:
            for transactions in transactionlist:
                allconfirmedtransactionlist.append(transactions)
        else:
            for transactions in transactionlist:
                allunconfirmedtransactionlist.append(transactions)
    totaladd = 0
    totalspend = 0

    if acct["type"] == "masterserve":
        totaladd += acct["startingamount"]
    for transaction in allconfirmedtransactionlist:
        transactionvalue = transaction["amount"]
        if transaction["sender"] == walletaddress:
            print("You sent" + str(transactionvalue) + currency + " to " + str(transaction["recipient"]))
            totalspend += transactionvalue
        if transaction["recipient"] == walletaddress:
            print("You received " + str(transactionvalue) + currency + " from  " + str(transaction["sender"]))
            totaladd += transactionvalue
    for transaction in allunconfirmedtransactionlist:
        if transaction["sender"] == walletaddress:
            print("You sent" + str(transactionvalue) + currency + " to " + str(transaction["recipient"]))
            totalspend += transactionvalue
    print("totaladd is " + str(totaladd))
    print("totalspend is " + str(totalspend))
    balance = totaladd - totalspend
    if balance < 0:
        print("You are in deficit? no account actions available until balance is 0 or more")
        return
    else:
        print("Your balance is" + str(balance))
        return balance


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


def fetchDataFromAccount(name, data):
    filelist = searchJSON(name, "account")
    path = filelist[0]
    print(path)
    with open(path, "r") as read_file:
        accountData = json.load(read_file)
    read_file.close()
    return accountData[data]


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
            self.wallets = {}
            self.currencyName = currencyName
        elif self.type == "normalnode":
            self.wallets = {}
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
        self.wallets[currency] = walletAddress


class Ledger:
    def __init__(self, currency, masteraccount):
        self.currency = currency
        self.masteraccountaddress = masteraccount
        self.transactionlist = []


def addWallet(acct):
    absolutedir = os.path.join(os.path.dirname(__file__), "currencies")
    chooseCurrency = input("Please enter the name of currency you'd like to add a wallet for: ")
    relativedir = str(chooseCurrency)
    if chooseCurrency == "":
        return
    combinedPath = os.path.join(absolutedir, relativedir)
    isExist = os.path.exists(combinedPath)
    if isExist == False:
        print("No currency with that name exists \n \n")
        return
    elif isExist == True:
        if chooseCurrency in acct["wallets"]:
            print("You already have a wallet for this currency")
            return
        walletAddress = str(secrets.token_urlsafe(32))
        acct["wallets"][chooseCurrency] = walletAddress
        filename = acct["name"] + (".json")
        accountdir = os.path.join(os.path.dirname(__file__), "accounts")
        filepath = os.path.join(accountdir, filename)
        saveJSON(acct, filepath)
        # Now we add this user to list of registered users, looking at currencyregister.json
        fileList = searchJSON(chooseCurrency, "register")
        if len(fileList) == 1:
            path = fileList[0]
            print(path)
            registerData = openJSON(path)
            registerData["users"].append(walletAddress)
            saveJSON(registerData, path)
        print("Wallet successfully added\n \n")
        return


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
    # Here, since we have an account saved, and currency directory, we can create the dictionary storing registered users
    # It's not meant to be exhaustive, but it's a good idea for now. Will work on no-tamper features later
    print(newmasteraccount.wallets)
    registeredusers = {"users": [newmasteraccount.wallets[currencyName]]}

    saveRegister(currencyName, registeredusers)
    # But account is now saved\
    print("Now login to your account to generate first transaction to yourself")
    enterName = input("Please enter account username: ")
    enterPwd = input("Please enter account password: ")
    openAccount = login(enterName, enterPwd)
    if openAccount == False:
        exit()
    startingamount = openAccount.get("startingamount")
    masteraddress = openAccount.get("wallets")[currencyName]
    newLedger = Ledger(currencyName, masteraddress)
    # Create first block
    id = 0
    newBlock = Block(id, currencyName)
    # First transaction is from master to master,
    firstTransaction = createTransaction(openAccount, currencyName, masteraddress, startingamount, enterPwd)
    jsonStr = json.dumps(firstTransaction)
    # add transaction to first block
    newBlock.updateTransactions(firstTransaction)
    jsonStr = json.dumps(newLedger.__dict__, indent=4)
    jsonStr = json.dumps(newBlock.__dict__, indent=4)
    saveBlockDetails(newBlock)
    saveLedgerDetails(newLedger)
    # since block isn't confirmed, let's hash the first block
    # All we need is a currrency name and miner address
    minerMode(currencyName, masteraddress)

    print("Currency " + str(currencyName + " created. Log into the master account to send it to other addresses,\n"
                                           " or register new accounts to use it.\n \n \n"))

    coreloop()


def minerMode(currency, miner):
    id = fetchNewestUnconfirmedBlockID(currency)
    transactionlist = fetchDataFromBlock(id, currency, "transactions")
    if id == None:
        print("No Blocks with pending transactions")
        return
    if len(transactionlist) == 0:
        print("Block has no transactions pending")
        return
    blockHash = fetchDataFromBlock(id, currency, "blockhash")
    print("Fetch hash is " + str(blockHash))
    difficulty = fetchDataFromBlock(id, currency, "difficulty")
    print("difficulty is " + str(difficulty))
    nonce = mine(blockHash, difficulty)
    print("nonce is" + str(nonce))
    confirmBlockNonce(currency, id, nonce, miner)
    print("Block succesfully mined!")
    return


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
        value = formattedData.get(data)
    return value


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
        value = formattedData.get(data)
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
    return guess


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
    wallet = acct.get("wallets")
    if currencyName in wallet:
        sender = wallet[currencyName]
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


def confirmBlockNonce(currency, id, nonceguess, miner):
    hash = fetchDataFromBlock(id, currency, "blockhash")
    difficulty = fetchDataFromBlock(id, currency, "difficulty")
    byteGuess = nonceguess.to_bytes(64, 'big')
    hashGuess = hashlib.sha256(byteGuess).hexdigest()
    slicedGuess = str(hashGuess)[0: -(difficulty)]
    slicedHash = str(hash)[0: -(difficulty)]
    slicedHash = str(hash)[0: -(difficulty)]
    # quick check if it's valid
    print("slicedguess is " + str(slicedGuess))
    print("sliceedhash is " + str(slicedHash))
    if slicedGuess == slicedHash:
        confirmBlock(currency, id, nonceguess, miner)
        newid = id + 1
        newBlock = Block(newid, currency)
        saveBlockDetails(newBlock)
        print("New block created")
        addBlockToLedger(id, currency)
        print("old block added to ledger")
    else:
        return False


def addBlockToLedger(id, currency):
    absolutedir = os.path.dirname(__file__)
    relativedir = "currencies/" + str(currency)
    filename = str(currency) + "ledger.json"
    totalpath = os.path.join(absolutedir, relativedir, filename)
    print(totalpath)
    with open(totalpath, "r") as read_file:
        accountData = json.load(read_file)
    read_file.close()
    accountData["blocklist"].append(id)
    with open(totalpath, "w") as write_file:
        json.dump((accountData), write_file, indent=4)
    write_file.close()


def confirmBlock(currency, id, nonce, miner):
    absolutedir = os.path.dirname(__file__)
    relativedir = "currencies/" + str(currency)
    filename = currency + "block" + str(id) + ".json"
    totalpath = os.path.join(absolutedir, relativedir, filename)
    print(totalpath)
    with open(totalpath, "r") as read_file:
        accountData = json.load(read_file)
    read_file.close()
    accountData["confirmed"] = True
    accountData["nonce"] = nonce
    accountData['miner'] = miner
    with open(totalpath, "w") as write_file:
        json.dump((accountData), write_file, indent=4)
    write_file.close()


def openJSON(path):
    file = open(path, 'r')
    data = json.load(file)
    file.close()
    return data


def coreloop():
    print("")
    print("Welcome to Julian's PyCrypto project")
    print("______________________________________________________________________")
    print("1) Create an account \n")
    print("2) Login to account \n")
    print("3) Check ledger of accepted transactions for a currency NOT DONE \n")
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
        coreloop()
    elif chooseFunction == "4":
        createCurrency()
    elif chooseFunction == "5":
        exit()
    else:
        coreloop()


if __name__ == '__main__':
    coreloop()
