# pythoncrypto
Very quick, 3 day implementation of crypto system.

Comes with built in hasher, ledger, and account system. Generates blocks and accounts, with a miner included to hash blocks. Current difficulty is set to 60, so for a the standard 64 byte key, you only need to match the first 4 bytes. Lower difficulties = longer hash times.

# Everything is in main.py. All you need are the 2 directories: currencies,accounts AND the main.py file.

Function 1: Account management
- Include account management with nick/pwd
- Key fed into key derivation function with salt to encrypt your private key
- Accounts can hold wallets for multiple currencies
- Automatically generates addresses when adding wallets for new currencies
- Fetches all previous transactions to generate spendable balance
- Can send currencies based on balance from confirmed transactions
- spending system searches accounts for available wallets in system, with addresses registered to currencies
- RSA 2048 Public/Private Key generated for signing, verifying transactions

Function 2: Currency management
- Generate currencies, requiring a master account, name and currency pool amount
- Generates ledgers, which contains list of confirmed blockIDs
- generates blocks, adds transactions and updates blockhashes as necessary

Function 3: Hashing/Mining
- Using an account, can search for unconfirmed blocks with pending transactions
- Once hashed, block is signed with miner's address and nonce
- new block is generated and hash from previous block is used to generate block hash of subsequent block(s)

Function 4: Transactions
- Using an account, get available balance of currency
- Send to other registered users
- commit transaction to block, signing using signature generated from transaction details and account's private key

## Usage

(I know I need to create a requirements.txt)

run main.py in directory with 2 other required directories: /currencies and /accounts

Main page should look like this

![image](https://user-images.githubusercontent.com/15609080/164075448-57dd2aca-5a40-405b-bac2-a15956a761e3.png)

And after logging in should look like this

![image](https://user-images.githubusercontent.com/15609080/164075577-18522997-7a58-4573-9798-84c1cdf66cff.png)

# Example setup

There are 3 accounts: boris,julian and varya. They all use the same password:1234
There is 1 currency:vodka. and boris is the master account for it, and holds the starting currency pool

Go nuts! THERE ARE ERRORS, and unpredictable behaviour due to lack of input sanitisation, but if you delete the contents of the 2 directories, it'll start from scratch just fine.
