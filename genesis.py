#WARNING: this file uses the old wallet structure, there is no need to update it at the moment

import hashlib
import socket
import re
import sqlite3
import os
import sys
import time
import base64

from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import PKCS1_v1_5
from Cryptodome.Hash import SHA
from Cryptodome import Random

if os.path.isfile("privkey.der"):
    print("privkey.der found")
elif os.path.isfile("privkey_encrypted.der"):
    print("privkey_encrypted.der found")

else:
    # generate key pair and an address
    key = RSA.generate(4096)
    public_key = key.publickey()

    private_key_readable = str(key.exportKey().decode("utf-8"))
    public_key_readable = str(key.publickey().exportKey().decode("utf-8"))
    address = hashlib.sha224(public_key_readable.encode("utf-8")).hexdigest()  # hashed public key
    # generate key pair and an address

    print("Your address: {}".format(address))
    print("Your private key:\n {}".format(private_key_readable))
    print("Your public key:\n {}".format(public_key_readable))

    with open("privkey.der", "a") as f:
        f.write(str(private_key_readable))

    with open("pubkey.der", "a") as f:
        f.write(str(public_key_readable))

    with open("address.txt", "a") as f:
        f.write("{}\n".format(address))

# import keys
pkraw = open('privkey.der').read()
key = RSA.importKey(pkraw)
public_key = key.publickey()
private_key_readable = str(key.exportKey().decode("utf-8"))
public_key_readable = str(key.publickey().exportKey().decode("utf-8"))
address = hashlib.sha224(public_key_readable.encode("utf-8")).hexdigest()

print("Your address: {}".format(address))
print("Your private key:\n {}".format(private_key_readable))
print("Your public key:\n {}".format(public_key_readable))
public_key_b64encoded = base64.b64encode(public_key_readable.encode("utf-8"))
# import keys

timestamp = str(time.time())
print("Timestamp: {}".format(timestamp))
transaction = (timestamp, "genesis", address, str(float(100000000)), "genesis")
print("Transaction: {}".format(transaction))
h = SHA.new(str(transaction).encode("utf-8"))
signer = PKCS1_v1_5.new(key)
signature = signer.sign(h)
signature_enc = base64.b64encode(signature)
print("Encoded Signature: {}".format(signature_enc))
block_hash = hashlib.sha224(str((timestamp, transaction)).encode("utf-8")).hexdigest()  # first hash is simplified
print ("Transaction Hash: {}".format(block_hash))

if os.path.isfile("static/ledger.db"):
    print("You are beyond genesis")
else:
    # transaction processing
    cursor = None
    mem_cur = None
    try:
        conn = sqlite3.connect('static/ledger.db')
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE transactions (block_height INTEGER, timestamp, address, recipient, amount, signature, public_key, block_hash, fee, reward, operation, openfield)")
        cursor.execute("INSERT INTO transactions VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", ("1", timestamp, 'genesis', address, '0', str(signature_enc), public_key_b64encoded, block_hash, 0, 1, 1, 'genesis'))  # Insert a row of data
        conn.commit()  # Save (commit) the changes

        mempool = sqlite3.connect('mempool.db')
        mem_cur = mempool.cursor()
        mem_cur.execute("CREATE TABLE transactions (timestamp, address, recipient, amount, signature, public_key, operation, openfield)")
        mempool.commit()

        conn.close()
        mempool.close()
        cursor = None
        mem_cur = None

        print("Genesis created.")
    except sqlite3.Error as e:
        print("Error %s:" % e.args[0])
        sys.exit(1)
    finally:
        if cursor is not None:
            cursor.close()
        if mem_cur is not None:
            mem_cur.close()
