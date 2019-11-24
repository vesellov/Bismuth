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

DIFFICULTY = 16


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
        cursor.execute("CREATE TABLE misc (block_height INTEGER, difficulty TEXT)")
        cursor.execute("INSERT INTO misc (difficulty, block_height) VALUES ({},1)".format(DIFFICULTY))
        # TODO: create indexes
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


if os.path.isfile("static/hyper.db"):
    print("You are beyond hyper genesis")
else:
    # transaction processing
    hyper_cursor = None
    try:
        hyper_conn = sqlite3.connect('static/hyper.db')
        hyper_cursor = hyper_conn.cursor()
        hyper_cursor.execute("CREATE TABLE transactions (block_height INTEGER, timestamp, address, recipient, amount, signature, public_key, block_hash, fee, reward, operation, openfield)")
        hyper_cursor.execute("INSERT INTO transactions VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", ("1", timestamp, 'genesis', address, '0', str(signature_enc), public_key_b64encoded, block_hash, 0, 1, 1, 'genesis'))  # Insert a row of data
        hyper_cursor.execute("CREATE TABLE misc (block_height INTEGER, difficulty TEXT)")
        hyper_cursor.execute("INSERT INTO misc (difficulty, block_height) VALUES ({},1)".format(DIFFICULTY))
        # TODO: create indexes
        hyper_conn.commit()  # Save (commit) the changes

        hyper_conn.close()
        hyper_cursor = None

        print("Hyper Genesis created.")
    except sqlite3.Error as e:
        print("Error %s:" % e.args[0])
        sys.exit(1)
    finally:
        if hyper_cursor is not None:
            hyper_cursor.close()


if os.path.isfile("static/index.db"):
    print("Index already exists")
else:
    # transaction processing
    index_cursor = None
    try:
        index_conn = sqlite3.connect('static/index.db')
        index_cursor = index_conn.cursor()
        index_cursor.execute("CREATE TABLE tokens (block_height INTEGER, timestamp, token, address, recipient, txid, amount INTEGER)")
        index_cursor.execute("CREATE TABLE aliases (block_height INTEGER, address, alias)")
        index_cursor.execute("CREATE TABLE staking (block_height INTEGER, timestamp NUMERIC, address, balance, ip, port, pos_address)")
        # TODO: create indexes
        index_conn.commit()  # Save (commit) the changes

        index_conn.close()
        index_cursor = None

        print("Index table created.")
    except sqlite3.Error as e:
        print("Error %s:" % e.args[0])
        sys.exit(1)
    finally:
        if index_cursor is not None:
            index_cursor.close()
