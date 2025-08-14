import hashlib
import json
import time
from flask import Flask, request, jsonify, render_template_string
import requests
import random
from ecdsa import SigningKey, SECP256k1, VerifyingKey
import threading
from mnemonic import Mnemonic
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import string
import sqlite3

# --- Database settings ---
DB_FILE = 'blockchain_db.db'
SQLCIPHER_KEY = None 
GENERATED_PASSWORD = None
SEED_PHRASE = None
ENCRYPTED_PRIVATE_KEY = None
SALT = None
PUBLIC_KEY = None
WALLET_ADDRESS = None
LAST_MINED_TIME = 0 
LAST_MINED_Timer = 10
new_hashstartswith = "00"


def generate_db_key(password, seed_phrase):
    """
    Generate an encryption key from the password and seed phrase.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=seed_phrase.encode('utf-8'),
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key.decode()

def get_db_connection():
    """
    Create a connection to the encrypted database.
    """
    global SQLCIPHER_KEY
    if not SQLCIPHER_KEY:
        return None
    
    try:
        cnxn = sqlite3.connect(DB_FILE)
        cnxn.execute(f"PRAGMA key = '{SQLCIPHER_KEY}';")
        return cnxn
    except (sqlite3.OperationalError, sqlite3.DatabaseError) as e:
        print(f"Failed to open the database: {e}. The encryption key is incorrect.")
        return None

def setup_database():
    """
    Set up database tables for the first time.
    """
    cnxn = get_db_connection()
    if not cnxn:
        return
    
    cursor = cnxn.cursor()
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS blocks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            block_hash TEXT NOT NULL UNIQUE,
            block_index INTEGER NOT NULL,
            previous_hash TEXT NOT NULL,
            timestamp REAL NOT NULL,
            nonce INTEGER NOT NULL
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            block_id INTEGER,
            sender TEXT NOT NULL,
            recipient TEXT NOT NULL,
            amount REAL NOT NULL,
            fee REAL NOT NULL,
            signature TEXT NOT NULL,
            public_key TEXT NOT NULL,
            timestamp REAL NOT NULL,
            FOREIGN KEY(block_id) REFERENCES blocks(id)
        )
    """)
    
    cnxn.commit()
    cursor.close()
    cnxn.close()

def hash_string(data_string):
    sha = hashlib.sha256()
    sha.update(data_string.encode('utf-8'))
    return sha.hexdigest()

class Block:
    def __init__(self, index, transactions, previous_hash, nonce=0, **kwargs):
        self.index = index
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.timestamp = time.time()
        self.nonce = nonce
        if 'hash' in kwargs:
            self.hash = kwargs['hash']
        else:
            self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_string = json.dumps({
            "index": self.index,
            "transactions": self.transactions,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp,
            "nonce": self.nonce
        }, sort_keys=True)
        return hash_string(block_string)

app = Flask(__name__)

PEERS = set()
PENDING_TRANSACTIONS = []
NODE_ADDRESS = ""
BOOTSTRAP_NODE = "https://crcurrncy.onrender.com"


def generate_key_from_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def save_seed_phrase_to_file(seed_phrase):
    with open('seed_phrase.txt', 'w') as f:
        f.write(seed_phrase)
    print(f"Seed phrase saved to seed_phrase.txt.")

def load_seed_phrase_from_file():
    global SEED_PHRASE
    if os.path.exists('seed_phrase.txt'):
        with open('seed_phrase.txt', 'r') as f:
            SEED_PHRASE = f.read().strip()
            return True
    return False

def generate_wallet():
    global ENCRYPTED_PRIVATE_KEY, PUBLIC_KEY, WALLET_ADDRESS, SALT, SEED_PHRASE, GENERATED_PASSWORD
    
    characters = string.ascii_letters + string.digits + string.punctuation
    GENERATED_PASSWORD = ''.join(random.choice(characters) for i in range(16))

    mnemo = Mnemonic("english")
    SEED_PHRASE = mnemo.generate(strength=128)
    save_seed_phrase_to_file(SEED_PHRASE)

    seed = mnemo.to_seed(SEED_PHRASE)
    
    private_key_obj = SigningKey.from_string(seed[:32], curve=SECP256k1)
    private_key = private_key_obj.to_string().hex()
    
    SALT = os.urandom(16)
    key = generate_key_from_password(GENERATED_PASSWORD, SALT)
    f = Fernet(key)
    ENCRYPTED_PRIVATE_KEY = f.encrypt(private_key.encode()).decode()
    
    public_key_obj = private_key_obj.get_verifying_key()
    PUBLIC_KEY = public_key_obj.to_string().hex()
    WALLET_ADDRESS = hashlib.sha256(PUBLIC_KEY.encode()).hexdigest()
    
    print(f"New wallet created. Address: {WALLET_ADDRESS}")
    print(f"Generated Seed Phrase: {SEED_PHRASE}")
    print(f"Generated Password: {GENERATED_PASSWORD}")

def save_block_to_db(block):
    cnxn = get_db_connection()
    if not cnxn: return False

    cursor = cnxn.cursor()
    
    try:
        cursor.execute("""
            INSERT INTO blocks (block_hash, block_index, previous_hash, timestamp, nonce)
            VALUES (?, ?, ?, ?, ?)
        """, (block.hash, block.index, block.previous_hash, block.timestamp, block.nonce))
        
        block_id = cursor.lastrowid
        
        for tx in block.transactions:
            cursor.execute("""
                INSERT INTO transactions (block_id, sender, recipient, amount, fee, signature, public_key, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (block_id, tx.get('from', ''), tx.get('to', ''), tx.get('amount', 0), tx.get('fee', 0), tx.get('signature', ''), tx.get('public_key', ''), time.time()))

        cnxn.commit()
        return True
    except sqlite3.IntegrityError:
        print("Block already exists in the database.")
        return False
    finally:
        cursor.close()
        cnxn.close()

def get_last_block():
    cnxn = get_db_connection()
    if not cnxn: return None

    cursor = cnxn.cursor()
    try:
        cursor.execute("SELECT id, block_hash, block_index, previous_hash, timestamp, nonce FROM blocks ORDER BY block_index DESC LIMIT 1")
        row = cursor.fetchone()
    except sqlite3.OperationalError:
        row = None
    finally:
        cursor.close()
        cnxn.close()
    
    if row:
        block_id, block_hash, block_index, previous_hash, timestamp, nonce = row
        
        cnxn_tx = get_db_connection()
        if not cnxn_tx: return None
        tx_cursor = cnxn_tx.cursor()
        
        transactions = []
        try:
            tx_cursor.execute("SELECT sender, recipient, amount, fee, signature, public_key FROM transactions WHERE block_id = ?", (block_id,))
            for tx_row in tx_cursor.fetchall():
                transactions.append({
                    'from': tx_row[0],
                    'to': tx_row[1],
                    'amount': tx_row[2],
                    'fee': tx_row[3],
                    'signature': tx_row[4],
                    'public_key': tx_row[5]
                })
        except sqlite3.OperationalError:
            pass
        finally:
            tx_cursor.close()
            cnxn_tx.close()
        
        block_data = {
            'hash': block_hash,
            'index': block_index,
            'previous_hash': previous_hash,
            'timestamp': timestamp,
            'nonce': nonce,
            'transactions': transactions
        }
        return Block(**block_data)
    return None

def get_balance(address):
    cnxn = get_db_connection()
    if not cnxn: return 0

    cursor = cnxn.cursor()
    
    try:
        cursor.execute("""
            SELECT SUM(CASE WHEN recipient = ? THEN amount ELSE -amount-fee END)
            FROM transactions
            WHERE sender = ? OR recipient = ?
        """, (address, address, address))
        row = cursor.fetchone()
        balance = float(row[0]) if row[0] is not None else 0
    except sqlite3.OperationalError:
        balance = 0
    finally:
        cursor.close()
        cnxn.close()
    
    for tx in PENDING_TRANSACTIONS:
        if tx.get("to") == address:
            balance += tx.get("amount")
        if tx.get("from") == address:
            balance -= tx.get("amount") + tx.get("fee", 0)
    
    return balance

def sign_transaction(private_key, transaction_data):
    try:
        signing_key = SigningKey.from_string(bytes.fromhex(private_key), curve=SECP256k1)
        transaction_json = json.dumps(transaction_data, sort_keys=True).encode('utf-8')
        signature = signing_key.sign(transaction_json).hex()
        return signature
    except Exception as e:
        print(f"Failed to sign transaction: {e}")
        return None

def verify_signature(public_key, transaction_data, signature):
    try:
        verifying_key = VerifyingKey.from_string(bytes.fromhex(public_key), curve=SECP256k1)
        transaction_json = json.dumps(transaction_data, sort_keys=True).encode('utf-8')
        return verifying_key.verify(bytes.fromhex(signature), transaction_json)
    except Exception as e:
        print(f"Failed to verify signature: {e}")
        return False

def broadcast_pending_transactions():
    for peer in list(PEERS):
        try:
            requests.post(f"{peer}/pending_transactions", json={"transactions": PENDING_TRANSACTIONS})
        except requests.exceptions.ConnectionError as e:
            print(f"Failed to broadcast to {peer}: {e}. Removing node from list.")
            PEERS.discard(peer)

def broadcast_block(new_block):
    print("Broadcasting block to all connected nodes.")
    for peer in list(PEERS):
        try:
            requests.post(f"{peer}/add_block", json=new_block.__dict__)
        except requests.exceptions.ConnectionError as e:
            print(f"Failed to broadcast to {peer}: {e}. Removing node from list.")
            PEERS.discard(peer)

def get_chain_length():
    cnxn = get_db_connection()
    if not cnxn: return 0
    cursor = cnxn.cursor()
    try:
        cursor.execute("SELECT COUNT(*) FROM blocks")
        length = cursor.fetchone()[0]
    except sqlite3.OperationalError:
        length = 0
    finally:
        cursor.close()
        cnxn.close()
    return length

def is_valid_chain(chain_data):
    if len(chain_data) == 0:
        return False
    
    if chain_data[0]['index'] != 0 or chain_data[0]['previous_hash'] != "0":
        return False

    for i in range(1, len(chain_data)):
        current_block = Block(**chain_data[i])
        previous_block = Block(**chain_data[i-1])
        
        if current_block.previous_hash != previous_block.hash:
            return False
            
    return True

def resolve_conflicts():
    longest_chain = None
    max_length = get_chain_length()
    
    print("Starting blockchain conflict resolution.")
    
    for peer in list(PEERS):
        try:
            response = requests.get(f"{peer}/get_blockchain")
            if response.status_code == 200:
                data = response.json()
                chain_data = data.get('blockchain')
                
                if len(chain_data) > max_length:
                    max_length = len(chain_data)
                    longest_chain = chain_data
        except requests.exceptions.ConnectionError as e:
            print(f"Failed to connect to {peer}: {e}. Removing node from list.")
            PEERS.discard(peer)
            
    if longest_chain and is_valid_chain(longest_chain):
        cnxn = get_db_connection()
        if not cnxn: return
        cursor = cnxn.cursor()
        
        cursor.execute("DELETE FROM transactions")
        cursor.execute("DELETE FROM blocks")
        
        for block_data in longest_chain:
            block = Block(**block_data)
            save_block_to_db(block)
        
        cnxn.commit()
        cnxn.close()
        
        print("Replaced local chain with the longest one.")
    else:
        print("Local chain is the longest or no longer chain is available.")
        
def get_blockchain_data():
    cnxn = get_db_connection()
    if not cnxn: return []

    cursor = cnxn.cursor()
    try:
        cursor.execute("SELECT id, block_hash, block_index, previous_hash, timestamp, nonce FROM blocks ORDER BY block_index ASC")
        chain_data = []
        for row in cursor.fetchall():
            block_id, block_hash, block_index, previous_hash, timestamp, nonce = row
            
            tx_cursor = cnxn.cursor()
            tx_cursor.execute("SELECT sender, recipient, amount, fee, signature, public_key FROM transactions WHERE block_id = ?", (block_id,))
            transactions = []
            for tx_row in tx_cursor.fetchall():
                transactions.append({
                    'from': tx_row[0],
                    'to': tx_row[1],
                    'amount': tx_row[2],
                    'fee': tx_row[3],
                    'signature': tx_row[4],
                    'public_key': tx_row[5]
                })
            tx_cursor.close()
            
            block_data = {
                'index': block_index,
                'hash': block_hash,
                'previous_hash': previous_hash,
                'timestamp': timestamp,
                'nonce': nonce,
                'transactions': transactions
            }
            chain_data.append(block_data)
    except sqlite3.OperationalError:
        chain_data = []
    finally:
        cursor.close()
        cnxn.close()
    return chain_data

def create_genesis_block():
    last_block = get_last_block()
    if not last_block:
        genesis_transactions = [
            {"from": "Genesis", "to": WALLET_ADDRESS, "amount": 100, "fee": 0, "signature": "0", "public_key": "0"}
        ]
        genesis_block = Block(0, genesis_transactions, "0")
        if save_block_to_db(genesis_block):
            print("Genesis Block created successfully.")
        else:
            print("Failed to create Genesis Block.")

def join_network():
    print("Attempting to join the network...")
    global NODE_ADDRESS, LAST_MINED_TIME, SQLCIPHER_KEY, GENERATED_PASSWORD, SEED_PHRASE

    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        NODE_ADDRESS = f"http://{s.getsockname()[0]}:5000"
    except Exception:
        NODE_ADDRESS = "http://127.0.0.1:5000"
    finally:
        s.close()
    
    print(f"Current node address: {NODE_ADDRESS}")
    
    if not os.path.exists(DB_FILE) or not os.path.exists('seed_phrase.txt'):
        print("No database or seed phrase found. Creating a new wallet...")
        
        generate_wallet()
        SQLCIPHER_KEY = generate_db_key(GENERATED_PASSWORD, SEED_PHRASE)
        
        setup_database()
        create_genesis_block()
        
        LAST_MINED_TIME = time.time()
        print("Network setup successful.")
    else:
        print("Database and seed phrase found. Please recover your wallet to open it.")
    
    try:
        if BOOTSTRAP_NODE != NODE_ADDRESS and SQLCIPHER_KEY:
            response = requests.post(
                f"{BOOTSTRAP_NODE}/register_node",
                json={"address": NODE_ADDRESS}
            )
            if response.status_code == 201:
                data = response.json()
                global PEERS
                
                received_chain = data.get('blockchain')
                if len(received_chain) > get_chain_length() and is_valid_chain(received_chain):
                    threading.Thread(target=resolve_conflicts).start()
                
                received_peers = set(data.get('peers'))
                PEERS.update(received_peers)
                PEERS.discard(NODE_ADDRESS)
                print("Peer list synchronized successfully.")

                broadcast_self_address()
            else:
                print(f"Failed to join network: {response.text}")
    except requests.exceptions.ConnectionError:
        print("Failed to connect to bootstrap node. Starting network as the first node.")
        if get_last_block() is None:
            create_genesis_block()
        LAST_MINED_TIME = time.time()


def broadcast_self_address():
    for peer in list(PEERS):
        try:
            requests.post(f"{peer}/register_node", json={"address": NODE_ADDRESS})
        except requests.exceptions.ConnectionError as e:
            print(f"Failed to broadcast node address to {peer}: {e}. Removing node.")
            PEERS.discard(peer)

@app.route('/')
def index():
    global WALLET_ADDRESS, SEED_PHRASE, SQLCIPHER_KEY
    node_peers = list(PEERS)
    
    chain_info = {"length": 0, "last_block": None}
    balance = 0
    
    if SQLCIPHER_KEY:
        chain_info['length'] = get_chain_length()
        last_block = get_last_block()
        if last_block:
            chain_info['last_block'] = last_block.__dict__
        if WALLET_ADDRESS:
            balance = get_balance(WALLET_ADDRESS)
        else:
            balance = "Wallet must be recovered first"
            
    seed_phrase_message = "Seed phrase is not available here for security reasons."
    if SEED_PHRASE:
        seed_phrase_message = "Seed phrase saved to an external file. Not displayed here."
    
    return render_template_string(HTML_TEMPLATE, peers=node_peers, chain_info=chain_info, wallet_address=WALLET_ADDRESS, balance=balance, pending_txs=PENDING_TRANSACTIONS, seed_phrase=seed_phrase_message)

@app.route('/get_status', methods=['GET'])
def get_status():
    global LAST_MINED_TIME, SQLCIPHER_KEY
    
    if not SQLCIPHER_KEY:
        return jsonify({"message": "Wallet must be recovered first."}), 401
    
    time_left = 0
    if time.time() - LAST_MINED_TIME < LAST_MINED_Timer and LAST_MINED_TIME != 0:
        time_left = int(LAST_MINED_Timer - (time.time() - LAST_MINED_TIME))

    last_block = get_last_block()
    chain_info = {
        "length": get_chain_length(),
        "last_block": last_block.__dict__ if last_block else None
    }
    
    response = {
        "wallet_address": WALLET_ADDRESS,
        "balance": get_balance(WALLET_ADDRESS),
        "peers": list(PEERS),
        "pending_txs": PENDING_TRANSACTIONS,
        "chain_info": chain_info,
        "time_left": time_left
    }
    return jsonify(response), 200

@app.route('/recover_wallet', methods=['POST'])
def recover_wallet():
    global ENCRYPTED_PRIVATE_KEY, SALT, WALLET_ADDRESS, PUBLIC_KEY, SQLCIPHER_KEY
    data = request.get_json()
    seed_phrase = data.get('seed_phrase')
    new_password = data.get('new_password')

    if not seed_phrase or not new_password:
        return jsonify({"message": "Seed phrase and new password are required."}), 400

    mnemo = Mnemonic("english")
    if not mnemo.check(seed_phrase):
        return jsonify({"message": "Invalid seed phrase."}), 400

    try:
        seed = mnemo.to_seed(seed_phrase)
        private_key_obj = SigningKey.from_string(seed[:32], curve=SECP256k1)
        private_key = private_key_obj.to_string().hex()

        SALT = os.urandom(16)
        key = generate_key_from_password(new_password, SALT)
        f = Fernet(key)
        ENCRYPTED_PRIVATE_KEY = f.encrypt(private_key.encode()).decode()

        public_key_obj = private_key_obj.get_verifying_key()
        PUBLIC_KEY = public_key_obj.to_string().hex()
        WALLET_ADDRESS = hashlib.sha256(PUBLIC_KEY.encode()).hexdigest()

        SQLCIPHER_KEY = generate_db_key(new_password, seed_phrase)
        
        setup_database()
        
        return jsonify({"message": f"Wallet recovered successfully. Your new address is: {WALLET_ADDRESS}"}), 200
    
    except Exception as e:
        return jsonify({"message": f"An error occurred during recovery: {str(e)}"}), 500

@app.route('/new_transaction', methods=['POST'])
def new_transaction():
    global ENCRYPTED_PRIVATE_KEY, SALT, PENDING_TRANSACTIONS, WALLET_ADDRESS, PUBLIC_KEY, SQLCIPHER_KEY

    if not SQLCIPHER_KEY:
        return jsonify({"message": "Wallet must be recovered first."}), 401

    tx_data = request.get_json()
    required = ["to", "amount", "password"]
    if not all(k in tx_data for k in required):
        return jsonify({"message": "Transaction data is incomplete. Please enter the password."}), 400

    password = tx_data["password"]
    del tx_data["password"]

    tx_data["from"] = WALLET_ADDRESS
    tx_data["fee"] = 0.1
    if get_balance(WALLET_ADDRESS) < tx_data["amount"] + tx_data["fee"]:
        return jsonify({"message": "Insufficient balance for this transaction."}), 400
    
    try:
        if not ENCRYPTED_PRIVATE_KEY or not SALT:
            return jsonify({"message": "Wallet must be recovered first using a seed phrase and password."}), 401
        
        key = generate_key_from_password(password, SALT)
        f = Fernet(key)
        decrypted_private_key = f.decrypt(ENCRYPTED_PRIVATE_KEY.encode()).decode()
        
    except Exception as e:
        return jsonify({"message": "Incorrect password. Failed to sign transaction."}), 401

    signature = sign_transaction(decrypted_private_key, tx_data)
    del decrypted_private_key
    if not signature:
        return jsonify({"message": "Failed to generate digital signature."}), 500
    
    tx_data["signature"] = signature
    tx_data["public_key"] = PUBLIC_KEY

    PENDING_TRANSACTIONS.append(tx_data)
    broadcast_pending_transactions()
    
    return jsonify({"message": "Transaction added successfully. Waiting to be mined."}), 201

@app.route('/pending_transactions', methods=['POST'])
def receive_pending_transactions():
    global PENDING_TRANSACTIONS, SQLCIPHER_KEY

    if not SQLCIPHER_KEY:
        return jsonify({"message": "Wallet must be recovered first."}), 401

    transactions = request.get_json().get('transactions')
    if not transactions:
        return jsonify({"message": "No transactions to add."}), 400
    
    for tx in transactions:
        signature = tx.get('signature')
        public_key = tx.get('public_key')
        if not signature or not public_key:
            print("Invalid transaction: No signature or public key.")
            continue
            
        temp_tx = tx.copy()
        del temp_tx['signature']
        del temp_tx['public_key']
        
        if verify_signature(public_key, temp_tx, signature):
            PENDING_TRANSACTIONS.append(tx)
            print("New valid transaction received.")
        else:
            print("Received an invalid transaction: signature verification failed.")

    return jsonify({"message": f"Received {len(transactions)} new transactions."}), 200

@app.route('/mine', methods=['POST'])
def mine_and_broadcast():
    global PENDING_TRANSACTIONS, LAST_MINED_TIME, WALLET_ADDRESS, SQLCIPHER_KEY

    if not SQLCIPHER_KEY:
        return jsonify({"message": "Wallet must be recovered first."}), 401
    
    if time.time() - LAST_MINED_TIME < LAST_MINED_Timer and LAST_MINED_TIME != 0:
        time_left = int(LAST_MINED_Timer - (time.time() - LAST_MINED_TIME))
        minutes = time_left // 60
        seconds = time_left % 60
        return jsonify({"message": f"You must wait 3 minutes between mining. Time remaining: {minutes} minutes and {seconds} seconds."}), 400

    last_block = get_last_block()
    if not last_block:
        return jsonify({"message": "Cannot mine. The chain is empty."}), 400
        
    mining_reward = 10
    new_transactions = [{"from": "Mining Reward", "to": WALLET_ADDRESS, "amount": mining_reward, "fee": 0, "signature": "0", "public_key": "0"}]
    new_transactions.extend(PENDING_TRANSACTIONS)
    
    new_block = Block(last_block.index + 1, new_transactions, last_block.hash)
    
    print("Starting automated mining...")
    nonce = 0
    while True:
        new_block.nonce = nonce
        new_hash = new_block.calculate_hash()
        if new_hash.startswith(new_hashstartswith): 
            new_block.hash = new_hash
            print(f"Nonce found: {nonce} with hash: {new_hash}")
            break
        nonce += 1
    
    if not save_block_to_db(new_block):
        return jsonify({"message": "Failed to save block to the database."}), 500
        
    PENDING_TRANSACTIONS = []
    LAST_MINED_TIME = time.time()
    
    broadcast_block(new_block)
    
    return jsonify({
        "message": f"Mining successful! You earned a reward of {mining_reward}.",
        "nonce_count": nonce
    }), 201

@app.route('/add_block', methods=['POST'])
def add_block_endpoint():
    global PENDING_TRANSACTIONS, SQLCIPHER_KEY

    if not SQLCIPHER_KEY:
        return jsonify({"message": "Wallet must be recovered first."}), 401

    new_block_data = request.get_json()
    last_block = get_last_block()
    if not last_block or new_block_data.get('previous_hash') != last_block.hash:
        print("Failed to add block. Previous hash is incorrect. Resolving conflict...")
        threading.Thread(target=resolve_conflicts).start()
        return jsonify({"message": "Failed to add block. Resolving conflict."}), 400

    new_block = Block(
        new_block_data['index'],
        new_block_data['transactions'],
        new_block_data['previous_hash'],
        nonce=new_block_data['nonce'],
        hash=new_block_data['hash']
    )
    
    if not save_block_to_db(new_block):
        return jsonify({"message": "Failed to save block to the database."}), 500

    for tx in new_block_data['transactions']:
        if tx in PENDING_TRANSACTIONS:
            PENDING_TRANSACTIONS.remove(tx)
    
    print(f"New block added successfully. Block number: {new_block.index}")
    return jsonify({"message": "Block added successfully."}), 200

@app.route('/get_blockchain', methods=['GET'])
def get_blockchain_endpoint():
    global SQLCIPHER_KEY
    if not SQLCIPHER_KEY:
        return jsonify({'message': 'Wallet must be recovered first.'}), 401
    
    chain_data = get_blockchain_data()
    return jsonify({'blockchain': chain_data}), 200

@app.route('/register_node', methods=['POST'])
def register_node():
    node_address = request.get_json().get('address')
    if not node_address:
        return "Node address is required.", 400
    
    PEERS.add(node_address)
    
    peers_to_send = list(PEERS)
    peers_to_send.append(NODE_ADDRESS)
    
    blockchain_data = get_blockchain_data()
    
    response = {
        'message': 'Node registered successfully. Peers and current chain are provided.',
        'blockchain': blockchain_data,
        'peers': peers_to_send
    }
    return jsonify(response), 201

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Blockchain Simulation</title>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;600&display=swap" rel="stylesheet">
    <style>
        body {
            font-family: 'Poppins', sans-serif;
            margin: 0;
            background: #f0f2f5;
            color: #333;
            display: flex;
            min-height: 100vh;
        }
        .sidebar {
            background: #2c3e50;
            color: white;
            padding: 20px;
            width: 280px;
            box-shadow: 2px 0 5px rgba(0,0,0,0.1);
            display: flex;
            flex-direction: column;
        }
        .sidebar-title {
            font-size: 1.5em;
            font-weight: 600;
            margin-bottom: 20px;
            border-bottom: 2px solid #34495e;
            padding-bottom: 10px;
            text-align: center;
        }
        .sidebar-section {
            margin-bottom: 30px;
        }
        .sidebar-section h4 {
            margin-top: 0;
            font-size: 1.2em;
            color: #ecf0f1;
            margin-bottom: 15px;
        }
        .peers-list, .pending-txs-list {
            list-style: none;
            padding: 0;
            margin: 0;
            max-height: 250px;
            overflow-y: auto;
        }
        .peers-list li, .pending-txs-list li {
            background: #34495e;
            margin-bottom: 8px;
            padding: 12px;
            border-radius: 8px;
            font-size: 0.9em;
            word-wrap: break-word;
            transition: background 0.2s ease;
        }
        .peers-list li:hover, .pending-txs-list li:hover {
            background: #4a627a;
        }
        .main-content {
            flex-grow: 1;
            padding: 40px;
            display: flex;
            flex-direction: column;
            gap: 40px;
            overflow-y: auto;
        }
        .card-container {
            display: flex;
            gap: 40px;
        }
        .card {
            background: white;
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.05);
            padding: 30px;
            flex: 1;
            transition: transform 0.3s ease;
        }
        .card:hover {
            transform: translateY(-5px);
        }
        .card-title {
            font-size: 1.5em;
            font-weight: 600;
            margin-bottom: 20px;
            text-align: center;
            color: #2c3e50;
        }
        .card-content p {
            margin: 10px 0;
            font-size: 1em;
            line-height: 1.6;
        }
        .card-content strong {
            color: #555;
        }
        .wallet-address, .last-hash {
            font-family: monospace;
            background: #f9f9f9;
            padding: 8px;
            border-radius: 4px;
            display: block;
            margin-top: 5px;
            font-size: 0.9em;
            word-wrap: break-word;
        }
        .form-section {
            display: flex;
            flex-direction: column;
            gap: 15px;
        }
        input[type="text"], input[type="password"], input[type="number"] {
            width: 100%;
            padding: 12px;
            border: 1px solid #ddd;
            border-radius: 8px;
            font-size: 1em;
            box-sizing: border-box;
            transition: border-color 0.3s ease;
        }
        input:focus {
            outline: none;
            border-color: #3498db;
        }
        .button {
            padding: 12px;
            font-size: 1em;
            font-weight: 600;
            border-radius: 8px;
            border: none;
            cursor: pointer;
            color: white;
            transition: background-color 0.3s ease;
        }
        .button.primary {
            background-color: #2ecc71;
        }
        .button.primary:hover {
            background-color: #27ae60;
        }
        .button.secondary {
            background-color: #3498db;
        }
        .button.secondary:hover {
            background-color: #2980b9;
        }
        .button:disabled {
            background-color: #bdc3c7;
            cursor: not-allowed;
        }
        #status-message, #transfer-message, #recover-message {
            margin-top: 15px;
            font-size: 0.95em;
            font-weight: 600;
            text-align: center;
        }
        #pending-txs-card pre {
            background: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 8px;
            overflow-x: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
            flex-grow: 1;
            margin: 0;
        }
    </style>
</head>
<body>
    <div class="sidebar">
        <div class="sidebar-title">Blockchain Node</div>
        
        <div class="sidebar-section">
            <h4>Connected Peers (<span id="peers_count">{{ peers|length }}</span>)</h4>
            <ul class="peers-list" id="peers_list">
                {% for peer in peers %}
                <li>{{ peer }}</li>
                {% else %}
                <li>No other nodes connected.</li>
                {% endfor %}
            </ul>
        </div>
        
        <div class="sidebar-section">
            <h4>Pending Transactions (<span id="pending_txs_count">{{ pending_txs|length }}</span>)</h4>
            <ul class="pending-txs-list" id="pending_txs_list">
                {% for tx in pending_txs %}
                <li>From: {{ tx.from }}<br>To: {{ tx.to }}<br>Amount: {{ tx.amount }}</li>
                {% else %}
                <li>No pending transactions.</li>
                {% endfor %}
            </ul>
        </div>
    </div>

    <div class="main-content">
        <div class="card-container">
            <div class="card">
                <h3 class="card-title">Wallet Information</h3>
                <div class="card-content">
                    <p><strong>Wallet Address:</strong><br><span id="wallet_address" class="wallet-address">{{ wallet_address }}</span></p>
                    <p><strong>Balance:</strong> <span id="wallet_balance">{{ balance }}</span> coins</p>
                </div>
            </div>
            
            <div class="card">
                <h3 class="card-title">Blockchain Status</h3>
                <div class="card-content">
                    <p><strong>Chain Length:</strong> <span id="chain_length">{{ chain_info.length }}</span> blocks</p>
                    <p><strong>Last Block Hash:</strong><br><span id="last_block_hash" class="last-hash">{{ chain_info.last_block.hash if chain_info.last_block else 'No blocks yet.' }}</span></p>
                </div>
            </div>
        </div>

        <div class="card-container">
            <div class="card">
                <h3 class="card-title">Mine a New Block</h3>
                <div class="form-section">
                    <div id="status-message"></div>
                    <button id="mine-button" class="button primary" onclick="mineBlock()">Start Mining</button>
                    <div id="mining_log"></div>
                </div>
            </div>

            <div class="card">
                <h3 class="card-title">Send Coins</h3>
                <div class="form-section">
                    <input type="text" id="recipient_address" placeholder="Recipient's Address">
                    <input type="number" id="amount" placeholder="Amount">
                    <input type="password" id="password" class="password-input" placeholder="Your Password">
                    <button class="button secondary" onclick="sendTransaction()">Send</button>
                    <div id="transfer_message"></div>
                </div>
            </div>
        </div>

        <div class="card-container">
            <div class="card">
                <h3 class="card-title">Recover Wallet</h3>
                <p style="font-size: 0.9em; color: #888;">Use this to open a wallet or set a new password on startup.</p>
                <div class="form-section">
                    <input type="text" id="recover_seed_phrase" placeholder="Enter seed phrase here">
                    <input type="password" id="recover_new_password" placeholder="Enter new password">
                    <button class="button secondary" onclick="recoverWallet()">Recover</button>
                    <div id="recover_message"></div>
                </div>
            </div>
            
            <div class="card">
                <h3 class="card-title">Last Block Details</h3>
                <pre id="last_block_txs">{{ chain_info.last_block.transactions if chain_info.last_block else 'No blocks yet.' }}</pre>
            </div>
        </div>
    </div>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script>
        function mineBlock() {
            $('#mine-button').prop('disabled', true);
            $('#mining_log').text('Mining in progress...');

            $.ajax({
                url: '/mine',
                type: 'POST',
                contentType: 'application/json',
                data: JSON.stringify({}),
                success: function(data) {
                    $('#mining_log').html(data.message + '<br>' + 'Nonce attempts: ' + data.nonce_count);
                },
                error: function(xhr, status, error) {
                    const response = JSON.parse(xhr.responseText);
                    $('#mining_log').text('Error: ' + response.message);
                },
                complete: function() {
                }
            });
        }
        
        function sendTransaction() {
            const recipient_address = $('#recipient_address').val();
            const amount = parseFloat($('#amount').val());
            const password_input = $('#password');

            if (!recipient_address || isNaN(amount) || amount <= 0) {
                alert('Please enter a valid address and amount.');
                return;
            }

            if (password_input.is(':hidden')) {
                password_input.show();
                password_input.focus();
                return;
            }

            const password = password_input.val();
            if (!password) {
                alert('Please enter your password.');
                return;
            }
            
            const payload = {
                to: recipient_address,
                amount: amount,
                password: password
            };
            
            $.ajax({
                url: '/new_transaction',
                type: 'POST',
                contentType: 'application/json',
                data: JSON.stringify(payload),
                success: function(data) {
                    $('#transfer_message').text(data.message);
                    password_input.val('');
                    password_input.hide();
                },
                error: function(xhr, status, error) {
                    const response = JSON.parse(xhr.responseText);
                    $('#transfer_message').text('Error: ' + response.message);
                }
            });
        }
        
        function recoverWallet() {
            const seedPhrase = $('#recover_seed_phrase').val();
            const newPassword = $('#recover_new_password').val();

            if (!seedPhrase || !newPassword) {
                alert('Please enter both the seed phrase and a new password.');
                return;
            }
            
            const payload = {
                seed_phrase: seedPhrase,
                new_password: newPassword
            };

            $.ajax({
                url: '/recover_wallet',
                type: 'POST',
                contentType: 'application/json',
                data: JSON.stringify(payload),
                success: function(data) {
                    $('#recover_message').text(data.message);
                    $('#recover_seed_phrase').val('');
                    $('#recover_new_password').val('');
                    updateData();
                },
                error: function(xhr, status, error) {
                    const response = JSON.parse(xhr.responseText);
                    $('#recover_message').text('Error: ' + response.message);
                }
            });
        }

        function updateData() {
            $.get('/get_status', function(data) {
                if(data.message && data.message === "Wallet must be recovered first.") {
                    $('#wallet_address').text("Not available");
                    $('#wallet_balance').text("0");
                    $('#chain_length').text("0");
                    $('#last_block_hash').text("No blocks yet.");
                    $('#last_block_txs').text("No blocks yet.");
                    $('#mine-button').prop('disabled', true);
                    $('#status-message').text("Wallet must be recovered first.");
                    return;
                }

                $('#wallet_address').text(data.wallet_address);
                $('#wallet_balance').text(data.balance);
                
                const peersList = data.peers.map(peer => `<li>${peer}</li>`).join('');
                $('#peers_list').html(peersList || '<li>No other nodes connected.</li>');
                $('#peers_count').text(data.peers.length);

                const pendingTxsList = data.pending_txs.map(tx => 
                    `<li>From: ${tx.from}<br>To: ${tx.to}<br>Amount: ${tx.amount}</li>`).join('');
                $('#pending_txs_count').text(data.pending_txs.length);
                $('#pending_txs_list').html(pendingTxsList || '<li>No pending transactions.</li>');
                
                $('#chain_length').text(data.chain_info.length);
                if (data.chain_info.last_block) {
                    $('#last_block_hash').text(data.chain_info.last_block.hash);
                    $('#last_block_txs').text(JSON.stringify(data.chain_info.last_block.transactions, null, 2));
                } else {
                    $('#last_block_hash').text('No blocks yet.');
                    $('#last_block_txs').text('No blocks yet.');
                }
                
                if (data.time_left > 0) {
                    let minutes = Math.floor(data.time_left / 60);
                    let seconds = data.time_left % 60;
                    $('#mine-button').prop('disabled', true);
                    $('#status-message').text('You must wait 3 minutes between mining. Time remaining: ' + minutes + 'm ' + seconds + 's.');
                } else {
                    $('#mine-button').prop('disabled', false);
                    $('#status-message').text('You can now start mining.');
                }
            });
        }

        $(document).ready(function() {
            setInterval(updateData, 1000); 
        });
    </script>
</body>
</html>
"""

if __name__ == "__main__":
    join_network()
    port = int(os.environ.get("PORT", 5000))

    app.run(host='0.0.0.0', port=port, debug=False)
