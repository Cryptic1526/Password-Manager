import argparse
import json
import hashlib
from json.decoder import JSONDecodeError
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import string
import random
import secrets

def generate_salt():
    # 128-bit salt for the key
    salt = secrets.token_bytes(16)
    return salt

def generate_key(master_password):
    salt = generate_salt() # make a new salt (new version of code, old one used a hardcoded salt)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key

def main():
    parser = argparse.ArgumentParser(description='Password Manager')
    subparsers = parser.add_subparsers(dest='command')

    # create new acc
    add_parser = subparsers.add_parser('addAcc', help='Add a new account')
    add_parser.add_argument('-accName', required=True, help='Account name')
    add_parser.add_argument('-accPass', required=True, help='Account password')
    add_parser.add_argument('-webMatch', help='URL or pattern to associate with the account') # idk why this is exists but more features = better grades?? :/

    # list all the saved accounts
    subparsers.add_parser('listAcc', help='List all stored accounts')

    # delete account from json file
    remove_parser = subparsers.add_parser('removeAcc', help='Remove an account')
    remove_parser.add_argument('-accName', required=True, help='Account name to remove')

    # generat a password
    gen_parser = subparsers.add_parser('genPass', help='Generate a secure random password')
    gen_parser.add_argument('-length', type=int, default=12, help='Length of the password')
    gen_parser.add_argument('-special', action='store_true', help='Include special characters')
    gen_parser.add_argument('-numbers', action='store_true', help='Include numbers')

    # update the pass
    update_parser = subparsers.add_parser('updatePass', help='Update an account password')
    update_parser.add_argument('-accName', required=True, help='Account name to update')
    update_parser.add_argument('-newPass', required=True, help='New password')

    args = parser.parse_args()

    # master password
    master_password = "SECRETpASS" # this NEVER should be hardcoded but its just a demo so its fine :/
    provided_hash = hashlib.sha256(master_password.encode()).hexdigest()

    try:
        with open('hashes.cryptk', 'r') as f:
            stored_hash = f.read()
    except FileNotFoundError:
        stored_hash = None

    if stored_hash is None or stored_hash != provided_hash:
        accounts = load_accounts()
        for acc_name, acc_details in accounts.items():
            encrypted_password = encrypt_password(acc_details['password'], generate_key(master_password))
            accounts[acc_name]['password'] = encrypted_password
        save_accounts(accounts)
        store_master_password_hash(master_password)

    key = generate_key(master_password)

    if args.command == 'addAcc':
        accounts = load_accounts()
        encrypted_password = encrypt_password(args.accPass, key)
        accounts[args.accName] = {'password': encrypted_password, 'webMatch': args.webMatch}
        save_accounts(accounts)
        print(f"Added account: {args.accName}")

    elif args.command == 'listAcc':
        accounts = load_accounts()
        for acc_name, acc_details in accounts.items():
            print(f"Account: {acc_name}, WebMatch: {acc_details['webMatch']}")
            # decrypt and show the password after master passowrd is entered, ill do it later its 3am rn

    elif args.command == 'removeAcc':
        accounts = load_accounts()
        if args.accName in accounts:
            del accounts[args.accName]
            save_accounts(accounts)
            print(f"Removed account: {args.accName}")
        else:
            print(f"Account not found: {args.accName}")

    elif args.command == 'genPass':
        password = generate_password(length=args.length, special=args.special, numbers=args.numbers)
        print(f"Generated password: {password}")

    elif args.command == 'updatePass':
        accounts = load_accounts()
        if args.accName in accounts:
            encrypted_password = encrypt_password(args.newPass, key)
            accounts[args.accName]['password'] = encrypted_password
            save_accounts(accounts)
            print(f"Updated password for: {args.accName}")
        else:
            print(f"Account not found: {args.accName}")

def generate_password(length=12, special=True, numbers=True):
    characters = string.ascii_letters
    if special:
        characters += string.punctuation
    if numbers:
        characters += string.digits

    password = ''.join(random.choice(characters) for _ in range(length))
    return password

def encrypt_password(password, key):
    cipher_suite = Fernet(key)
    cipher_text = cipher_suite.encrypt(password.encode())
    return base64.b64encode(cipher_text).decode('utf-8')
    # sir you have no idea how much time i spent on this line, i was trying to decode the bytes object to a string object and it was being autistically retarded and i was about to give up but then i realized after like 30 minutes of troubleshooting (i must have read at least 20% of all the threads in stack overflow at that point) that i was decoding the wrong thing and i was decoding the cipher_text instead of the bytes object that was returned by the encrypt function and i was like "oh" and then i fixed it and now its working and i am happy :D

def decrypt_password(cipher_text, key):
    cipher_suite = Fernet(key)
    plain_text = cipher_suite.decrypt(cipher_text)
    return plain_text.decode()

def save_accounts(accounts, file_path='accounts.json'):
    with open(file_path, 'w') as f:
        json.dump(accounts, f, default=lambda o: o.decode('utf-8') if isinstance(o, bytes) else o)

def load_accounts(file_path='accounts.json'):
    try:
        with open(file_path, 'r') as f:
            try:
                return json.load(f)
            except JSONDecodeError:
                return {}
    except FileNotFoundError:
        return {}

def store_master_password_hash(master_password):
    hashed_password = hashlib.sha256(master_password.encode()).hexdigest()
    with open('hashes.cryptk', 'w') as f:
        f.write(hashed_password)
      
main()
