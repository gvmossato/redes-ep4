import os
import argparse
import requests
import json

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from base64 import b64encode

# ===== #
# Utils #
# ===== #

def get_cmd_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-u",
        "--username",
        type=str,
        required=True,
        help="registered client username"
    )
    parser.add_argument(
        "-p",
        "--password",
        type=str,
        required=True,
        help="corresponding client password"
    )
    return parser.parse_args()

def bytearr_to_b64(bytearr):
    return b64encode(bytearr).decode('ascii')

# ============ #
# Cryptography #
# ============ #

KEY_SIZE = 32


class HMAC:
    def __init__(self):
        self.mac = os.urandom(KEY_SIZE)
        self.hmac = hmac.HMAC(self.mac, hashes.SHA256())

    def apply(self, message: bytes):
        self.hmac.update(message)
        return self.hmac.finalize()


class AES:
    def __init__(self):
        self.key = os.urandom(KEY_SIZE)
        self.iv = os.urandom(KEY_SIZE)

        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CTR(self.iv),
            backend=default_backend()
        )

        self.encryptor = cipher.encryptor()
        self.decryptor = cipher.decryptor()

    def encrypt(self, message: bytes):
        self.encryptor.update(message)
        return self.encryptor.finalize()

    def decrypt(self, message: bytes):
        self.decryptor.update(message)
        return self.decryptor.finalize()

# ====== #
# Script #
# ====== #

cmd_args = get_cmd_args()
credentials = json.dumps({
    'username' : cmd_args.username,
    'password' : cmd_args.password
})

aes_manager = AES()
hmac_manager = HMAC()

session_keys = bytearr_to_b64(
    aes_manager.key  +
    hmac_manager.mac +
    aes_manager.iv
)
cyphertext = bytearr_to_b64(
    aes_manager.encrypt(credentials.encode('utf-8'))
)
hmac_b64 = bytearr_to_b64(
    hmac_manager.apply(cyphertext)
)

res = requests.post(
    'http://localhost:5000/login',
    data={
        'session_keys' : session_keys,
        'cyphertext'   : cyphertext,
        'hmac'         : hmac_b64,
    }
)

if res.status_code == 200:
    print('\nLogin bem sucedido:')
    print('Status code:', res.status_code)
    print('ID da sessão:', res.cookies['session_id'])
else:
    print(f'\nResposta inesperada:')
    print('Status code:', res.status_code)
    print(res.json())
