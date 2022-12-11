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
        "-e",
        "--email",
        type=str,
        required=True,
        help="registered client email"
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

KEY_SIZE = 16

class HMAC:
    def __init__(self, mac=None):
        self.mac = os.urandom(KEY_SIZE) if mac is None else mac
        self.hmac = hmac.HMAC(self.mac, hashes.SHA256())

    def execute(self, message, finalize=True):
        self.hmac.update(message)
        if finalize:
            return self.hmac.finalize()

    def verify(self, signature):
        self.hmac.verify(signature)

class AES:
    def __init__(self, key=None, iv=None):
        self.key = os.urandom(KEY_SIZE) if key is None else key
        self.iv = os.urandom(KEY_SIZE) if iv is None else iv

        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CTR(self.iv),
            backend=default_backend()
        )

        self.encryptor = cipher.encryptor()
        self.decryptor = cipher.decryptor()

    def encrypt(self, message):
        return self.encryptor.update(message) + self.encryptor.finalize()

    def decrypt(self, message):
        return self.decryptor.update(message) + self.decryptor.finalize()

# ====== #
# Script #
# ====== #

cmd_args = get_cmd_args()
credentials = json.dumps({
    'email' : cmd_args.email,
    'password' : cmd_args.password
})

aes_manager = AES()
hmac_manager = HMAC()

session_keys = aes_manager.key + hmac_manager.mac + aes_manager.iv
cyphertext = aes_manager.encrypt(credentials.encode('utf-8'))
signature = hmac_manager.execute(cyphertext)

payload = {
    'session_keys': bytearr_to_b64(session_keys),
    'cyphertext'  : bytearr_to_b64(cyphertext),
    'hmac'        : bytearr_to_b64(signature),
}

res = requests.post(
    'http://localhost:5000/signin',
    headers={ 'Content-Type': 'application/json' },
    data=json.dumps(payload)
)

print('\nConteúdo da requisição:', payload, sep='\n')

if res.status_code == 200:
    print(f'\n[{res.status_code}] Login bem sucedido:')
    print('ID da sessão:', res.request._cookies.get('session_id'), end='\n\n')
else:
    print(f'\n[{res.status_code}] Resposta inesperada:')
    print(res.json(), end='\n\n')
