import os
import argparse
import requests
import json

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac, serialization
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
    parser.add_argument(
        "-k",
        "--key",
        type=str,
        required=True,
        help="server rsa public key path"
    )
    return parser.parse_args()

def bytearr_to_b64(bytearr):
    return b64encode(bytearr).decode('ascii')

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding, rsa

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
    def __init__(self, key, iv):
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

class KeySerializer:
    def __init__(self, public_key_path, private_key_path=None):
        self.public_key_path = public_key_path
        self.private_key_path = private_key_path

    def _read_public(self):
        with open(self.public_key_path, "rb") as public_key_file_object:
            public_key = serialization.load_pem_public_key(
                public_key_file_object.read(),
                backend=default_backend()
            )
        return public_key

    def _read_private(self):
        with open(self.private_key_path, "rb") as private_key_file_object:
            private_key = serialization.load_pem_private_key(
                private_key_file_object.read(),
                backend=default_backend(),
                password=None
            )
        return private_key

    def read(self, which):
        readers = {
            'public' : self._read_public,
            'private' : self._read_private,
        }
        return readers[which]()

class Transmission:
    def __init__(
            self,
            server_public_key,
            server_private_key=None,
            aes_key=None,
            mac=None,
            iv=None,
        ):
        self.server_public_key = server_public_key
        self.server_private_key = server_private_key

        self.aes = AES(key=aes_key, iv=iv)
        self.sym_hmac = HMAC(
            mac=self.server_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
        self.assym_hmac = HMAC(mac=mac)

    def send(self, message_bytes):
        sym_keys = self.aes.key + self.aes.iv + self.assym_hmac.mac

        session_keys = self.server_public_key.encrypt(
            sym_keys,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        cyphertext = self.aes.encrypt(message_bytes)
        signature = self.assym_hmac.execute(session_keys + cyphertext)

        payload = {
            'session_keys': bytearr_to_b64(session_keys),
            'cyphertext'  : bytearr_to_b64(cyphertext),
            'hmac'        : bytearr_to_b64(signature),
        }

        print('\nConteúdo da requisição:')
        print(payload)

        return requests.post(
            'http://localhost:5000/signin',
            headers={ 'Content-Type': 'application/octet-stream' },
            data=json.dumps(payload).encode('utf-8')
        )

    def verify(self, received_bytes):
        session_keys = received_bytes['session_keys']
        cyphertext = received_bytes['cyphertext']
        signature = received_bytes['hmac']

        self.assym_hmac.execute(session_keys + cyphertext, finalize=False)
        self.assym_hmac.verify(signature)
        return

    def receive(self, cyphertext):
        return json.loads(self.aes.decrypt(cyphertext).decode('utf-8'))

# ====== #
# Script #
# ====== #

cmd_args = get_cmd_args()

credentials = json.dumps({
    'email' : cmd_args.email,
    'password' : cmd_args.password
}).encode('utf-8')
key_serializer = KeySerializer(public_key_path=cmd_args.key)

transmission = Transmission(server_public_key=key_serializer.read('public'))
res = transmission.send(credentials)

if res.status_code == 200:
    print(f'\n[{res.status_code}] Login bem sucedido:')
    print('ID da sessão:', res.request._cookies.get('session_id'), end='\n\n')
else:
    print(f'\n[{res.status_code}] Resposta inesperada:')
    print(res.json(), end='\n\n')
