'''
ecc.py

This file is part of hxcrypto.

'''

# Copyright (c) 2017-2019 v3aqb

# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
# 02110-1301  USA

import base64
import hashlib
from typing import Union, Optional, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key, \
    load_der_private_key, load_der_public_key, Encoding, PublicFormat, PrivateFormat, NoEncryption


def exchange(peer_public_bytes: bytes, private_key: Optional[Union[EllipticCurvePrivateKey, X448PrivateKey, X25519PrivateKey]] = None) -> Tuple[bytes, bytes]:
    peer_public_key = load_der_public_key(peer_public_bytes)
    public: Union[EllipticCurvePublicKey, X448PublicKey, X25519PublicKey]
    if isinstance(peer_public_key, EllipticCurvePublicKey):
        curve = peer_public_key.curve
        private = private_key if isinstance(private_key, EllipticCurvePrivateKey) else ec.generate_private_key(curve)
        shared_secret = private.exchange(ec.ECDH(), peer_public_key)
        public = private.public_key()
        return public.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo), shared_secret
    if isinstance(peer_public_key, X448PublicKey):
        private448 = private_key if isinstance(private_key, X448PrivateKey) else X448PrivateKey.generate()
        shared_secret = private448.exchange(peer_public_key)
        public = private448.public_key()
        return public.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo), shared_secret
    if isinstance(peer_public_key, X25519PublicKey):
        private25519 = private_key if isinstance(private_key, X25519PrivateKey) else X25519PrivateKey.generate()
        shared_secret = private25519.exchange(peer_public_key)
        public = private25519.public_key()
        return public.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo), shared_secret
    raise ValueError(f'unknown public key <{peer_public_key.__class__.__name__}>')


class Ecc:
    curve = {256: ec.SECP521R1(),
             192: ec.SECP384R1(),
             128: ec.SECP256R1(),
             32: ec.SECP521R1(),
             24: ec.SECP384R1(),
             16: ec.SECP256R1(),
             }

    def __init__(self, key_len=128, from_file: Optional[str] = None):
        if from_file:
            with open(from_file, 'rb') as key_file:
                data = key_file.read()
            if data.startswith(b'-----'):
                self.ec_private = load_pem_private_key(data, None)
            else:
                self.ec_private = load_der_private_key(data, None)
        else:
            if key_len in self.curve:
                self.ec_private = ec.generate_private_key(self.curve[key_len])
            elif key_len == 25519:
                self.ec_private = X25519PrivateKey.generate()
            elif key_len == 448:
                self.ec_private = X448PrivateKey.generate()
        self.ec_public = self.ec_private.public_key()

    def get_pub_key(self) -> bytes:
        '''get public key'''
        return self.ec_public.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    def get_pub_key_b64u(self) -> str:
        return base64.urlsafe_b64encode(self.get_pub_key()).decode()

    def get_dh_key(self, other: bytes) -> bytes:
        '''ECDH exchange'''
        peer_public_key = load_der_public_key(other)
        if isinstance(peer_public_key, EllipticCurvePublicKey) and isinstance(self.ec_private, EllipticCurvePrivateKey):
            return self.ec_private.exchange(ec.ECDH(), peer_public_key)
        return self.ec_private.exchange(peer_public_key)  # type: ignore[arg-type, call-arg, union-attr]

    def get_dh_key_b64u(self, other: str) -> bytes:
        return self.get_dh_key(base64.urlsafe_b64decode(other))

    def save(self, path: str) -> None:
        '''save private key to file'''
        data = self.ec_private.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        with open(path, 'wb') as write_to:
            write_to.write(data)

    def sign(self, data: bytes, hash_algo: str) -> bytes:
        '''Sign the given digest using ECDSA. Returns a signature.'''
        if isinstance(self.ec_private, EllipticCurvePrivateKey):
            signature = self.ec_private.sign(data, ec.ECDSA(getattr(hashes, hash_algo)()))
        else:
            signature = self.ec_private.sign(data)  # type: ignore[call-arg, union-attr]
        return signature

    def verify(self, data, signature, hash_algo) -> None:
        '''Verify the given digest using ECDSA.
           raise Exception if NOT verified.
        '''
        if isinstance(self.ec_public, EllipticCurvePublicKey):
            self.ec_public.verify(signature, data, ec.ECDSA(getattr(hashes, hash_algo)()))
        else:
            self.ec_public.verify(signature, data)  # type: ignore[call-arg, union-attr]

    @staticmethod
    def b64u_to_hash(data: bytes) -> str:
        data = base64.urlsafe_b64decode(data)
        hash_ = hashlib.md5(data).digest()
        return base64.urlsafe_b64encode(hash_).decode()[:8]

    @staticmethod
    def verify_with_pub_key(pubkey, data: bytes, signature: bytes, hash_algo: str) -> None:
        '''Verify the given digest using pubkey.
           raise Exception if NOT verified.
        '''
        pubkey = load_der_public_key(pubkey)
        if isinstance(pubkey, EllipticCurvePublicKey):
            pubkey.verify(signature, data, ec.ECDSA(getattr(hashes, hash_algo)()))
        else:
            pubkey.verify(signature, data)

    @staticmethod
    def save_pub_key(pubkey, path: str) -> None:
        '''save public key to path'''
        pubk = load_der_public_key(pubkey)
        data = pubk.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        with open(path, 'wb') as write_to:
            write_to.write(data)
