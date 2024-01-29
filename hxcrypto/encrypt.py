#!/usr/bin/env python
# coding: UTF-8
#

# Copyright (c) 2013-2022 v3aqb

# This file is part of hxcrypto.

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

#
# Copyright (c) 2012 clowwindy
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


import os
import sys
import time
import base64
import hashlib
import random
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes, aead
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from .iv_checker import iv_checker, IVError
try:
    from blake3 import blake3
except ImportError:
    blake3 = None

SS_SUBKEY = "ss-subkey"
SS_SUBKEY_2022 = 'shadowsocks 2022 session subkey'

EXEMPT_LIST = [
    b'GET /',
    b'POST /',
    b'HEAD /',
]


class BufEmptyError(ValueError):
    '''BufEmptyError'''


def random_string_ss(size):
    if random.random() < 0.3:
        init = random.choice(EXEMPT_LIST)
    elif random.random() < 0.5:
        init = base64.b64encode(random_string(6))
    else:
        init = base64.b64encode(random_string(size))[:size]
    return init + random_string(size - len(init))


def random_string(size):
    '''random_string'''
    return os.urandom(size)


def EVP_BytesToKey(password, key_len):
    ''' equivalent to OpenSSL's EVP_BytesToKey() with count 1
        so that we make the same key and iv as nodejs version'''
    if not isinstance(password, bytes):
        password = password.encode('utf8')
    temp = b''
    output = b''
    while len(output) < key_len:
        md5 = hashlib.md5()
        data = password
        if temp:
            data = temp + password
        md5.update(data)
        temp = md5.digest()
        output += temp
    return output[:key_len]


def check(key, method_):
    '''check if method_ is supported'''
    Encryptor(key, method_)  # test if the settings if OK


METHOD_SUPPORTED = {
    # 'id': (key_len, iv/salt_len, is_aead)
    'aes-128-cfb': (16, 16, False),
    'aes-192-cfb': (24, 16, False),
    'aes-256-cfb': (32, 16, False),
    # 'aes-128-ofb': (16, 16, False),
    # 'aes-192-ofb': (24, 16, False),
    # 'aes-256-ofb': (32, 16, False),
    'aes-128-ctr': (16, 16, False),
    'aes-192-ctr': (24, 16, False),
    'aes-256-ctr': (32, 16, False),
    'camellia-128-cfb': (16, 16, False),
    'camellia-192-cfb': (24, 16, False),
    'camellia-256-cfb': (32, 16, False),
    # 'camellia-128-ofb': (16, 16, False),
    # 'camellia-192-ofb': (24, 16, False),
    # 'camellia-256-ofb': (32, 16, False),
    # 'camellia-128-ctr': (16, 16, False),
    # 'camellia-192-ctr': (24, 16, False),
    # 'camellia-256-ctr': (32, 16, False),
    'rc4-md5': (16, 16, False),
    'rc4': (16, 0, False),
    'chacha20-ietf': (32, 12, False),
    'none': (0, 0, False),  # for testing only
    'aes-128-gcm': (16, 16, True),
    'aes-256-gcm': (32, 32, True),
    # 'aes-128-ccm': (16, 16, True),
    # 'aes-256-ccm': (32, 32, True),
    # 'aes-128-ocb-taglen128': (16, 16, True),
    # 'aes-256-ocb-taglen128': (32, 32, True),
    'chacha20-ietf-poly1305': (32, 32, True),
}

if blake3:
    METHOD_SUPPORTED.update({'2022-blake3-aes-128-gcm': (16, 16, True),
                             '2022-blake3-aes-256-gcm': (32, 32, True),
                             '2022-blake3-chacha20-ietf-poly1305': (32, 32, True),
                             })


def is_aead(method_):
    '''return if method_ is AEAD'''
    if method_ not in METHOD_SUPPORTED:
        return False
    return METHOD_SUPPORTED.get(method_)[2]


class plain:
    '''dummy stream cipher'''
    def __init__(self):
        pass

    def update(self, buf):
        '''fake encrypt / decrypt'''
        return buf


class Chacha20IETF:
    '''chacha20-ietf with python-cryptography'''
    def __init__(self, cipher_name, key, iv):
        self._key = key
        self._iv = iv
        assert cipher_name == 'chacha20-ietf'

        # byte counter, not block counter
        self.counter = 0

    def update(self, data):
        '''encrypt / decrypt'''
        data_len = len(data)

        # we can only prepend some padding to make the encryption align to
        # blocks
        padding = self.counter % 64
        if padding:
            data = (b'\0' * padding) + data

        nonce = struct.pack("<i", self.counter // 64) + self._iv

        algorithm = algorithms.ChaCha20(self._key, nonce)
        cipher = Cipher(algorithm, mode=None)
        encryptor = cipher.encryptor()
        cipher_text = encryptor.update(data)

        self.counter += data_len

        return cipher_text[padding:]


def get_cipher(key, method, op_, iv_):
    '''get stream cipher'''
    if method == 'none':
        return plain()
    if method == 'rc4-md5':
        md5 = hashlib.md5()
        md5.update(key)
        md5.update(iv_)
        key = md5.digest()
        method = 'rc4'
    cipher = None

    if method in ('rc4', 'chacha20-ietf'):
        pass
    elif method.endswith('ctr'):
        mode = modes.CTR(iv_)
    elif method.endswith('cfb'):
        mode = modes.CFB(iv_)
    elif method.endswith('ofb'):
        mode = modes.OFB(iv_)
    else:
        raise ValueError('operation mode "%s" not supported!' % method.upper())

    if method == 'rc4':
        cipher = Cipher(algorithms.ARC4(key), None)
    elif method == 'chacha20-ietf':
        return Chacha20IETF(method, key, iv_)
    elif method.startswith('aes'):
        cipher = Cipher(algorithms.AES(key), mode)
    elif method.startswith('camellia'):
        cipher = Cipher(algorithms.Camellia(key), mode)
    else:
        raise ValueError('crypto algorithm "%s" not supported!' % method.upper())

    return cipher.encryptor() if op_ else cipher.decryptor()


class DummyIVChecker:
    def __init__(self):
        pass

    def check(self, key, iv_):
        pass


class EncryptorStream:
    def __init__(self, password, method, check_iv=True, role=2):
        if method not in METHOD_SUPPORTED:
            raise ValueError('encryption method not supported')

        self.iv_checker = iv_checker if check_iv else DummyIVChecker()
        self.role = role  # 0 for ss-client, 1 for ss-server, 2 for plain

        self.method = method
        self.key_len, self.iv_len, _aead = METHOD_SUPPORTED.get(method)
        self._key_len, self._iv_len = self.key_len, self.iv_len  # for backword compatible
        if _aead:
            raise ValueError('AEAD method is not supported by Encryptor class!')

        self.ctx = None
        self.__key = EVP_BytesToKey(password, self.key_len)

        self._encryptor = None
        self._decryptor = None
        self.encrypt_once = self.encrypt

    def encrypt(self, data):
        if not data:
            raise BufEmptyError
        if not self._encryptor:
            for _ in range(5):
                if not self._iv_len:
                    iv_ = b''
                    break
                if self.role == 0:
                    iv_ = random_string_ss(self._iv_len)
                else:
                    iv_ = random_string(self._iv_len)
                try:
                    self.iv_checker.check(self.__key, iv_)
                except IVError:
                    continue
                break
            else:
                raise IVError("unable to create iv")
            self._encryptor = get_cipher(self.__key, self.method, 1, iv_)
            return iv_ + self._encryptor.update(data)
        return self._encryptor.update(data)

    def decrypt(self, data):
        if not data:
            return b''
        if self._decryptor is None:
            iv_ = data[:self._iv_len]
            self.iv_checker.check(self.__key, iv_)
            self._decryptor = get_cipher(self.__key, self.method, 0, iv_)
            data = data[self._iv_len:]
            if not data:
                return b''
        return self._decryptor.update(data)


def Encryptor(password, method, check_iv=True, role=2):
    '''return shadowsocks Encryptor'''
    if is_aead(method):
        subkey = SS_SUBKEY_2022 if method.startswith('2022') else SS_SUBKEY
        return AEncryptorAEAD(password, method, subkey, check_iv, role)
    return EncryptorStream(password, method, check_iv, role)


def AEncryptor(key, method, ctx, check_iv=True, role=2):
    if not is_aead(method):
        method = 'chacha20-ietf-poly1305'
    return AEncryptorAEAD(key, method, ctx, check_iv, role)


if sys.version_info[0] == 3:
    def buffer(buf):
        return buf


def get_aead_cipher(key, method):
    '''get_aead_cipher
       method should be AEAD method'''
    if 'aes' in method:
        if method.endswith('gcm'):
            return aead.AESGCM(key)
        if method.endswith('ccm'):
            return aead.AESCCM(key)
        if 'ocb' in method:
            return aead.AESOCB3(key)
    return aead.ChaCha20Poly1305(key)


def key_expand(key, salt, ctx, key_len):
    if ctx == SS_SUBKEY_2022:
        return blake3(key + salt, derive_key_context=ctx).digest()[:key_len]
    algo = hashes.SHA1() if ctx == SS_SUBKEY else hashes.SHA256()
    if not isinstance(ctx, bytes):
        ctx = ctx.encode()
    hkdf = HKDF(algorithm=algo,
                length=key_len,
                salt=salt,
                info=ctx,
                )
    key = hkdf.derive(key)
    return key


class AEncryptorAEAD:
    '''
    Provide Authenticated Encryption, compatible with shadowsocks AEAD mode.
    '''
    NONCE_LEN = 12
    TAG_LEN = 16

    def __init__(self, key, method, ctx, check_iv=True, role=2):
        if method not in METHOD_SUPPORTED:
            raise ValueError('encryption method not supported')

        self.role = role
        self.key_len, self.iv_len, _aead = METHOD_SUPPORTED.get(method)
        self._key_len, self._iv_len = self.key_len, self.iv_len  # for backword compatible
        if not _aead:
            raise ValueError('non-AEAD method is not supported by AEncryptor_AEAD class!')

        self.method = method

        self.ctx = ctx  # SUBKEY_INFO
        self.__key = key

        self.iv_checker = iv_checker if check_iv else DummyIVChecker()

        if self.ctx == SS_SUBKEY:
            self.encrypt = self.encrypt_ss
            self.__key = EVP_BytesToKey(key, self.key_len)
        elif self.ctx == SS_SUBKEY_2022:
            self.encrypt = self.encrypt_ss
            self.__key = base64.b64decode(key)
        else:
            self.encrypt = self._encrypt
        self.encrypt_once = self._encrypt

        self._encryptor = None
        self._encryptor_nonce = 0

        self._decryptor = None
        self._decryptor_nonce = 0
        self._decryptor_iv = None

    def _encrypt(self, data, associated_data=None):
        '''
        TCP Chunk (after encryption, *ciphertext*)
        +--------------+------------+
        |    *Data*    |  Data_TAG  |
        +--------------+------------+
        |   Variable   |   Fixed    |
        +--------------+------------+
        for shadowsocks AEAD, this method must be called twice:
        first encrypt Data_Len, then encrypt Data
        '''
        if not data:
            raise BufEmptyError
        nonce = struct.pack('<Q', self._encryptor_nonce) + b'\x00\x00\x00\x00'
        self._encryptor_nonce += 1

        if not self._encryptor:
            for _ in range(5):
                if self.ctx in (SS_SUBKEY, SS_SUBKEY_2022):
                    if self.role == 0:
                        iv_ = random_string_ss(self._iv_len)
                    else:
                        iv_ = random_string(self._iv_len)
                else:
                    iv_ = random_string(self._iv_len)
                try:
                    self.iv_checker.check(self.__key, iv_)
                except IVError:
                    continue
                break
            else:
                raise IVError("unable to create iv")
            _encryptor_skey = key_expand(self.__key, iv_, self.ctx, self.key_len)
            self._encryptor = get_aead_cipher(_encryptor_skey, self.method)
            cipher_text = self._encryptor.encrypt(nonce, data, associated_data)
            cipher_text = iv_ + cipher_text
        else:
            cipher_text = self._encryptor.encrypt(nonce, data, associated_data)

        return cipher_text

    def encrypt_ss(self, data):
        if not self._encryptor and self.ctx == SS_SUBKEY_2022:
            if self.role:  # server
                header = b'\1' + struct.pack("!Q", int(time.time()))
                header += self._decryptor_iv + struct.pack("!H", len(data))
                ct1 = self._encrypt(header)
            else:  # client
                header = b'\0' + struct.pack("!Q", int(time.time()))
                header += struct.pack("!H", len(data))
                ct1 = self._encrypt(header)
        else:
            ct1 = self._encrypt(struct.pack("!H", len(data)))
        ct2 = self._encrypt(data)
        return ct1 + ct2

    def decrypt(self, data, associated_data=None):
        if not data:
            raise BufEmptyError

        if self._decryptor is None:
            _decryptor_iv, data = data[:self._iv_len], data[self._iv_len:]
            _decryptor_skey = key_expand(self.__key, _decryptor_iv, self.ctx, self.key_len)
            _decryptor = get_aead_cipher(_decryptor_skey, self.method)
            nonce = struct.pack('<Q', self._decryptor_nonce) + b'\x00\x00\x00\x00'
            buf = _decryptor.decrypt(nonce, data, associated_data)
            self._decryptor = _decryptor
            self._decryptor_iv = _decryptor_iv
            self._decryptor_nonce += 1
            self.iv_checker.check(self.__key, self._decryptor_iv)
            return buf
        if not data:
            return b''
        nonce = struct.pack('<Q', self._decryptor_nonce) + b'\x00\x00\x00\x00'
        buf = self._decryptor.decrypt(nonce, data, associated_data)
        self._decryptor_nonce += 1
        return buf
