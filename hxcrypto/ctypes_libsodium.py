'''
provide libsodium support for openssl < 1.1.0

not needed on windows
'''

# Copyright (c) 2017-2019 v3aqb

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

# Copyright (c) 2014 clowwindy
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

from __future__ import absolute_import, division, print_function, \
    with_statement

import logging
from ctypes import CDLL, c_char_p, c_int, c_ulonglong, c_uint, byref, \
    create_string_buffer, c_void_p

from cryptography.exceptions import InvalidTag

LIBSODIUM = None
LOADED = False

# for salsa20 and chacha20
BLOCK_SIZE = 64


def set_logger():
    '''
    set logger
    '''
    logger = logging.getLogger('ctypes_libsodium')
    logger.setLevel(logging.INFO)
    hdr = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s',
                                  datefmt='%H:%M:%S')
    hdr.setFormatter(formatter)
    logger.addHandler(hdr)


set_logger()


def find_library(possible_lib_names, search_symbol, library_name):
    '''
    find_library
    '''
    import ctypes.util

    paths = []

    if isinstance(possible_lib_names, str):
        possible_lib_names = [possible_lib_names]

    lib_names = []
    for lib_name in possible_lib_names:
        lib_names.append(lib_name)
        lib_names.append('lib' + lib_name)

    for name in lib_names:
        path = ctypes.util.find_library(name)
        if path:
            paths.append(path)

    if not paths:
        # We may get here when find_library fails because, for example,
        # the user does not have sufficient privileges to access those
        # tools underlying find_library on linux.
        import glob

        for name in lib_names:
            patterns = [
                '/usr/local/lib*/lib%s.*' % name,
                '/usr/lib*/lib%s.*' % name,
                'lib%s.*' % name,
                ]

            for pat in patterns:
                files = glob.glob(pat)
                if files:
                    paths.extend(files)

    logger = logging.getLogger('ctypes_libsodium')
    for path in paths:
        try:
            lib = CDLL(path)
            if hasattr(lib, search_symbol):
                logger.info('loading %s from %s', library_name, path)
                return lib
            logger.warning('can\'t find symbol %s in %s', search_symbol, path)
        except OSError:
            pass
    return None


def load_libsodium():
    '''load_libsodium'''
    global LOADED, LIBSODIUM

    LIBSODIUM = find_library('sodium', 'crypto_stream_salsa20_xor_ic', 'libsodium')

    if LIBSODIUM is None:
        raise OSError('libsodium not found')

    if LIBSODIUM.sodium_init() < 0:
        raise OSError('libsodium init failed')

    LIBSODIUM.sodium_init.restype = c_int
    LIBSODIUM.crypto_stream_salsa20_xor_ic.restype = c_int
    LIBSODIUM.crypto_stream_salsa20_xor_ic.argtypes = (c_void_p, c_char_p,
                                                       c_ulonglong,
                                                       c_char_p, c_ulonglong,
                                                       c_char_p)
    LIBSODIUM.crypto_stream_chacha20_xor_ic.restype = c_int
    LIBSODIUM.crypto_stream_chacha20_xor_ic.argtypes = (c_void_p, c_char_p,
                                                        c_ulonglong,
                                                        c_char_p, c_ulonglong,
                                                        c_char_p)

    LIBSODIUM.crypto_stream_chacha20_ietf_xor_ic.restype = c_int
    LIBSODIUM.crypto_stream_chacha20_ietf_xor_ic.argtypes = (
        c_void_p, c_char_p,
        c_ulonglong,
        c_char_p,
        c_uint,  # uint32_t initial counter
        c_char_p
    )

    LIBSODIUM.crypto_aead_chacha20poly1305_ietf_encrypt.restype = c_int
    LIBSODIUM.crypto_aead_chacha20poly1305_ietf_encrypt.argtypes = (
        c_void_p, c_void_p,
        c_char_p, c_ulonglong,
        c_char_p, c_ulonglong,
        c_char_p,
        c_char_p, c_char_p
    )
    LIBSODIUM.crypto_aead_chacha20poly1305_ietf_decrypt.restype = c_int
    LIBSODIUM.crypto_aead_chacha20poly1305_ietf_decrypt.argtypes = (
        c_void_p, c_void_p,
        c_char_p,
        c_char_p, c_ulonglong,
        c_char_p, c_ulonglong,
        c_char_p, c_char_p
    )

    LIBSODIUM.sodium_init()

    LOADED = True


class BaseCrypto(object):
    '''common for SodiumCrypto and SodiumAeadCrypto
    '''
    buf_size = 1024 * 16

    def __init__(self):
        self._buf = create_string_buffer(self.buf_size)

    def expand_buf(self):
        '''expand_buf'''
        self.buf_size = self.buf_size * 2
        self._buf = create_string_buffer(self.buf_size)


class SodiumCrypto(BaseCrypto):
    '''
    stream cipher:
      salsa20
      chacha20
      chacha20-ietf

    '''

    def __init__(self, cipher_name, key, iv):
        if not LOADED:
            load_libsodium()
        self._key = key
        self._key_ptr = c_char_p(key)
        self._iv = iv
        self._iv_ptr = c_char_p(iv)
        if cipher_name == 'salsa20':
            self._cipher = LIBSODIUM.crypto_stream_salsa20_xor_ic
        elif cipher_name == 'chacha20':
            self._cipher = LIBSODIUM.crypto_stream_chacha20_xor_ic
        elif cipher_name == 'chacha20-ietf':
            self._cipher = LIBSODIUM.crypto_stream_chacha20_ietf_xor_ic
        else:
            raise ValueError('Unknown cipher')
        # byte counter, not block counter
        self._counter = 0
        super().__init__()

    def update(self, data):
        '''
        encrypt / decrypt
        '''
        data_len = len(data)

        # we can only prepend some padding to make the encryption align to
        # blocks
        padding = self._counter % BLOCK_SIZE
        while self.buf_size < padding + data_len:
            self.expand_buf()

        if padding:
            data = (b'\0' * padding) + data
        self._cipher(byref(self._buf), c_char_p(data), padding + data_len,
                     self._iv_ptr, self._counter // BLOCK_SIZE, self._key_ptr)
        self._counter += data_len
        # buf is copied to a str object when we access buf.raw
        # strip off the padding
        return self._buf.raw[padding:padding + data_len]


class SodiumAeadCrypto(BaseCrypto):
    '''
    chacha20-ietf-poly1305
    '''

    def __init__(self, cipher_name, key):
        if not LOADED:
            load_libsodium()
        self._key = key
        self._tlen = 16

        if cipher_name == 'chacha20-ietf-poly1305':
            self._encryptor = LIBSODIUM.crypto_aead_chacha20poly1305_ietf_encrypt
            self._decryptor = LIBSODIUM.crypto_aead_chacha20poly1305_ietf_decrypt
        else:
            raise Exception('Unknown cipher')
        super().__init__()

    def encrypt(self, nonce, data, associated):
        '''
        aead encrypt
        '''
        plen = len(data)
        while self.buf_size < plen + self._tlen:
            self.expand_buf()

        cipher_out_len = c_ulonglong(0)
        associated_p = c_char_p(associated) if associated else None
        associated_l = c_ulonglong(len(associated)) if associated else c_ulonglong(0)
        self._encryptor(
            byref(self._buf), byref(cipher_out_len),
            c_char_p(data), c_ulonglong(plen),
            associated_p, associated_l,
            None,
            c_char_p(nonce), c_char_p(self._key)
        )
        if cipher_out_len.value != plen + self._tlen:
            raise Exception("Encrypt failed")

        return self._buf.raw[:cipher_out_len.value]

    def decrypt(self, nonce, data, associated):
        '''
        aead decrypt
        '''
        clen = len(data)
        while self.buf_size < clen:
            self.expand_buf()

        cipher_out_len = c_ulonglong(0)
        associated_p = c_char_p(associated) if associated else None
        associated_l = c_ulonglong(len(associated)) if associated else c_ulonglong(0)
        result = self._decryptor(
            byref(self._buf), byref(cipher_out_len),
            None,
            c_char_p(data), c_ulonglong(clen),
            associated_p, associated_l,
            c_char_p(nonce), c_char_p(self._key)
        )
        if result != 0:
            raise InvalidTag

        if cipher_out_len.value != clen - self._tlen:
            raise Exception("Decrypt failed, length not match")

        return self._buf.raw[:cipher_out_len.value]
