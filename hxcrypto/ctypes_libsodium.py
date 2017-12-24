#!/usr/bin/env python

# Copyright (c) 2017-2018 v3aqb

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

import os
import logging
from ctypes import CDLL, c_char_p, c_int, c_ulonglong, c_uint, byref, \
    create_string_buffer, c_void_p

from cryptography.exceptions import InvalidTag

logger = logging.getLogger('ctypes_libsodium')
logger.setLevel(logging.INFO)
hdr = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s %(name)s:%(levelname)s %(message)s',
                              datefmt='%H:%M:%S')
hdr.setFormatter(formatter)
logger.addHandler(hdr)

libsodium = None
loaded = False

buf_size = 1024 * 16

# for salsa20 and chacha20
BLOCK_SIZE = 64


def find_library_nt(name):
    # modified from ctypes.util
    # ctypes.util.find_library just returns first result he found
    # but we want to try them all
    # because on Windows, users may have both 32bit and 64bit version installed
    import glob
    results = []
    for directory in os.environ['PATH'].split(os.pathsep):
        fname = os.path.join(directory, name)
        if os.path.isfile(fname):
            results.append(fname)
        if fname.lower().endswith(".dll"):
            continue
        fname += "*.dll"
        files = glob.glob(fname)
        if files:
            results.extend(files)
    return results


def find_library(possible_lib_names, search_symbol, library_name):
    import ctypes.util

    paths = []

    if type(possible_lib_names) not in (list, tuple):
        possible_lib_names = [possible_lib_names]

    lib_names = []
    for lib_name in possible_lib_names:
        lib_names.append(lib_name)
        lib_names.append('lib' + lib_name)

    for name in lib_names:
        if os.name == "nt":
            paths.extend(find_library_nt(name))
        else:
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
                '%s.dll' % name]

            for pat in patterns:
                files = glob.glob(pat)
                if files:
                    paths.extend(files)
    for path in paths:
        try:
            lib = CDLL(path)
            if hasattr(lib, search_symbol):
                logger.info('loading %s from %s', library_name, path)
                return lib
            else:
                logger.warn('can\'t find symbol %s in %s', search_symbol, path)
        except Exception:
            pass
    return None


def load_libsodium():
    global loaded, libsodium, buf

    libsodium = find_library('sodium', 'crypto_stream_salsa20_xor_ic', 'libsodium')

    if libsodium is None:
        raise Exception('libsodium not found')

    if libsodium.sodium_init() < 0:
        raise Exception('libsodium init failed')

    libsodium.sodium_init.restype = c_int
    libsodium.crypto_stream_salsa20_xor_ic.restype = c_int
    libsodium.crypto_stream_salsa20_xor_ic.argtypes = (c_void_p, c_char_p,
                                                       c_ulonglong,
                                                       c_char_p, c_ulonglong,
                                                       c_char_p)
    libsodium.crypto_stream_chacha20_xor_ic.restype = c_int
    libsodium.crypto_stream_chacha20_xor_ic.argtypes = (c_void_p, c_char_p,
                                                        c_ulonglong,
                                                        c_char_p, c_ulonglong,
                                                        c_char_p)

    libsodium.crypto_stream_chacha20_ietf_xor_ic.restype = c_int
    libsodium.crypto_stream_chacha20_ietf_xor_ic.argtypes = (
        c_void_p, c_char_p,
        c_ulonglong,
        c_char_p,
        c_uint,  # uint32_t initial counter
        c_char_p
    )

    libsodium.crypto_aead_chacha20poly1305_ietf_encrypt.restype = c_int
    libsodium.crypto_aead_chacha20poly1305_ietf_encrypt.argtypes = (
        c_void_p, c_void_p,
        c_char_p, c_ulonglong,
        c_char_p, c_ulonglong,
        c_char_p,
        c_char_p, c_char_p
    )
    libsodium.crypto_aead_chacha20poly1305_ietf_decrypt.restype = c_int
    libsodium.crypto_aead_chacha20poly1305_ietf_decrypt.argtypes = (
        c_void_p, c_void_p,
        c_char_p,
        c_char_p, c_ulonglong,
        c_char_p, c_ulonglong,
        c_char_p, c_char_p
    )

    libsodium.sodium_init()

    buf = create_string_buffer(buf_size)
    loaded = True


class SodiumCrypto(object):
    def __init__(self, cipher_name, key, iv, op):
        if not loaded:
            load_libsodium()
        self.key = key
        self.iv = iv
        self.key_ptr = c_char_p(key)
        self.iv_ptr = c_char_p(iv)
        if cipher_name == 'salsa20':
            self.cipher = libsodium.crypto_stream_salsa20_xor_ic
        elif cipher_name == 'chacha20':
            self.cipher = libsodium.crypto_stream_chacha20_xor_ic
        elif cipher_name == 'chacha20-ietf':
            self.cipher = libsodium.crypto_stream_chacha20_ietf_xor_ic
        else:
            raise Exception('Unknown cipher')
        # byte counter, not block counter
        self.counter = 0

    def update(self, data):
        global buf_size, buf
        l = len(data)

        # we can only prepend some padding to make the encryption align to
        # blocks
        padding = self.counter % BLOCK_SIZE
        while buf_size < padding + l:
            buf_size = buf_size * 2
            buf = create_string_buffer(buf_size)

        if padding:
            data = (b'\0' * padding) + data
        self.cipher(byref(buf), c_char_p(data), padding + l,
                    self.iv_ptr, self.counter // BLOCK_SIZE, self.key_ptr)
        self.counter += l
        # buf is copied to a str object when we access buf.raw
        # strip off the padding
        return buf.raw[padding:padding + l]


class SodiumAeadCrypto(object):
    def __init__(self, cipher_name, key):
        if not loaded:
            load_libsodium()
        self.__key = key
        self._tlen = 16

        if cipher_name == 'chacha20-ietf-poly1305':
            self._encryptor = libsodium.crypto_aead_chacha20poly1305_ietf_encrypt
            self._decryptor = libsodium.crypto_aead_chacha20poly1305_ietf_decrypt
        else:
            raise Exception('Unknown cipher')

    def encrypt(self, nonce, data, associated):
        global buf, buf_size
        plen = len(data)
        while buf_size < plen + self._tlen:
            buf_size = buf_size * 2
            buf = create_string_buffer(buf_size)

        cipher_out_len = c_ulonglong(0)
        associated_p = c_char_p(associated) if associated else None
        associated_l = c_ulonglong(len(associated)) if associated else c_ulonglong(0)
        self._encryptor(
            byref(buf), byref(cipher_out_len),
            c_char_p(data), c_ulonglong(plen),
            associated_p, associated_l,
            None,
            c_char_p(nonce), c_char_p(self.__key)
        )
        if cipher_out_len.value != plen + self._tlen:
            raise Exception("Encrypt failed")

        return buf.raw[:cipher_out_len.value]

    def decrypt(self, nonce, data, associated):
        global buf, buf_size
        clen = len(data)
        while buf_size < clen:
            buf_size = buf_size * 2
            buf = create_string_buffer(buf_size)

        cipher_out_len = c_ulonglong(0)
        associated_p = c_char_p(associated) if associated else None
        associated_l = c_ulonglong(len(associated)) if associated else c_ulonglong(0)
        r = self._decryptor(
            byref(buf), byref(cipher_out_len),
            None,
            c_char_p(data), c_ulonglong(clen),
            associated_p, associated_l,
            c_char_p(nonce), c_char_p(self.__key)
        )
        if r != 0:
            raise InvalidTag

        if cipher_out_len.value != clen - self._tlen:
            raise Exception("Decrypt failed, length not match")

        return buf.raw[:cipher_out_len.value]
