
import os
import time
from hxcrypto import encrypt, Encryptor, is_aead
from hxcrypto.encrypt import AEncryptorAEAD, METHOD_SUPPORTED


def test():
    # disable ivchecker
    class DummyIVChecker(object):
        '''DummyIVChecker'''
        def __init__(self, size, timeout):
            pass

        def check(self, key, iv):
            pass

    encrypt.IV_CHECKER = DummyIVChecker(1, 1)

    print('encrypt and decrypt 20MB data.')
    data = os.urandom(10240)
    lst = sorted(METHOD_SUPPORTED.keys())
    for method in lst:
        if is_aead(method):
            continue
        try:
            cipher = Encryptor(b'123456', method)
            time_log = time.time()
            for _ in range(1024):
                ct1 = cipher.encrypt(data)
                ct2 = cipher.encrypt(data)
                cipher.decrypt(ct1)
                cipher.decrypt(ct2)
            print('%s %ss' % (method, time.time() - time_log))
        except Exception as e:
            print(repr(e))

    print('test AE GCM')
    ae1 = AEncryptorAEAD(b'123456', 'aes-128-gcm', b'ctx')
    ae2 = AEncryptorAEAD(b'123456', 'aes-128-gcm', b'ctx')
    ct1 = ae1.encrypt(b'abcde')
    ct2 = ae1.encrypt(b'fg')
    print(ae2.decrypt(ct1))
    print(ae2.decrypt(ct2))

    for method in lst:
        if is_aead(method):
            try:
                cipher = AEncryptorAEAD(b'123456', method, b'ctx')
                cipher1 = AEncryptorAEAD(b'123456', method, b'ctx')
                time_log = time.time()
                for _ in range(1024):
                    ct1 = cipher.encrypt(data)
                    ct2 = cipher.encrypt(data)
                    cipher1.decrypt(ct1)
                    cipher1.decrypt(ct2)
                print('%s %ss' % (method, time.time() - time_log))
            except Exception as e:
                print(repr(e))


if __name__ == '__main__':
    test()
