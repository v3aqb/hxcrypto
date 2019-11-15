
import os
import time
import traceback

from hxcrypto import encrypt, Encryptor, is_aead, method_supported, AEncryptor


def test_one(method):
    data = os.urandom(10240)
    if is_aead(method):
        cipher = AEncryptor(b'123456', method, b"ctx")
        cipher1 = AEncryptor(b'123456', method, b"ctx")
    else:
        cipher = Encryptor(b'123456', method)
        cipher1 = Encryptor(b'123456', method)
    ct1 = cipher.encrypt(data)
    cipher1.decrypt(ct1)
    time_log = time.time()
    for _ in range(1024):
        ct1 = cipher.encrypt(data)
        ct2 = cipher.encrypt(data)
        cipher1.decrypt(ct1)
        cipher1.decrypt(ct2)
    return time.time() - time_log


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

    lst = sorted(method_supported.keys())
    lst = sorted(lst, key=lambda method: is_aead(method))
    size = max([len(x) for x in lst])
    format_ = '%-{:d}s %.4fs'.format(size)

    for method in lst:
        try:
            time_used = test_one(method)
            print(format_ % (method, time_used))
        except Exception as e:
            print(traceback.format_exc())


def test_for_result():
    # disable ivchecker
    class DummyIVChecker(object):
        '''DummyIVChecker'''
        def __init__(self, size, timeout):
            pass

        def check(self, key, iv):
            pass

    encrypt.IV_CHECKER = DummyIVChecker(1, 1)

    result = []
    result.append('encrypt and decrypt 20MB data.')

    lst = sorted(method_supported.keys())
    lst = sorted(lst, key=lambda method: is_aead(method))
    size = max([len(x) for x in lst])
    format_ = '%-{:d}s %.4fs'.format(size)

    for method in lst:
        try:
            time_used = test_one(method)
            result.append(format_ % (method, time_used))
        except Exception as e:
            result.append(format_ % method)
    return '\n'.join(result)


if __name__ == '__main__':
    print(test_for_result())
