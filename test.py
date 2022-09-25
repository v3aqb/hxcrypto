
import os
import time
import traceback

from hxcrypto import Encryptor, is_aead, method_supported, AEncryptor

BLOCK = 10240
REPEAT = 1024


def test_one(method, block, repeat):
    data = os.urandom(block)

    if is_aead(method):
        cipher = AEncryptor(b'cXdlcg==', method, b"ctx", check_iv=False)
        cipher1 = AEncryptor(b'cXdlcg==', method, b"ctx", check_iv=False)
    else:
        cipher = Encryptor(b'123456', method, check_iv=False)
        cipher1 = Encryptor(b'123456', method, check_iv=False)
    ct1 = cipher.encrypt(data)
    cipher1.decrypt(ct1)
    time_log = time.time()
    for _ in range(repeat):
        ct1 = cipher.encrypt(data)
        ct2 = cipher.encrypt(data)
        cipher1.decrypt(ct1)
        cipher1.decrypt(ct2)
    return time.time() - time_log


def test():
    size = (BLOCK / 1024) * (REPEAT / 1024) * 2
    print('encrypt and decrypt %dMB data.' % size)

    lst = sorted(method_supported.keys())
    lst = sorted(lst, key=lambda method: is_aead(method))
    size = max([len(x) for x in lst])
    format_ = '%-{:d}s %.4fs'.format(size)

    for method in lst:
        try:
            time_used = test_one(method, BLOCK, REPEAT)
            print(format_ % (method, time_used))
        except Exception as e:
            print(traceback.format_exc())


def test_for_result():
    result = []
    size = (BLOCK / 1024) * (REPEAT / 1024) * 2
    result.append('encrypt and decrypt %dMB data.' % size)

    lst = sorted(method_supported.keys())
    lst = sorted(lst, key=lambda method: is_aead(method))
    size = max([len(x) for x in lst])
    format_ = '%-{:d}s %.4fs'.format(size)

    for method in lst:
        try:
            time_used = test_one(method, BLOCK, REPEAT)
            result.append(format_ % (method, time_used))
        except Exception as e:
            result.append(format_ % method)
    return '\n'.join(result)


if __name__ == '__main__':
    print(test())
