import os
import glob

for f in glob.glob('./hxcrypto/*.ui'):
    fname = f.replace('\\', '/').split('/')[-1].split('.')[0]
    os.system('pyuic5 %s -o ./hxcrypto/ui_%s.py' % (f, fname))

# os.system('pylupdate5 ./hxcrypto/ui_crypto.py -ts -noobsolete ./hxcrypto/translate/zh_CN.ts')
# os.system('lrelease ./hxcrypto/translate/zh_CN.ts')
