import os
import glob

for f in glob.glob('./hxcrypto/*.ui'):
    fname = f.replace('\\', '/').split('/')[-1].split('.')[0]
    os.system('pyuic6 %s -o ./hxcrypto/ui_%s.py' % (f, fname))

# os.system('pylupdate5 ./hxcrypto/ui_crypto.py -ts -noobsolete ./hxcrypto/translate/zh_CN.ts')
# os.system('lrelease ./hxcrypto/translate/zh_CN.ts')
for path in glob.glob('./hxcrypto/ui_*.py'):
    with open(path, 'r') as f:
        data = f.read()
    with open(path, 'w') as f:
        data = data.replace('from PyQt6 import QtCore, QtGui, QtWidgets',
'''try:
    from PyQt6 import QtCore, QtGui, QtWidgets
except ImportError:
    from PyQt5 import QtCore, QtGui, QtWidgets''')
        f.write(data)
