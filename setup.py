
from setuptools import setup

setup(
    name="hxcrypto",
    version="0.0.3",
    license='https://www.gnu.org/licenses/lgpl-3.0.txt',
    description="cryptography module for shadowsocks and hxsocks",
    author='v3aqb',
    author_email='null',
    url='https://github.com/v3aqb/hxcrypto',
    packages=['hxcrypto'],
    package_data={'hxcrypto': ['translate/*.qm']},
    install_requires=["cryptography >= 2.1"],
    classifiers=[
        'License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Topic :: Internet :: Proxy Servers',
    ],
)
