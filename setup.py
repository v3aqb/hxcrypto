
from setuptools import setup

setup(
    name="hxcrypto",
    version="0.0.7",
    license='https://www.gnu.org/licenses/lgpl-3.0.txt',
    description="cryptography module for shadowsocks and hxsocks",
    author='v3aqb',
    author_email='null',
    url='https://github.com/v3aqb/hxcrypto',
    packages=['hxcrypto'],
    package_data={'hxcrypto': ['translate/*.qm', 'py.typed']},
    install_requires=["cryptography >= 3.1", "dmfrbloom"],
    classifiers=[
        'License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
    ],
)
