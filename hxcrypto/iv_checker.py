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

from typing import Dict
from collections import defaultdict
from dmfrbloom.bloomfilter import BloomFilter as _BloomFilter  # type: ignore[import-untyped]


class BloomFilter(_BloomFilter):
    def __init__(self, expected_items: int, fp_rate: float):
        super().__init__(expected_items, fp_rate)
        self.count = 0

    def add(self, element: bytes) -> None:
        super().add(element)
        self.count += 1

    def __contains__(self, element: bytes):
        return self.lookup(element)

    def __len__(self) -> int:
        return self.count

    def clear(self) -> None:
        self.filter.zero()
        self.count = 0


class IVError(ValueError):
    pass


class IVStore:

    def __init__(self, expected_items: int):
        self.expected_items = expected_items
        self.store_0 = BloomFilter(self.expected_items, 0.0001)
        self.store_1 = BloomFilter(self.expected_items, 0.0001)

    def add(self, item: bytes):
        if item in self:
            raise IVError
        if len(self.store_0) >= self.expected_items:
            self.store_0, self.store_1 = self.store_1, self.store_0
            self.store_0.clear()
        self.store_0.add(item)

    def __contains__(self, item: bytes):
        if item in self.store_0:
            return True
        if item in self.store_1:
            return True
        return False


class DummyIVChecker:
    '''DummyIVChecker'''
    def __init__(self, expected_items: int = 0, timeout: int = 0) -> None:
        pass

    def check(self, key, iv) -> None:
        pass


class IVChecker(DummyIVChecker):
    # check reused iv, removing out-dated data automatically

    def __init__(self, expected_items: int = 50000, timeout: int = 3600) -> None:
        # create a IVStore for each key
        self.timeout = timeout
        self.expected_items = expected_items
        self.store: Dict[bytes, IVStore] = defaultdict(lambda: IVStore(expected_items))

    def check(self, key: bytes, iv: bytes) -> None:
        if iv:
            self.store[key].add(iv)


iv_checker = IVChecker()
