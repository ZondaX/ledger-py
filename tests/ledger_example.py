# ********************************************************************************
# *   LedgerPy
# *   (c) 2019 ZondaX GmbH
# *
# *  Licensed under the Apache License, Version 2.0 (the "License");
# *  you may not use this file except in compliance with the License.
# *  You may obtain a copy of the License at
# *
# *      http://www.apache.org/licenses/LICENSE-2.0
# *
# *  Unless required by applicable law or agreed to in writing, software
# *  distributed under the License is distributed on an "AS IS" BASIS,
# *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# *  See the License for the specific language governing permissions and
# *  limitations under the License.
# ********************************************************************************/

from binascii import hexlify
from typing import List

from ledgerpy.ledger import LedgerBase

last_error = 0


class LedgerCosmos(LedgerBase):
    INS_PUBLIC_KEY_SECP256K1 = 0x01
    INS_SIGN_SECP256K1 = 0x02
    INS_SHOW_ADDR_SECP256K1 = 0x03

    def __init__(self, cla):
        super().__init__(cla)

    @staticmethod
    def serialize_path(path: List[int]):
        if len(path) != 5:
            raise Exception("Path should have 5 elements")

        spath = bytearray()
        for idx, p in enumerate(path):
            if idx < 3:
                p |= 0x80000000
            tmp = p.to_bytes(4, byteorder='little', signed=False)
            spath += tmp

        spath = len(path).to_bytes(1, byteorder='little', signed=False) + spath
        return spath

    def get_public_key(self, account, index):
        if not self.connected:
            raise Exception("Device is not yet connected")

        path = [44, 118, account, 0, index]
        spath = self.serialize_path(path)

        answer = self.send(self.INS_PUBLIC_KEY_SECP256K1, 0, 0, spath)

        return answer


def test_get_version():
    cosmos = LedgerCosmos(0x55)
    cosmos.connect()
    assert cosmos.version == "1.1.0"


def test_serialize_path():
    spath = LedgerCosmos.serialize_path([44, 118, 5, 0, 4])
    assert hexlify(spath) == b'052c00008076000080050000800000000004000000'


def test_get_public_key():
    cosmos = LedgerCosmos(0x55)
    cosmos.connect()
    cosmos.DEBUGMODE = True
    pk = cosmos.get_public_key(0, 0)
    assert hexlify(pk) == b'04362226ad04532f96ea9bded237698c5abd67c43b063fa2aec6d83ea22098d306b695b8db82c9557ecc32ec7699a505c08b33f2be789308a56d8ec8d6be5544af'
