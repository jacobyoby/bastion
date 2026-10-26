# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""This module contains a default implementation of paranoid storage.

A storage contains information that might be useful for running the tests. For
now, this default implementation uses information stored in the file system.
"""
from collections.abc import Iterator, Set
import lzma
import re
from absl import logging
from paranoid_crypto.lib import resources
from paranoid_crypto.lib import util
from paranoid_crypto.lib.data import data_pb2
from paranoid_crypto.lib.data import storage
from paranoid_crypto.lib.data import unseeded_rands

PATH = "lib/data/"

# See GetKeypairData method for explanation of the file(s) below.
KEYPAIR_TABLE_FILE_SMALL = "keypair_table_small.lzma"

# See GetOpenSSlDenyList method for explanation of the files below.
OPENSSL_DENY_RSA1024 = "weak_keylist.RSA-1024.dat"
OPENSSL_DENY_RSA2048 = "weak_keylist.RSA-2048.dat"
OPENSSL_DENY_RSA4096 = "weak_keylist.RSA-4096.dat"
# lzma-compressed lists in the same format, built from badkeys/debianopenssl:
# openssl keys of 3072 bits, and ssh-keygen keys, which differ from openssl's.
# See lib/data/weak_keylist.LICENSE for their source.
OPENSSL_DENY_LZMA = (
    ("RSA-3072", "weak_keylist.RSA-3072.lzma"),
    ("RSA-1024", "weak_keylist_ssh.RSA-1024.lzma"),
    ("RSA-2048", "weak_keylist_ssh.RSA-2048.lzma"),
    ("RSA-3072", "weak_keylist_ssh.RSA-3072.lzma"),
    ("RSA-4096", "weak_keylist_ssh.RSA-4096.lzma"),
)

# See GetSharedPrimesProduct method for explanation of the files below.
SHARED_PRIMES_FILE = "shared_primes.RSA-%d.dat"
SHARED_PRIMES_BITS = (512, 768, 1024, 2048, 4096)


class DefaultStorage(storage.Storage):
  """Default implementation of storage.Storage.

  It uses the file system as a storage. Implement your own class if you want
  different data or want to load from different resources.
  """

  def GetUnseededRands(self, size: int) -> Set[int]:
    return unseeded_rands.size_unseeded_map.get(size, frozenset())

  def GetKeypairData(self) -> data_pb2.KeypairData:
    # TABLE_FILE_SMALL brute-forces only the first byte,
    # i.e., detects only 33% of the keys. It is useful to be used in non-prod
    # environment, e.g., unit tests as they can run faster. But in production
    # a larger table would be preferable.
    path = PATH + KEYPAIR_TABLE_FILE_SMALL
    logging.info("Loading Keypair data from %s.", path)
    data = resources.GetParanoidResourceAsFile(path, "rb").read()
    return data_pb2.KeypairData.FromString(lzma.decompress(data))

  def GetOpensslDenylist(self) -> Set[str]:

    def _ReadDenylist(keytype: str,
                      weak_keylist: Iterator[str]) -> Iterator[str]:
      for line in weak_keylist:
        line = line.strip()
        if re.match(r"^[0-9a-f]{20}$", line):
          yield "%s:%s" % (keytype, line)

    file_rsa1024 = resources.GetParanoidResourceAsFile(
        PATH + OPENSSL_DENY_RSA1024, mode="r")
    file_rsa2048 = resources.GetParanoidResourceAsFile(
        PATH + OPENSSL_DENY_RSA2048, mode="r")
    file_rsa4096 = resources.GetParanoidResourceAsFile(
        PATH + OPENSSL_DENY_RSA4096, mode="r")
    weak_keylist = set()
    weak_keylist.update(_ReadDenylist("RSA-1024", file_rsa1024))
    weak_keylist.update(_ReadDenylist("RSA-2048", file_rsa2048))
    weak_keylist.update(_ReadDenylist("RSA-4096", file_rsa4096))
    for keytype, name in OPENSSL_DENY_LZMA:
      data = lzma.decompress(resources.GetParanoidResource(PATH + name))
      weak_keylist.update(
          _ReadDenylist(keytype, data.decode("ascii").splitlines()))
    return weak_keylist

  def GetSharedPrimesProduct(self, bits: int) -> int:
    # Products of primes shared by real moduli, from the badkeys project; see
    # lib/data/shared_primes.LICENSE for their source and license.
    if bits not in SHARED_PRIMES_BITS:
      return 1
    path = PATH + SHARED_PRIMES_FILE % bits
    logging.info("Loading shared primes from %s.", path)
    return util.Bytes2Int(resources.GetParanoidResource(path))
