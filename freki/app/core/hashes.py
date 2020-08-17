"""
    Freki - malware analysis tool

    Copyright (C) 2020 Freki authors

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import hashlib
import zlib
import ssdeep

class Hashes():
    """Calculates different hashes."""

    def __init__(self, stream=None):
        """Gets the file content."""

        self.content = stream

    def get_all(self):
        """Returns a dict with all available hashes."""

        return {"MD5" : self.get_md5(self.content),
                "SHA-1": self.get_sha1(self.content),
                "SHA-224" : self.get_sha224(self.content),
                "SHA-256" : self.get_sha256(self.content),
                "SHA-384" : self.get_sha384(self.content),
                "SHA-512" : self.get_sha512(self.content),
                "CRC32" : self.get_crc32(self.content),
                "SSDEEP" : self.get_ssdeep(self.content)}

    @staticmethod
    def get_md5(file_bytes):
        """Returns the MD5 hash."""

        md5_hash = hashlib.md5()
        md5_hash.update(file_bytes)

        return md5_hash.hexdigest()

    @staticmethod
    def get_sha1(file_bytes):
        """Returns the SHA-1 hash."""

        sha1_hash = hashlib.sha1()
        sha1_hash.update(file_bytes)

        return sha1_hash.hexdigest()

    @staticmethod
    def get_sha224(file_bytes):
        """Returns the SHA-224 hash."""

        sha224_hash = hashlib.sha224()
        sha224_hash.update(file_bytes)

        return sha224_hash.hexdigest()

    @staticmethod
    def get_sha256(file_bytes):
        """Returns the SHA-256 hash."""

        sha256_hash = hashlib.sha256()
        sha256_hash.update(file_bytes)

        return sha256_hash.hexdigest()

    @staticmethod
    def get_sha384(file_bytes):
        """Returns the SHA-384 hash."""

        sha384_hash = hashlib.sha384()
        sha384_hash.update(file_bytes)

        return sha384_hash.hexdigest()

    @staticmethod
    def get_sha512(file_bytes):
        """Returns the SHA-512 hash."""

        sha512_hash = hashlib.sha512()
        sha512_hash.update(file_bytes)

        return sha512_hash.hexdigest()

    @staticmethod
    def get_crc32(file_bytes):
        """Returns the CRC32."""

        return hex(zlib.crc32(file_bytes))

    @staticmethod
    def get_ssdeep(file_bytes):
        """Returns the SSDEEP."""

        return ssdeep.hash(file_bytes)
