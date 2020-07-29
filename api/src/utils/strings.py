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

import re
import string
import codecs

class Strings():
    """Extracts the file strings."""

    def __init__(self, charset, _file):
        """Stores the file bytes for later extraction."""

        self.stream = codecs.getreader(charset)(open(_file, "rb"), errors="ignore")
        self.url_regex = re.compile(r'(?i)\b((?:http[s]?:(?:/{1,3}|[a-z0-9%])|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:\'".,<>?«»“”‘’]))')
        self.ip_regex = re.compile(r"\b(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\b")

    def get(self):
        """Gets all strings from the file. It also filters URLs and IP addresses.

        Returns:
            A dict containing the strings, URLs, and IPs.
        """

        str_len = 7
        strings = []
        _dict = []

        for (_, _string) in self.is_printable(self.stream):
            if not self.is_readable(_string, 0.8):
                continue

            if len(_string) < str_len:
                continue

            if _dict:
                valid = False
                raw_str = ""

                for char in string.ascii_letters + string.digits:
                    raw_str += char
                raw_str = raw_str.split()

                for data in raw_str:
                    if len(data) < str_len:
                        continue

                    for dic in _dict:
                        if dic.check(data.lower()):
                            valid = True
                if not valid:
                    continue

            _string = _string.strip()
            strings.append(_string)

        return {"all" : strings, "urls" : list(filter(self.url_regex.search, strings)),
                "ips" : list(filter(self.ip_regex.search, strings))}

    @staticmethod
    def is_printable(stream):
        """Checks if the stream is printable."""

        offset = 0
        current_string = []

        for char in stream.read():
            if char in string.printable:
                if current_string:
                    current_string[1].append(char)
                else:
                    current_string = (offset, [char])
            else:
                if current_string:
                    yield (current_string[0], "".join(current_string[1]))
                    current_string = []
            offset += 1

    @staticmethod
    def is_readable(_string, percentage):
        """Returns the percentage of readable chars in the string."""

        count = 0
        for char in _string:
            if char in string.ascii_letters + string.digits:
                count += 1

        return float(count) / float(len(_string)) >= percentage
