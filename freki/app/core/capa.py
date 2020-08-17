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

import subprocess
import json

class Capa():
    """Extracts the file capabilities with capa (https://github.com/fireeye/capa)."""

    def analyze(self, _file):
        """Runs the capa binary and returns its output formated.

        TODO: Use the Python 3.x library when available.
        """

        capa_output = subprocess.check_output(["./app/core/bin/capa-v1.0.0-linux",
                                               "-v", "-j", _file])
        capa_data = json.loads(capa_output.decode("utf-8"))
        data_parsed = {}

        for k in capa_data["rules"]:
            try:
                data_parsed[k] = {"namespace" : capa_data["rules"][k]["meta"]["namespace"],
                                  "scope" : capa_data["rules"][k]["meta"]["scope"],
                                  "matches" : self.get_list(capa_data["rules"][k]["matches"])}
            except:
                pass

        return data_parsed

    @staticmethod
    def get_list(_dict):
        """Converts a dict to a list."""

        _list = []
        for key in _dict.keys():
            _list.append(hex(int(key)))

        return _list
