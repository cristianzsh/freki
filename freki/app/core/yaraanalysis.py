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

import os.path
import yara

class YaraAnalysis():
    """Gets Yara matches."""

    def __init__(self):
        """Compiles, saves and loads the Yara rules."""

        if not os.path.exists("./app/core/yara_rules/compiled"):
            self.rules = yara.compile(filepath="./app/core/yara_rules/index.yar")
            self.rules.save("./app/core/yara_rules/compiled")

        self.rules = yara.load("./app/core/yara_rules/compiled")

    def get_matches(self, stream):
        """Returns all matches.

        Args:
            stream: The file bytes.

        Returns:
            A list with the matches.
        """

        matches = self.rules.match(data=stream)

        return str(matches).strip("][").split(", ")
