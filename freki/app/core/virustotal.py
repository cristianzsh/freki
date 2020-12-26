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

import requests

class VirusTotal():
    """Queries the VirusTotal API for information."""

    def __init__(self, key):
        """Stores the user key.

        Args:
            key: VirusTotal API key.
        """

        self.key = key
        self.scan_url = "https://www.virustotal.com/api/v3/files"
        self.report_url = "https://www.virustotal.com/api/v3/files/{}"
        self.headers = {"X-Apikey" : self.key}

    def detection(self, stream):
        """Sends the file to VirusTotal detection.

        Args:
            stream: The file bytes.

        Returns:
            The VirusTotal response or an error if the request limit is reached.
        """

        files = {"file": stream}
        response = requests.post(self.scan_url, files=files, headers=self.headers)
        print(response.status_code)

        if response.status_code != 200:
            return False, response.status_code

        return response.json(), response.status_code

    def report(self, scan_id):
        """Gets an existing VirusTotal report.

        Args:
            scan_id: The report ID (MD5, SHA-1 or SHA-256).

        Returns:
            The VirusTotal response or an error if the request limit is reached.
        """
        self.report_url = self.report_url.format(scan_id)
        response = requests.get(self.report_url, headers=self.headers)

        if response.status_code != 200:
            return False, response.status_code

        response = response.json()

        if not response["data"]["attributes"]["last_analysis_results"]:
            return False, 0

        return response, 200
