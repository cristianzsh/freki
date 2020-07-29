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

    def detection(self, _file):
        """Sends the file to VirusTotal detection.

        Args:
            _file: The file to be analyzed.

        Returns:
            The VirusTotal response or an error if the request limit is reached.
        """

        scan_url = "https://www.virustotal.com/vtapi/v2/file/scan"
        scan_params = {"apikey" : self.key}
        files = {"file": open(_file, "rb")}
        response = requests.post(scan_url, files=files, params=scan_params)

        if response.status_code == 403:
            return {"verbose_msg" : "Invalid key!", "response_code" : -1}

        if response.status_code == 204:
            return {"verbose_msg" : "You have exceeded your VirusTotal request quota!"}

        return response.json()

    def report(self, scan_id):
        """Gets an existing VirusTotal report.

        Args:
            scan_id: The report ID (MD5, SHA-1 or SHA-256).

        Returns:
            The VirusTotal response or an error if the request limit is reached.
        """

        report_url = "https://www.virustotal.com/vtapi/v2/file/report"
        report_params = {"apikey" : self.key, "resource" : scan_id}
        response = requests.get(report_url, params=report_params)

        if response.status_code == 403:
            return {"verbose_msg" : "Invalid key!", "response_code" : -1}

        if response.status_code == 204:
            return {"verbose_msg" : "You have exceeded your VirusTotal request quota!"}

        return response.json()
