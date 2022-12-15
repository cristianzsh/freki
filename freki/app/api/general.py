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

from flask_restx import Resource

from app.core.yaraanalysis import YaraAnalysis
from app.core.hashes import Hashes
from app.core.strings import Strings
from app.core.utils import get_basic_information, save_file

from . import api, ns_general, upload_parser, get_bytes, get_sha1, token_required

@ns_general.route("/basic_information", methods=["POST"])
class BasicInformation(Resource):
    """Fetches basic information about a file."""

    @api.doc(security="apikey")
    @api.doc(responses={200: "Success",
                        401 : "User is not authorized",
                        429 : "API request rate limit exceeded"})
    @token_required
    @api.expect(upload_parser)
    def post(self):
        """Returns basic information of the file.

        Returns a dict with the mime type, magic and size of the uploaded file.
        """

        contents = get_bytes()
        file_location = save_file(get_sha1(contents), contents)

        return get_basic_information(file_location), 200

@ns_general.route("/hashes", methods=["POST"])
class GetHashes(Resource):
    """Gets hashes of a file."""

    @api.doc(responses={200: "Success",
                        429 : "API request rate limit exceeded"})
    @api.expect(upload_parser)
    def post(self):
        """Calculates the different hashes of the file.

        Returns a dict containing the MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512,
        CRC32 and SSDEEP of the uploaded file.
        """

        return Hashes(get_bytes()).get_all(), 200

@ns_general.route("/strings", methods=["POST"])
class GetStrings(Resource):
    """Extracts the strings of the sample."""

    @api.doc(security="apikey")
    @api.doc(responses={200: "Success",
                        401 : "User is not authorized",
                        429 : "API request rate limit exceeded"})
    @token_required
    @api.expect(upload_parser)
    def post(self):
        """Returns the strings of the sample.

        It also filters IP addresses and URLs.
        """

        contents = get_bytes()
        file_location = save_file(get_sha1(contents), contents)

        return {"strings" : Strings("iso-8859-1", file_location).get()}, 200

@ns_general.route("/yara_matches", methods=["POST"])
class YaraMatches(Resource):
    """Gets Yara matches."""

    @api.doc(responses={200: "Success",
                        429 : "API request rate limit exceeded"})
    @api.expect(upload_parser)
    def post(self):
        """Returns the Yara matches."""

        return {"matches" : YaraAnalysis().get_matches(get_bytes())}, 200
