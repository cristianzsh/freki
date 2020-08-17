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

from flask_restplus import Resource

from app.core.utils import save_file
from app.core.pe import PE
from app.core.capa import Capa

from . import api, ns_pe, upload_parser, get_bytes, get_sha1, token_required

@ns_pe.route("/get_all", methods=["POST"])
class PEAll(Resource):
    """Gets all available information of a PE file."""

    @api.doc(responses={200: "Success", 406 : "Not acceptable",
                        429 : "API request rate limit exceeded"})
    @api.expect(upload_parser)
    def post(self):
        """Returns all available information of the PE file.

        Complete analysis of the PE file. If the file is invalid (not a PE),
        it returns an error message.
        """

        try:
            return PE(get_bytes()).get_all(), 200
        except:
            return {"message" : "Invalid file type!"}, 406

@ns_pe.route("/summary", methods=["POST"])
class PESummary(Resource):
    """Extracts general information about the PE file."""

    @api.doc(responses={200: "Success", 406 : "Not acceptable",
                        429 : "API request rate limit exceeded"})
    @api.expect(upload_parser)
    def post(self):
        """Returns general information about the PE file."""

        try:
            return PE(get_bytes()).get_summary(), 200
        except:
            return {"message" : "Invalid file type!"}, 406

@ns_pe.route("/file_header", methods=["POST"])
class PEFileHeader(Resource):
    """Extracts the PE file header."""

    @api.doc(responses={200: "Success", 406 : "Not acceptable",
                        429 : "API request rate limit exceeded"})
    @api.expect(upload_parser)
    def post(self):
        """Returns the PE file header."""

        try:
            return PE(get_bytes()).get_file_header(), 200
        except:
            return {"message" : "Invalid file type!"}, 406

@ns_pe.route("/dos_header", methods=["POST"])
class PEDOSHeader(Resource):
    """Extracts the PE DOS header."""

    @api.doc(responses={200: "Success", 406 : "Not acceptable",
                        429 : "API request rate limit exceeded"})
    @api.expect(upload_parser)
    def post(self):
        """Returns the PE DOS header."""

        try:
            return PE(get_bytes()).get_dos_header(), 200
        except:
            return {"message" : "Invalid file type!"}, 406

@ns_pe.route("/optional_header", methods=["POST"])
class PEOptionalHeader(Resource):
    """Extracts the PE optional header."""

    @api.doc(responses={200: "Success", 406 : "Not acceptable",
                        429 : "API request rate limit exceeded"})
    @api.expect(upload_parser)
    def post(self):
        """Returns the PE optional header."""

        try:
            return PE(get_bytes()).get_optional_header(), 200
        except:
            return {"message" : "Invalid file type!"}, 406

@ns_pe.route("/sections", methods=["POST"])
class PESections(Resource):
    """Extracts the PE sections."""

    @api.doc(responses={200: "Success", 406 : "Not acceptable",
                        429 : "API request rate limit exceeded"})
    @api.expect(upload_parser)
    def post(self):
        """Returns the PE sections."""

        try:
            return PE(get_bytes()).get_sections(), 200
        except:
            return {"message" : "Invalid file type!"}, 406

@ns_pe.route("/imports", methods=["POST"])
class PEImports(Resource):
    """Extracts the PE optional header."""

    @api.doc(responses={200: "Success", 406 : "Not acceptable",
                        429 : "API request rate limit exceeded"})
    @api.expect(upload_parser)
    def post(self):
        """Returns the PE imports."""

        try:
            return PE(get_bytes()).get_imports(), 200
        except:
            return {"message" : "Invalid file type!"}, 406

@ns_pe.route("/capabilities", methods=["POST"])
class Capabilities(Resource):
    """Extracts the PE capabilities."""

    @api.doc(security="apikey")
    @api.doc(responses={200: "Success",
                        401 : "User is not authorized",
                        406 : "Not acceptable",
                        429 : "API request rate limit exceeded"})
    @token_required
    @api.expect(upload_parser)
    def post(self):
        """Returns the PE capabilities."""

        contents = get_bytes()
        file_location = save_file(get_sha1(contents), contents)

        try:
            return Capa().analyze(file_location), 200
        except:
            return {"message" : "Invalid file type!"}, 406
