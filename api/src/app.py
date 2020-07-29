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
import configparser
import random
import magic

from flask import Flask
from flask_restplus import Api, Resource
from werkzeug.datastructures import FileStorage

from utils.hashes import Hashes
from utils.virustotal import VirusTotal
from utils.pe import PE
from utils.strings import Strings
from utils.capa import Capa
from utils.yaraanalysis import YaraAnalysis

config = configparser.ConfigParser()
config.read("config.ini")

HOST = config["APP"]["HOST"]
PORT = config["APP"]["PORT"]
SECRET_KEY = config["APP"]["SECRET_KEY"]
SAVE_DIR = config["APP"]["SAVE_DIRECTORY"]
DEBUG = config["APP"]["DEBUG"]

VT_KEY = config["VIRUSTOTAL"]["KEY"]

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY

api = Api(app, version="1.0", title="Freki API",
          description="Free and open source malware analysis tool.")

ns_general = api.namespace("general", description="General information about files.")
ns_pe = api.namespace("pe", description="Portable Executable (PE) functions.")

upload_parser = api.parser()
upload_parser.add_argument("file", location="files", type=FileStorage, required=True)

yara = YaraAnalysis()
vt = VirusTotal(VT_KEY)

def get_basic_information(_file):
    """Gets basic information about the uploaded file.

    Args:
        _file: The filepath.

    Returns:
        A dict containing the mime type, magic and size of the file. For
        example:

        {
            "mime_type": "application/x-dosexec",
            "magic": "PE32 executable (console) Intel 80386 (stripped to external PDB),
                      for MS Windows",
            "size": 3736787
        }
    """

    mime = magic.from_file(_file, mime=True)
    file_magic = magic.from_file(_file)
    return {"mime_type" : mime, "magic" : file_magic, "size" : os.path.getsize(_file)}

def save_file():
    """Saves the uploaded file.

    Generates a random name and saves it at the location stored in SAVE_DIR.

    Returns:
        The file location. For example:

        /tmp/1197122591013297584
        /home/theo/samples/16864982539520815181
    """

    args = upload_parser.parse_args()
    uploaded_file = args["file"]
    file_location = "{}/{}".format(SAVE_DIR, random.getrandbits(64))
    uploaded_file.save(file_location)

    return file_location

@api.route("/full_scan", methods=["POST"])
class FullScan(Resource):
    """Realizes a complete scan of the file."""

    @api.expect(upload_parser)
    def post(self):
        """Complete scan of the file.

        Returns basic information, signatures, VirusTotal results and Yara matches.
        If the file is a Portable Executable (PE), it also fetches data about its sections
        (e.g., headers, imports) and capabilities.
        """

        file_location = save_file()

        basic_info = get_basic_information(file_location)
        hashes = Hashes(file_location)
        signatures = hashes.get_all()

        virustotal_detection = vt.report(signatures["SHA-1"])
        if virustotal_detection["response_code"] == 0:
            virustotal_detection = vt.detection(file_location)

        pe_info = None
        capa = None
        if basic_info["mime_type"] == "application/x-dosexec":
            pe_file = PE(file_location)
            pe_info = pe_file.get_all()
            capa = Capa().analyze(file_location)
            pe_info["strings"] = Strings("iso-8859-1", file_location).get()

        return {"file_name" : upload_parser.parse_args()["file"].filename,
                "signatures" : signatures,
                "basic_information" : basic_info,
                "virustotal_detection" : virustotal_detection,
                "pe_info" : pe_info,
                "yara" : yara.get_matches(file_location),
                "capa" : capa}, 200


# Common to all files:
@ns_general.route("/basic_information", methods=["POST"])
class BasicInformation(Resource):
    """Fetches basic information about a file."""

    @api.expect(upload_parser)
    def post(self):
        """Returns basic information of the file.

        Returns a dict with the mime type, magic and size of the uploaded file.
        """

        file_location = save_file()
        return get_basic_information(file_location)

@ns_general.route("/hashes", methods=["POST"])
class GetHashes(Resource):
    """Gets hashes of a file."""

    @api.expect(upload_parser)
    def post(self):
        """Calculates the different hashes of the file.

        Returns a dict containing the MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512,
        CRC32 and SSDEEP of the uploaded file.
        """

        file_location = save_file()
        return Hashes(file_location).get_all()

@ns_general.route("/virustotal_detection", methods=["POST"])
class VirusTotalDetection(Resource):
    """Sends data from VirusTotal."""

    @api.expect(upload_parser)
    def post(self):
        """Sends the file to the VirusTotal detection system."""

        file_location = save_file()
        return vt.detection(file_location)

@ns_general.route("/virustotal_report/<scan_id>", methods=["GET"])
class VirusTotalReport(Resource):
    """Gets data from VirusTotal."""

    def get(self, scan_id):
        """Returns the VirusTotal report of the specified ID.

        The scan_id can be the MD5, SHA-1 or SHA-256 of a file.
        """

        return vt.report(scan_id)


# Specific for PE files:
@ns_pe.route("/get_all", methods=["POST"])
class PEAll(Resource):
    """Gets all available information of a PE file."""

    @api.doc(responses={200: "Success", 406 : "Not Acceptable"})
    @api.expect(upload_parser)
    def post(self):
        """Returns all available information of the PE file.

        Complete analysis of the PE file. If the file is invalid (not a PE),
        it returns an error message.
        """

        file_location = save_file()
        try:
            return PE(file_location).get_all()
        except:
            return {"message" : "Invalid file!"}, 406

@ns_pe.route("/basic_information", methods=["POST"])
class PEBasicInformation(Resource):
    """Extracts general information about the PE file."""

    @api.doc(responses={200: "Success", 406 : "Not Acceptable"})
    @api.expect(upload_parser)
    def post(self):
        """Returns general information about the PE file."""
        
        file_location = save_file()
        try:
            return PE(file_location).get_pe_information()
        except:
            return {"message" : "Invalid file!"}, 406

@ns_pe.route("/file_header", methods=["POST"])
class PEFileHeader(Resource):
    """Extracts the PE file header."""

    @api.doc(responses={200: "Success", 406 : "Not Acceptable"})
    @api.expect(upload_parser)
    def post(self):
        """Returns the PE file header."""

        file_location = save_file()
        try:
            return PE(file_location).get_file_header()
        except:
            return {"message" : "Invalid file!"}, 406

@ns_pe.route("/optional_header", methods=["POST"])
class PEOptionalHeader(Resource):
    """Extracts the PE optional header."""

    @api.doc(responses={200: "Success", 406 : "Not Acceptable"})
    @api.expect(upload_parser)
    def post(self):
        """Returns the PE optional header."""

        file_location = save_file()
        try:
            return PE(file_location).get_optional_header()
        except:
            return {"message" : "Invalid file!"}, 406

@ns_pe.route("/sections", methods=["POST"])
class PESections(Resource):
    """Extracts the PE sections."""

    @api.doc(responses={200: "Success", 406 : "Not Acceptable"})
    @api.expect(upload_parser)
    def post(self):
        """Returns the PE sections."""

        file_location = save_file()
        try:
            return PE(file_location).get_sections()
        except:
            return {"message" : "Invalid file!"}, 406

@ns_pe.route("/imports", methods=["POST"])
class PEImports(Resource):
    """Extracts the PE optional header."""

    @api.doc(responses={200: "Success", 406 : "Not Acceptable"})
    @api.expect(upload_parser)
    def post(self):
        """Returns the PE imports."""

        file_location = save_file()
        try:
            return PE(file_location).get_imports()
        except:
            return {"message" : "Invalid file!"}, 406

@ns_pe.route("/capabilities", methods=["POST"])
class Capabilities(Resource):
    """Extracts the PE capabilities."""

    @api.doc(responses={200: "Success", 406 : "Not Acceptable"})
    @api.expect(upload_parser)
    def post(self):
        """Returns the PE capabilities."""

        file_location = save_file()
        try:
            return Capa().analyze(file_location)
        except:
            return {"message" : "Invalid file!"}, 406

@ns_pe.route("/strings", methods=["POST"])
class GetStrings(Resource):
    """Extracts the PE strings."""

    @api.expect(upload_parser)
    def post(self):
        """Returns the PE strings.

        It also filters IP addresses and URLs.
        """

        file_location = save_file()

        return {"strings" : Strings("iso-8859-1", file_location).get()}

@ns_pe.route("/yara_matches", methods=["POST"])
class YaraMatches(Resource):
    """Gets Yara matches."""

    @api.expect(upload_parser)
    def post(self):
        """Returns the Yara matches."""

        file_location = save_file()

        return {"matches" : yara.get_matches(file_location)}

if __name__ == "__main__":
    app.run(debug=DEBUG, host=HOST, port=PORT)
