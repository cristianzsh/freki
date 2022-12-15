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

import json

from flask_restx import Resource
from flask import request, send_from_directory

try:
    from werkzeug import secure_filename
except ImportError as error:
    from werkzeug.utils import secure_filename

from app import app
from app.models import User, Submission
from app.core.pe import PE
from app.core.strings import Strings
from app.core.capa import Capa
from app.core.foremost import Foremost
from app.core.yaraanalysis import YaraAnalysis
from app.core.hashes import Hashes
from app.core.virustotal import VirusTotal
from app.core.utils import get_basic_information, zip_file, save_log, save_submission, save_file
from . import api, ns_report, upload_parser, token_required

@ns_report.route("/get_sample/<sha1>", methods=["GET"])
class GetSample(Resource):
    """Gets the specified sample."""

    @api.doc(security="apikey")
    @api.doc(responses={200: "Success",
                        401 : "User is not authorized",
                        429 : "API request rate limit exceeded"})
    @token_required
    def get(self, sha1):
        """Finds samples by the SHA-1."""

        return send_from_directory(app.config["SAMPLES_DIR"],
                                   "{}/{}.zip".format(sha1, sha1),
                                   as_attachment=True)

@ns_report.route("/get_report/<sha1>", methods=["GET"])
class GetReport(Resource):
    """Fetches the specified report."""

    @api.doc(responses={200: "Success",
                        404 : "Report not found",
                        429 : "API request rate limit exceeded"})
    def get(self, sha1):
        """Finds reports by the SHA-1."""

        submission = Submission().query.filter_by(sha1=sha1).first()
        if submission:
            return json.loads(submission.data), 200

        return {"message" : "Sorry, that SHA-1 does not exist in our database."}, 404



@ns_report.route("/full_scan", methods=["POST"])
class FullScan(Resource):
    """Performs a complete scan of the file."""

    @api.doc(security="apikey")
    @api.doc(responses={200: "Success",
                        401 : "User is not authorized",
                        429 : "API request rate limit exceeded"})
    @token_required
    @api.expect(upload_parser)
    def post(self):
        """Complete scan of the file.

        Returns basic information, signatures, VirusTotal results and Yara matches.
        If the file is a Portable Executable (PE), it also fetches data about its sections
        (e.g., headers, imports) and capabilities.
        """

        # Get the filename, contents and SHA-1.
        uploaded_file = upload_parser.parse_args()["file"]
        filename = secure_filename(uploaded_file.filename)
        contents = uploaded_file.read()
        sha1 = Hashes().get_sha1(contents)

        # Get user information
        user = User().query.filter_by(freki_key=request.headers["API-KEY"]).first()

        # Return the results if the file was already analyzed.
        submission = Submission().query.filter_by(sha1=sha1).first()
        if submission:
            save_log(filename, submission.id, user.id)
            return json.loads(submission.data), 200

        # Save the file at the default samples folder.
        file_path = save_file(sha1, contents)

        # Get the VirusTotal report if it exists, else
        # send the file to analysis.
        virustotal = VirusTotal(user.vt_key)
        virustotal_detection, _ = virustotal.report(sha1)
        if not virustotal_detection:
            virustotal_detection, _ = virustotal.detection(contents)

        # Get hashes and basic information.
        hashes = Hashes(contents).get_all()
        basic_information = get_basic_information(file_path)
        pe_info = None
        capa_data = None
        data = {"file_name" : filename,
                "hashes" : hashes,
                "basic_information" : basic_information,
                "virustotal_detection" : virustotal_detection,
                "yara" : YaraAnalysis().get_matches(contents),
               }

        # If the file is a PE, analyze it.
        if basic_information["mime_type"] == "application/x-dosexec":
            pe_file = PE(contents)
            pe_info = pe_file.get_all()
            capa_data = Capa().analyze(file_path)
            foremost_data = Foremost().analyze(file_path)
            pe_info["strings"] = Strings("iso-8859-1", file_path).get()

            data["pe_info"] = pe_info
            data["capa"] = capa_data
            data["foremost"] = foremost_data

        # Log the submission and zip the sample.
        save_submission(data, user.id)
        zip_file(file_path)

        return data, 200

@ns_report.route("/list", methods=["GET"])
class ListReports(Resource):
    """Lists all unique submissions."""

    @api.doc(responses={200: "Success",
                        429 : "API request rate limit exceeded"})
    def get(self):
        """Lists all unique submissions."""

        submissions = Submission().query.all()
        sha1_list = []

        if submissions:
            for sub in submissions:
                sha1_list.append(sub.sha1)

        return sha1_list, 200
