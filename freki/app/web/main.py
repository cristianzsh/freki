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

from flask import render_template, redirect, url_for, request, flash, send_from_directory
from flask_login import current_user, login_required

try:
    from werkzeug import secure_filename
except ImportError:
    from werkzeug.utils import secure_filename

from app import app
from app.models import Comment, Log, Submission
from app.core.pe import PE
from app.core.strings import Strings
from app.core.capa import Capa
from app.core.foremost import Foremost
from app.core.yaraanalysis import YaraAnalysis
from app.core.hashes import Hashes
from app.core.virustotal import VirusTotal
from app.core.utils import get_basic_information, zip_file, save_log, save_submission, save_file

from . import web

@web.route("/")
def index():
    """Renders the homepage."""

    return render_template("main/index.html",
                           last_submissions=Log.query.order_by(Log.sub_date.desc()).limit(10).all(),
                           sub_count=len(Log.query.all()))

@web.route("/file/<path:path>")
@login_required
def get_file(path):
    """Returns the sample by its SHA-1."""

    return send_from_directory(app.config["SAMPLES_DIR"],
                               path, as_attachment=True)

@web.route("/scan_file", methods=["POST"])
@login_required
def scan_file():
    """Analyzes a file if it is new or returns an existing analysis."""

    # Get the filename, contents and SHA-1.
    uploaded_file = request.files["file"]
    filename = secure_filename(uploaded_file.filename)
    contents = uploaded_file.read()
    sha1 = Hashes().get_sha1(contents)

    # Redirect the user to the analysis page
    # if the file was already analyzed.
    submission = Submission().query.filter_by(sha1=sha1).first()
    if submission:
        save_log(filename, submission.id, current_user.id)
        return redirect("/analysis?sha1={}&name={}".format(sha1, filename))

    # Save the file at the default samples folder.
    file_path = save_file(sha1, contents)

    # Get the VirusTotal report if it exists, else
    # send the file to analysis.
    virustotal = VirusTotal(current_user.vt_key)
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
    save_submission(data, current_user.id)
    zip_file(file_path)

    return redirect("/analysis?sha1={}&name={}".format(sha1, filename))

@web.route("/analysis", methods=["GET"])
def analysis():
    """Fetches data from the database and returns the specified analysis."""

    sha1 = request.args.get("sha1").strip()
    name = request.args.get("name")

    # Check if the file exists in the database.
    log = Log.query.filter(Log.submission.has(sha1=sha1)).all()
    if not log:
        flash("Sorry, that SHA-1 does not exist in our database.")
        return redirect(url_for("web.index"))

    # Get the data.
    data = json.loads(log[0].submission.data)
    if name:
        data["file_name"] = name

    # Load comments, other names and first/last submissions.
    comments = Comment.query.filter(Comment.submission.has(sha1=sha1)).\
                             order_by(Comment.date.desc()).all()

    names = []
    for log_name in log:
        if log_name.name not in names:
            names.append(log_name.name)

    history = [log[0].sub_date, log[-1].sub_date]

    return render_template("main/analysis.html", data=data, history=history,
                           names=names, comments=comments)
