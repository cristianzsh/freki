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
import hashlib
import configparser
import requests

from flask import Flask, render_template, redirect, request
from database import Database

try:
    from werkzeug import secure_filename
except:
    from werkzeug.utils import secure_filename
    pass

config = configparser.ConfigParser()
config.read("config.ini")

HOST = config["APP"]["HOST"]
PORT = config["APP"]["PORT"]
SECRET_KEY = config["APP"]["SECRET_KEY"]
SAVE_DIR = config["APP"]["SAVE_DIRECTORY"]
DEBUG = config["APP"]["DEBUG"]
SQLITE_DB = config["DATABASE"]["DB"]

API_URL = config["API"]["URL"]

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY
db = Database(SQLITE_DB)

@app.route("/")
def index():
    """Renders the home page."""

    return render_template("index.html", last_submissions=db.select_files(top=True))

@app.route("/scan_file", methods=["POST"])
def scan_file():
    """Sends a file to the Freki API for a full scan and saves the log."""

    uploaded_file = request.files["file"]
    filename = secure_filename(uploaded_file.filename)
    file_location = "{}/{}".format(SAVE_DIR, filename)
    uploaded_file.save(file_location)

    files = {"file" : open(file_location, "rb")}

    sha1_hash = hashlib.sha1()
    sha1_hash.update(open(file_location, "rb").read())
    sha1 = sha1_hash.hexdigest()

    data = db.get_analysis(sha1)
    if data:
        db.update_analysis(data["signatures"]["SHA-1"])
        db.insert_file(data["signatures"]["SHA-1"], data["signatures"]["SHA-256"],
                       filename, file_location, json.dumps(data))

        return redirect("/analysis?sha1={}&name={}".format(sha1, uploaded_file.filename))

    response = requests.post("{}/full_scan".format(API_URL), files=files)
    data = response.json()

    db.insert_file(data["signatures"]["SHA-1"], data["signatures"]["SHA-256"],
                   filename, file_location, json.dumps(data))

    return redirect("/analysis?sha1={}".format(sha1))

@app.route("/analysis", methods=["GET"])
def analysis():
    """Fetches the data from the database and returns the specified analysis."""

    sha1 = request.args.get("sha1")
    name = request.args.get("name")

    data = db.get_analysis(sha1)
    if not data:
        return render_template("index.html", last_submissions=db.select_files(top=True),
                               not_found=True)

    if data["virustotal_detection"]["verbose_msg"] != "Scan finished, information embedded":
        response = requests.get("{}/general/virustotal_report/{}".format(API_URL, sha1))
        data["virustotal_detection"] = response.json()

    if name:
        data["file_name"] = name

    return render_template("analysis.html", data=data,
                           history=db.get_first_last_submissions(data["signatures"]["SHA-256"]),
                           names=db.get_file_names(data["signatures"]["SHA-256"]))

if __name__ == "__main__":
    app.run(debug=DEBUG, host=HOST, port=PORT)
