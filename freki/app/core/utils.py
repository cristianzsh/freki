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

from datetime import datetime
from os import path, mkdir

import math
import json
import magic
import pyminizip

from app import db, app
from app.models import Log, Submission

def convert_file_size(file_bytes):
    """Converts the file size for easy reading."""

    if file_bytes == 0:
        return "0B"

    sizes = ("B", "KB", "MB", "GB")
    i = int(math.floor(math.log(file_bytes, 1024)))
    s = round(file_bytes / math.pow(1024, i), 2)

    return "{} {} ({} bytes)".format(s, sizes[i], file_bytes)

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
            "size": 3.56 MB (3736787 bytes)
        }
    """

    mime = magic.from_file(_file, mime=True)
    file_magic = magic.from_file(_file)

    return {"mime_type" : mime,
            "magic" : file_magic,
            "size" : convert_file_size(path.getsize(_file))}

def save_log(filename, submission_id, user_id):
    """Inserts a new log in the database."""

    log = Log(name=filename,
              sub_date=datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
              submission_id=submission_id, user_id=user_id)
    db.session.add(log)
    db.session.commit()

def save_submission(data, user_id):
    """Inserts a new submission in the database."""

    vt_analyzed = False
    if data["virustotal_detection"]:
        vt_analyzed = True

    new_submission = Submission(sha1=data["hashes"]["SHA-1"],
                                sha256=data["hashes"]["SHA-256"],
                                data=json.dumps(data),
                                vt_analyzed=vt_analyzed)
    db.session.add(new_submission)
    db.session.commit()

    save_log(data["file_name"], new_submission.id, user_id)

def save_file(sha1, contents):
    """Saves the sample at the default folder."""

    save_path = "{}/{}".format(app.config["SAMPLES_DIR"], sha1)
    file_path = "{}/{}".format(save_path, sha1)

    if not path.exists(file_path):
        mkdir(save_path)
        open(file_path, "wb").write(contents)

    return file_path

def zip_file(_file):
    """Compresses the sample and adds a password."""

    pyminizip.compress(_file, None, "{}.zip".format(_file), "infected", 1)
