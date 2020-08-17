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

import random

from functools import wraps
from flask import Blueprint, request
from werkzeug.datastructures import FileStorage
from flask_restplus import Api

from app import db
from app.models import User
from app.core.hashes import Hashes

api_blueprint = Blueprint("api", __name__)

authorizations = {
    "apikey" : {
        "type" : "apiKey",
        "in" : "header",
        "name" : "API-KEY"
    }
}

api = Api(api_blueprint, version="1.1", title="Freki API", doc="/",
          description="""Freki is a free and open-source malware analysis platform.
          This API allows you to query for different information about samples.\
          If you want full access, please sign up and get an API key. Each user has \
          a quota of 4 requests per minute.""",
          license="AGPL-3.0 License",
          license_url="https://github.com/crhenr/freki/blob/master/LICENSE",
          contact="Freki",
          contact_url="https://github.com/crhenr/freki",
          authorizations=authorizations)

# API namespaces.
ns_report = api.namespace("report", path="/",
                          description="Scan a new file or search for samples and reports.")
ns_user = api.namespace("user", path="/user", description="User options.")
ns_general = api.namespace("general", path="/", description="General information about samples.")
ns_pe = api.namespace("pe", description="Portable Executable (PE) operations.")

# Parsers.
upload_parser = api.parser()
upload_parser.add_argument("file", location="files", type=FileStorage, required=True)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        """Checks if the API key is valid."""

        token = None
        if "API-KEY" in request.headers:
            token = request.headers["API-KEY"]

        if not token:
            return {"message" : "API key is missing!"}, 401

        user_token = User().query.filter_by(freki_key=token).first()
        if not user_token:
            return {"message" : "Invalid API key!"}, 401

        return f(*args, **kwargs)

    return decorated

def get_bytes():
    """Returns the bytes of the uploaded file."""

    return upload_parser.parse_args()["file"].read()

def get_sha1(contents):
    """Returns the SHA-1 of the uploaded file."""

    return Hashes().get_sha1(contents)

from . import general
from . import pe
from . import user
from . import report
