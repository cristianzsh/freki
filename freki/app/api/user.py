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
from werkzeug import check_password_hash

from app.models import User

from . import api, ns_user

usr_parser = api.parser()
usr_parser.add_argument("email", required=True)
usr_parser.add_argument("password", required=True)

@ns_user.route("/get_token", methods=["GET"])
class GetToken(Resource):
    """Gets the user token."""

    @api.doc(responses={200: "Success",
                        404 : "User not found",
                        429 : "API request rate limit exceeded"})
    @api.expect(usr_parser)
    def get(self):
        """Returns the user API key."""

        args = usr_parser.parse_args()
        email = args["email"]
        password = args["password"]

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            return {"token" : user.freki_key}, 200

        return {"message" : "Invalid credentials!"}, 404

@ns_user.route("/get_info", methods=["GET"])
class GetInfo(Resource):
    """Gets user data."""

    @api.doc(responses={200: "Success",
                        404 : "User not found",
                        429 : "API request rate limit exceeded"})
    @api.expect(usr_parser)
    def get(self):
        """Returns user information."""

        args = usr_parser.parse_args()
        email = args["email"]
        password = args["password"]

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            info = {"username" : user.username,
                    "email" : user.email,
                    "token" : user.freki_key,
                    "vt_key" : user.vt_key}
            return info, 200

        return {"message" : "Invalid credentials!"}, 404
