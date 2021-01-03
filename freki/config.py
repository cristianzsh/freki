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

from os import environ

class Config(): # pylint: disable=R0903
    """Base config."""

    DEBUG = False
    TESTING = False

    SECRET_KEY = environ.get("FREKI_SECRET_KEY")
    VT_MASTER_KEY = environ.get("FREKI_VT_MASTER_KEY")
    DB_SERVER = environ.get("FREKI_MYSQL_HOST")
    DB_PASSWORD = environ.get("FREKI_MYSQL_PASSWORD")
    SSL_CONTEXT = "adhoc"
    SAMPLES_DIR = "/opt/freki/files"
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_DATABASE_URI = "mysql://freki:{}@{}/freki".format(DB_PASSWORD, DB_SERVER)

class ProductionConfig(Config): # pylint: disable=R0903
    """Production config."""

    DEBUG = False

class DevelopmentConfig(Config): # pylint: disable=R0903
    """Development config."""

    DEVELOPMENT = True
    DEBUG = True
    ENV = "development"

class TestingConfig(Config): # pylint: disable=R0903
    """Testing config."""

    TESTING = True
