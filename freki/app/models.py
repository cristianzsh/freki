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

from flask_login import UserMixin
from sqlalchemy.dialects.mysql import LONGTEXT
from sqlalchemy.ext.declarative import declarative_base

from . import db

Base = declarative_base()

def create_tables(engine):
    """Creates the database tables."""
    Base.metadata.create_all(engine)

class User(Base, UserMixin, db.Model):
    """User fields."""

    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(90), nullable=False)
    vt_key = db.Column(db.String(64), nullable=True)
    freki_key = db.Column(db.String(255), nullable=False)

class Submission(Base, db.Model):
    """Submission fields."""

    __tablename__ = "submissions"
    id = db.Column(db.Integer, primary_key=True)
    sha1 = db.Column(db.String(40), unique=True, nullable=False)
    sha256 = db.Column(db.String(64), unique=True, nullable=False)
    data = db.Column(LONGTEXT, nullable=False)
    vt_analyzed = db.Column(db.Boolean, default=False)

class Log(Base, db.Model):
    """Log fields."""

    __tablename__ = "logs"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    sub_date = db.Column(db.String(19), nullable=False)
    submission_id = db.Column(db.Integer, db.ForeignKey("submissions.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    submission = db.relationship("Submission", backref="logs")
    user = db.relationship("User", backref="logs")

class Comment(Base, db.Model):
    """Comment fields."""

    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(4000), nullable=False)
    date = db.Column(db.String(19), nullable=False)
    submission_id = db.Column(db.Integer, db.ForeignKey("submissions.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    submission = db.relationship("Submission", backref="comments")
    user = db.relationship("User", backref="comments")
