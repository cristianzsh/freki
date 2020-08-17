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

import re
import jwt

from flask_login import login_user, logout_user, login_required, current_user
from flask import render_template, redirect, request, url_for, flash
from werkzeug import generate_password_hash, check_password_hash
from sqlalchemy.exc import DataError
from sqlalchemy import or_

from app import db, app
from app.models import User, Log, Comment, Submission

from . import web

def validate_password(password):
    """Validates a password."""

    if len(password) < 8:
        flash("Make sure your password is at lest 8 letters.")
        return False
    elif re.search("[0-9]", password) is None:
        flash("Make sure your password has a number in it.")
        return False
    elif re.search("[a-z]", password) is None:
        flash("Make sure your password has a letter in it.")
        return False
    elif re.search("[A-Z]", password) is None:
        flash("Make sure your password has a capital letter in it.")
        return False

    return True

@web.route("/login")
def login():
    """Renders the login page."""

    return render_template("auth/login.html")

@web.route("/login", methods=["POST"])
def login_post():
    """Authenticates the user."""

    user_field = request.form.get("user")
    password = request.form.get("password")

    user = User.query.filter(or_(User.email == user_field, User.username == user_field)).first()
    if user and check_password_hash(user.password, password):
        login_user(user)
        return redirect(url_for("web.index"))

    flash("Invalid credentials!")
    return redirect(url_for("web.login"))

@web.route("/signup")
def signup():
    """Renders the sign up page."""

    return render_template("auth/signup.html")

@web.route("/signup", methods=["POST"])
def signup_post():
    """Creates a new user."""

    username = request.form.get("username")
    email = request.form.get("email")
    password = request.form.get("password")

    user = User.query.filter(or_(User.email == email, User.username == username)).first()
    if user:
        flash("This email or username is already being used.")
        return redirect(url_for("web.signup"))

    if not validate_password(password):
        return redirect(url_for("web.signup"))

    # Generate the user API key.
    user_token = jwt.encode({"username" : username, "date" : str(datetime.utcnow())},
                            app.config["SECRET_KEY"])

    new_user = User(email=email, username=username,
                    password=generate_password_hash(password, method="sha256"),
                    freki_key=user_token)
    db.session.add(new_user)

    try:
        db.session.commit()
    except DataError:
        flash("Invalid credentials.")
        return redirect(url_for("web.signup"))

    return redirect(url_for("web.login"))

@web.route("/logout")
@login_required
def logout():
    """Logs the user out."""

    logout_user()
    return redirect(url_for("web.index"))

@web.route("/profile")
@login_required
def profile():
    """Renders the profile page."""

    my_submissions = Log.query.filter_by(user_id=current_user.id).all()
    my_comments = Comment.query.filter(Comment.user.has(id=current_user.id)).\
                                order_by(Comment.date.desc()).all()

    return render_template("auth/profile.html",
                           my_submissions=my_submissions,
                           my_comments=my_comments)

@web.route("/update_profile", methods=["POST"])
@login_required
def update_profile():
    """Updates user information."""

    username = request.form.get("username").strip() or current_user.username
    passwd = current_user.password
    vt_key = request.form.get("vt_key").strip() or None

    if request.form.get("password").strip():
        passwd = generate_password_hash(request.form.get("password"),
                                        method="sha256")

    user = User.query.filter_by(id=current_user.id).first()
    user.username = username
    user.password = passwd
    user.vt_key = vt_key
    try:
        db.session.commit()
    except DataError:
        flash("Invalid information!")

    return redirect(url_for("web.profile"))

@web.route("/new_comment/<sha1>", methods=["POST"])
@login_required
def new_comment(sha1):
    """Inserts a new comment."""

    text = request.form.get("comment_text")
    submission = Submission().query.filter_by(sha1=sha1).first()

    comment = Comment(text=text,
                      submission_id=submission.id,
                      user_id=current_user.id,
                      date=datetime.now().strftime("%d/%m/%Y %H:%M:%S"))
    db.session.add(comment)
    try:
        db.session.commit()
    except DataError:
        flash("Your comment is too long!")

    return redirect(request.referrer)

@web.route("/edit_comment/<comment_id>", methods=["POST"])
@login_required
def edit_comment(comment_id):
    """Updates the specified comment."""

    text = request.form.get("text")
    comment = Comment.query.filter_by(id=comment_id).first()
    if comment.user.id == current_user.id:
        comment.text = text
        try:
            db.session.commit()
        except DataError:
            flash("Your comment is too long!")

    return redirect(request.referrer)

@web.route("/delete_comment/<comment_id>", methods=["GET"])
@login_required
def delete_comment(comment_id):
    """Deletes the specified comment."""

    comment = Comment.query.filter_by(id=comment_id).first()
    if comment and comment.user_id == current_user.id:
        db.session.delete(comment)
        db.session.commit()

        return redirect(request.referrer)

    return redirect(url_for("web.index"))
