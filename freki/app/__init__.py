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
import time
import atexit

from pathlib import Path

from apscheduler.schedulers.background import BackgroundScheduler
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.contrib.fixers import ProxyFix

from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError
from sqlalchemy_utils import create_database, database_exists
from .core.virustotal import VirusTotal

db = SQLAlchemy()

app = Flask(__name__, template_folder="templates")
app.wsgi_app = ProxyFix(app.wsgi_app)
app.config.from_object("config.ProductionConfig")
vt_master_key = app.config["VT_MASTER_KEY"]
samples_dir = app.config["SAMPLES_DIR"]

def create_freki_files():
    """Creates the samples folder and the database tables."""

    Path(samples_dir).mkdir(parents=True, exist_ok=True)
    db_uri = app.config["SQLALCHEMY_DATABASE_URI"]

    try:
        engine = create_engine(db_uri)
        if not database_exists(db_uri):
            create_database(db_uri)

        from .models import create_tables
        create_tables(engine)

        print("[*] Database status: Connected successfully!")
    except OperationalError as error:
        print("[!] Could not connect to the database!\n\nCurrent settings:")
        print("Database user: freki")
        print("Database server:", app.config["DB_SERVER"])
        print("Database password:", app.config["DB_PASSWORD"])
        exit(1)

    # Query VirusTotal every 5 min.
    scheduler = BackgroundScheduler()
    scheduler.add_job(func=fetch_vt_data, trigger="interval", seconds=300)
    scheduler.start()
    atexit.register(lambda: scheduler.shutdown())

def configure_app():
    """Configures the web client and API."""

    create_freki_files()

    login_manager = LoginManager()
    login_manager.login_view = "web.login"
    login_manager.init_app(app)

    from .models import User

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # Set a default limit of 4 requests per minute.
    limiter = Limiter(app, default_limits=["4/minute"],
                      key_func=get_remote_address)

    # Register blueprints.
    from .web import web as main_blueprint
    app.register_blueprint(main_blueprint)
    limiter.exempt(main_blueprint)

    from .api import api_blueprint as api_blueprint
    app.register_blueprint(api_blueprint, url_prefix="/api")

    @app.errorhandler(404)
    def page_not_found(error):
        """Renders a custom 404 page."""
        return render_template("error/404.html"), 404

    @app.errorhandler(405)
    def method_not_allowed(error):
        """Redirects the user to the homepage."""
        return redirect(url_for("web.index"))

    @app.errorhandler(413)
    @app.errorhandler(RequestEntityTooLarge)
    def request_entity_too_large(error):
        """Displays a message if the file is too large."""
        flash("Maximum upload file size: {}".format(app.config["MAX_CONTENT_LENGTH"]))
        return redirect(url_for("web.index")), 413

    db.init_app(app)

    return app

def fetch_vt_data():
    """Updates the VT results."""

    from .models import Submission, Log

    request_count = 1
    with app.app_context():
        submissions = Submission().query.filter_by(vt_analyzed=0).all()

        for sub in submissions:
            log = Log().query.filter_by(submission_id=sub.id).first()
            reporter_key = log.user.vt_key

            if request_count > 4:
                break

            vt_detection, status_code = VirusTotal(reporter_key).report(sub.sha1)

            # If the user key is invalid, try with the master key.
            if status_code == 401:
                vt_detection, status_code = VirusTotal(vt_master_key).report(sub.sha1)

            # Send the sample for analysis if it does not exist.
            if status_code == 404:
                sample = open("{0}/{1}/{1}".format(samples_dir, sub.sha1), "rb").read()
                vt_detection, status_code = VirusTotal(vt_master_key).detection(sample)

            request_count += 1

            if vt_detection:
                new_data = json.loads(sub.data)
                new_data["virustotal_detection"] = vt_detection

                sub.data = json.dumps(new_data)
                sub.vt_analyzed = True
                db.session.commit()
