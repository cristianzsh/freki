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

import sqlite3
from datetime import datetime
import json

class Database():
    """Manipulates the database."""

    def __init__(self, db_file):
        """Connects to the database."""

        self.con = sqlite3.connect(db_file, check_same_thread=False)
        self.con.execute("CREATE TABLE IF NOT EXISTS Files (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, sha1 TEXT NOT NULL, sha256 TEXT NOT NULL, name TEXT NOT NULL, os_path TEXT NOT NULL, sub_date TEXT NOT NULL, data JSON);")
        self.cur = self.con.cursor()

    def insert_file(self, sha1, sha256, name, os_path, data):
        """Inserts a new analysis."""

        self.con.execute("INSERT INTO Files (sha1, sha256, name, os_path, sub_date, data) VALUES (?, ?, ?, ?, ?, ?)", (sha1, sha256, name, os_path, datetime.now().strftime("%d/%m/%Y %H:%M:%S"), data))
        self.con.commit()

    def select_files(self, top=False):
        """Returns all or the latest 10 analysis."""

        with self.con:
            if top:
                self.cur.execute("SELECT * FROM Files ORDER BY sub_date DESC LIMIT 10")
            else:
                self.cur.execute("SELECT * FROM Files")

        return self.cur.fetchall()

    def get_first_last_submissions(self, sha256):
        """Returns the first and the last datetime of a submission."""

        with self.con:
            self.cur.execute("SELECT sub_date FROM Files WHERE sha256 = ?", (sha256,))
            rows = self.cur.fetchall()

        return [rows[0][0], rows[-1][0]]

    def get_file_names(self, sha256):
        """Returns the unique file names of a submission."""

        with self.con:
            self.cur.execute("SELECT DISTINCT name FROM Files WHERE sha256 = ?", (sha256,))
            rows = self.cur.fetchall()

            return rows

    def get_analysis(self, sha1):
        """Returns the latest analysis of a submission."""

        with self.con:
            self.cur.execute("SELECT data FROM Files WHERE sha1 = ? ORDER BY sub_date DESC LIMIT 1", (sha1,))
            row = self.cur.fetchall()
            if row:
                return json.loads(row[0][0])

        return None

    def update_analysis(self, sha1):
        """Removes past analysis of a submission."""

        self.cur.execute("UPDATE Files SET data = null WHERE sha1 = ?", (sha1, ))
        self.con.commit()
