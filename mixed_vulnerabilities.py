import os
import pickle
import sqlite3
import subprocess
import logging
import urllib.request
from flask import Flask, request, redirect, Response

app = Flask(__name__)
db_connection = None


# --- CRITICAL: SQL Injection (CWE-89) ---

@app.route("/v2/user")
def get_user():
    uid = request.args.get("id", "")
    query = f"SELECT * FROM users WHERE id = {uid}"
    cursor = db_connection.cursor()
    cursor.execute(query)
    return Response(str(cursor.fetchall()), mimetype="text/plain")


@app.route("/v2/search")
def search():
    q = request.args.get("q", "")
    query = "SELECT * FROM users WHERE name LIKE '%" + q + "%'"
    cursor = db_connection.cursor()
    cursor.execute(query)
    return Response(str(cursor.fetchall()), mimetype="text/plain")


# --- CRITICAL: Command Injection (CWE-78) ---

@app.route("/v2/ping")
def ping():
    host = request.args.get("host", "")
    result = subprocess.check_output("ping -c 1 " + host, shell=True)
    return Response(result, mimetype="text/plain")


# --- HIGH: Reflected XSS (CWE-79) ---

@app.route("/v2/greet")
def greet():
    name = request.args.get("name", "")
    return Response(f"<html><body><h1>Hello, {name}!</h1></body></html>", mimetype="text/html")


# --- HIGH: Path Traversal (CWE-22) ---

@app.route("/v2/read")
def read_file():
    fname = request.args.get("file", "")
    with open("/data/" + fname, "r") as f:
        return Response(f.read(), mimetype="text/plain")


# --- HIGH: Deserialization (CWE-502) ---

@app.route("/v2/load", methods=["POST"])
def load_data():
    data = pickle.loads(request.get_data())
    return Response(str(data), mimetype="text/plain")


# --- MEDIUM: Open Redirect (CWE-601) ---

@app.route("/v2/redirect")
def redir():
    url = request.args.get("url", "/")
    return redirect(url)


# --- MEDIUM: SSRF (CWE-918) ---

@app.route("/v2/fetch")
def fetch():
    url = request.args.get("url", "")
    resp = urllib.request.urlopen(url)
    return Response(resp.read(), mimetype="text/plain")


# --- Init ---

def init_db():
    global db_connection
    db_connection = sqlite3.connect(":memory:", check_same_thread=False)
    cur = db_connection.cursor()
    cur.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)")
    cur.execute("INSERT INTO users VALUES (1, 'admin', 'admin@test.com')")
    db_connection.commit()


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=8080, debug=True)
