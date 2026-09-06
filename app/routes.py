"""
Main Routes
"""

from flask import Blueprint, render_template, redirect, url_for

main = Blueprint("main", __name__)


@main.route("/")
def home():

    return render_template("index.html")


@main.route("/log-explorer/")
def log_explorer_redirect():
    return redirect(url_for("siem.log_explorer"))


@main.route("/vuln-scanner/")
def vuln_scanner_redirect():
    return redirect(url_for("scanner.index"))


@main.route("/scan-history/")
def scan_history_redirect():
    return redirect(url_for("scanner.history"))

