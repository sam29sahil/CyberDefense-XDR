from flask import render_template

from app.dashboard import dashboard


@dashboard.route("/")
def index():
    return render_template("dashboard/dashboard.html")
