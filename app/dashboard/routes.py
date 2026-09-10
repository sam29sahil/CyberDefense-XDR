from flask import render_template
from flask_login import login_required
from app.dashboard import dashboard
from app.user_management.decorators import permission_required


@dashboard.route("/")
@login_required
@permission_required("dashboard.view")
def index():
    return render_template("dashboard/dashboard.html")
