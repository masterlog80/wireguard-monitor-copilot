"""Authentication blueprint."""
from __future__ import annotations

from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user, logout_user, login_required, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

from config import Config

auth_bp = Blueprint("auth", __name__)


class User(UserMixin):
    """Single hard-coded admin user (credentials stored via env vars)."""

    def __init__(self, username: str):
        self.id = username
        self.username = username
        self._password_hash = generate_password_hash(Config.ADMIN_PASSWORD)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self._password_hash, password)

    def __repr__(self) -> str:
        return f"<User {self.username}>"


# One singleton user created at module load time.
_admin_user = User(Config.ADMIN_USERNAME)


def load_user(user_id: str) -> User | None:
    if user_id == _admin_user.id:
        return _admin_user
    return None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if username == _admin_user.username and _admin_user.check_password(password):
            login_user(_admin_user, remember=True)
            next_page = request.args.get("next") or url_for("main.dashboard")
            return redirect(next_page)
        flash("Invalid username or password.", "danger")
    return render_template("login.html")


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))
