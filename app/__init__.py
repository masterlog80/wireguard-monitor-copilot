"""Flask application factory."""
from __future__ import annotations

from flask import Flask
from flask_login import LoginManager

from config import Config
from .auth import User, load_user


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)

    # --- Flask-Login setup ---
    login_manager = LoginManager()
    login_manager.login_view = "auth.login"  # type: ignore[assignment]
    login_manager.login_message_category = "info"
    login_manager.init_app(app)

    @login_manager.user_loader
    def _load_user(user_id: str):
        return load_user(user_id)

    # --- Register blueprints ---
    from .routes import main_bp
    from .auth import auth_bp
    from .users import users_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(users_bp)

    # --- Start background poller ---
    from . import wireguard

    wireguard.start_poller(interval=5.0)

    return app
