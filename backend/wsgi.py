"""Production WSGI entry point.

Run with a production server such as:
    gunicorn --chdir backend wsgi:app
"""
from app import create_app

app = create_app()
