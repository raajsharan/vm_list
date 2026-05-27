"""
setup_db.py
-----------
One-time script: creates the application PostgreSQL database (if missing)
and all ORM tables inside it.

Reads connection parameters from .env:
    DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD

DB_USER must have CREATE DATABASE privilege (e.g. a superuser like
'postgres') for the initial run. After the database exists, the app
can connect as a less-privileged user.

Run once before starting the app:
    python setup_db.py
"""

import os
import sys

import psycopg
from psycopg import sql
from dotenv import load_dotenv

load_dotenv()


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def create_database():
    db_name = _env("DB_NAME")
    db_user = _env("DB_USER")
    db_pass = _env("DB_PASSWORD")
    db_host = _env("DB_HOST", "localhost")
    db_port = int(_env("DB_PORT", "5432") or 5432)

    if not db_name or not db_user:
        print("ERROR: DB_NAME and DB_USER must be set in .env.")
        sys.exit(1)

    with psycopg.connect(
        dbname="postgres",
        user=db_user,
        password=db_pass,
        host=db_host,
        port=db_port,
        autocommit=True,
    ) as conn:
        row = conn.execute(
            "SELECT 1 FROM pg_database WHERE datname = %s", (db_name,)
        ).fetchone()

        if row:
            print(f"Database '{db_name}' already exists — skipping creation.")
        else:
            conn.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(db_name)))
            print(f"Database '{db_name}' created.")


def create_tables():
    import database
    url = os.environ.get("DATABASE_URL") or database.build_url_from_env()
    if not url:
        print("ERROR: Database connection vars not set. "
              "Set DB_HOST/DB_PORT/DB_NAME/DB_USER/DB_PASSWORD in .env.")
        sys.exit(1)
    database.init_app(url)
    print("All tables created (or already exist).")


if __name__ == "__main__":
    print("=== VMware Inventory — database setup ===")
    create_database()
    create_tables()
    print("Done.")
