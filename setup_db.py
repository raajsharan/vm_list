"""
setup_db.py
-----------
One-time script: creates the 'vmware_inventory' PostgreSQL database (if it
does not already exist) and then creates all ORM tables inside it.

Run once before starting the app:
    python setup_db.py
"""

import os
import sys

import psycopg
from psycopg import sql
from dotenv import load_dotenv

load_dotenv()

DB_NAME = "vmware_inventory"
DB_USER = "postgres"
DB_PASS = "Password@1234"
DB_HOST = "localhost"
DB_PORT = 5432


def create_database():
    with psycopg.connect(
        dbname="postgres",
        user=DB_USER,
        password=DB_PASS,
        host=DB_HOST,
        port=DB_PORT,
        autocommit=True,
    ) as conn:
        row = conn.execute(
            "SELECT 1 FROM pg_database WHERE datname = %s", (DB_NAME,)
        ).fetchone()

        if row:
            print(f"Database '{DB_NAME}' already exists — skipping creation.")
        else:
            conn.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(DB_NAME)))
            print(f"Database '{DB_NAME}' created.")


def create_tables():
    import database
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        print("ERROR: DATABASE_URL not set. Check your .env file.")
        sys.exit(1)
    database.init_app(database_url)
    print("All tables created (or already exist).")


if __name__ == "__main__":
    print("=== VMware Inventory — database setup ===")
    create_database()
    create_tables()
    print("Done.")
