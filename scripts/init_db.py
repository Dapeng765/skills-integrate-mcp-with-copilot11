"""Initialize SQLite DB and create a default admin user.

Usage:
    python scripts/init_db.py

This will create ./data.db and add a default admin (username: admin, password: adminpass)
"""
import sys
from pathlib import Path
# ensure repo root is on sys.path so `src` package can be imported when running this script
repo_root = str(Path(__file__).resolve().parents[1])
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from src.models import Base, get_db_engine, create_session, Admin
from passlib.context import CryptContext
from sqlalchemy.exc import IntegrityError
import os

pwd = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")


def init_db(database_url: str | None = None):
    engine = get_db_engine(database_url)
    Base.metadata.create_all(bind=engine)
    SessionLocal = create_session(engine)
    db = SessionLocal()
    try:
        # create default admin if not exists
        if not db.query(Admin).filter(Admin.username == "admin").first():
            admin = Admin(username="admin", password_hash=pwd.hash("adminpass"))
            db.add(admin)
            db.commit()
            print("Created default admin: username=admin password=adminpass")
        else:
            print("Admin user already exists, skipping creation")
    except IntegrityError:
        db.rollback()
    finally:
        db.close()


if __name__ == "__main__":
    init_db()
