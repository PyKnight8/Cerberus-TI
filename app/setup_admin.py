"""Run `python -m app.setup_admin` once, with a hidden password prompt."""

from getpass import getpass

from app.config import load_settings
from app.database import Database
from app.management import set_password


def main():
    password = getpass("New administrator password (12+ characters): ")
    confirmation = getpass("Confirm password: ")
    if password != confirmation:
        raise SystemExit("Passwords do not match")
    db = Database(load_settings().database_url)
    db.initialize()
    set_password(db, password)
    db.engine.dispose()
    print("Administrator password saved")


if __name__ == "__main__":
    main()
