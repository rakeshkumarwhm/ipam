"""Admin CLI:  python -m app.cli init-db | create-admin <username>"""
import getpass
import sys

from sqlalchemy.orm import Session

from .db import Base, init_engine
from .models import Role, User
from .security import hash_password, validate_password_strength


def main(argv: list[str]) -> int:
    if len(argv) < 2 or argv[1] not in ("init-db", "create-admin"):
        print(__doc__)
        return 2
    engine = init_engine()
    if argv[1] == "init-db":
        Base.metadata.create_all(engine)
        print("Tables created.")
        return 0
    if len(argv) != 3:
        print("usage: create-admin <username>")
        return 2
    pw = getpass.getpass("Password: ")
    if pw != getpass.getpass("Repeat: "):
        print("Passwords differ")
        return 1
    try:
        validate_password_strength(pw)
    except ValueError as e:
        print(e)
        return 1
    with Session(engine) as db:
        db.add(User(username=argv[2], password_hash=hash_password(pw), role=Role.admin))
        db.commit()
    print("Admin created.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
