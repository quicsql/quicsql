#!/usr/bin/env python3
"""SQLAlchemy on quicSQL via the official libSQL dialect (sqlalchemy-libsql).

    python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
    .venv/bin/python main.py        (env: QUICSQL_URL, QUICSQL_TOKEN)

The dialect URL is `sqlite+libsql://host:port/<db>` — plain HTTP by default,
add ?secure=true for HTTPS. The auth token travels in connect_args.
"""

import os
import sys
from urllib.parse import urlparse

from sqlalchemy import Column, Integer, Text, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Session

BASE = os.environ.get("QUICSQL_URL", "http://127.0.0.1:7775")
TOKEN = os.environ.get("QUICSQL_TOKEN", "dev-token")

host = urlparse(BASE).netloc  # host:port for the dialect URL
engine = create_engine(
    f"sqlite+libsql://{host}/app",
    connect_args={"auth_token": TOKEN},
)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users_sqlalchemy"
    id = Column(Integer, primary_key=True)
    name = Column(Text, nullable=False)
    balance = Column(Integer, nullable=False)


def check(cond: bool, msg: str) -> None:
    if not cond:
        print(f"FAIL: {msg}", file=sys.stderr)
        sys.exit(1)


Base.metadata.create_all(engine)

with Session(engine) as session:
    session.query(User).delete()
    session.add_all([User(name="ada", balance=100), User(name="bob", balance=100)])
    session.commit()

    # An ORM transaction: both updates land atomically on commit.
    ada = session.execute(select(User).where(User.name == "ada")).scalar_one()
    bob = session.execute(select(User).where(User.name == "bob")).scalar_one()
    ada.balance -= 30
    bob.balance += 30
    session.commit()

    rows = session.execute(select(User.name, User.balance).order_by(User.name)).all()
    got = ",".join(f"{n}={b}" for n, b in rows)
    check(got == "ada=70,bob=130", f"ORM rows after transaction, got {got}")

print("OK python-sqlalchemy")
