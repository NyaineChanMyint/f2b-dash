#!/usr/bin/env python3
"""Create or reset a local Fail2Ban Dashboard user.

Passwords are read from the environment, avoiding command-history exposure.
"""
import argparse
import os

import central


def main():
    parser = argparse.ArgumentParser(description="Create or reset a dashboard user")
    parser.add_argument("--reset", action="store_true", help="replace the password when the user already exists")
    args = parser.parse_args()
    username = os.environ.get("F2B_NEW_USERNAME", "")
    password = os.environ.get("F2B_NEW_PASSWORD", "")
    if not central.valid_username(username):
        parser.error("F2B_NEW_USERNAME must be 3-64 characters: letters, digits, ., _, -")
    try:
        digest, salt = central.password_hash(password)
    except ValueError as exc:
        parser.error(str(exc))
    central.initialise()
    with central.db() as conn:
        existing = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
        if existing and not args.reset:
            parser.error("user already exists; use --reset to replace its password")
        if existing:
            conn.execute("UPDATE users SET password_hash=?, password_salt=? WHERE id=?", (digest, salt, existing["id"]))
            print("Password reset for user: " + username)
        else:
            conn.execute("INSERT INTO users(username,password_hash,password_salt,role,created_at) VALUES(?,?,?,?,?)", (username, digest, salt, "viewer", central.iso_now()))
            print("Created user: " + username)


if __name__ == "__main__":
    main()

