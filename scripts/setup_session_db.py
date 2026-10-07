"""
One-time setup: create the session database (if missing) and its table.

Reads OVELA_SESSION_DB_CONNECTION. The connection string must include
DATABASE=<name>. Run from the project root:

    .\\.venv\\Scripts\\python.exe -m scripts.setup_session_db
"""

from __future__ import annotations

import os
import re
import sys
from contextlib import closing

from app.session_store import (
    ENV_VAR,
    SessionStoreError,
    SqlServerSessionStore,
)


def main() -> int:
    connection_string = os.environ.get(ENV_VAR, "").strip()

    if not connection_string:
        print(f"{ENV_VAR} is not set.")
        return 1

    database_name = None
    server_parts: list[str] = []

    for part in connection_string.split(";"):
        if not part.strip():
            continue

        key, _, value = part.partition("=")

        if key.strip().upper() in ("DATABASE", "INITIAL CATALOG"):
            database_name = value.strip()
            continue

        server_parts.append(part)

    if not database_name:
        print("The connection string must include DATABASE=<name>.")
        return 1

    if not re.fullmatch(r"[A-Za-z0-9_]+", database_name):
        print("Database name may contain only letters, digits and underscore.")
        return 1

    import pyodbc

    master_connection_string = ";".join(server_parts + ["DATABASE=master"])

    try:
        with closing(
            pyodbc.connect(master_connection_string, autocommit=True, timeout=5)
        ) as conn:
            conn.cursor().execute(
                f"IF DB_ID(N'{database_name}') IS NULL "
                f"CREATE DATABASE [{database_name}]"
            )

        SqlServerSessionStore(connection_string).create_schema()
    except (SessionStoreError, pyodbc.Error) as exc:
        print(f"Setup failed: {type(exc).__name__}: {str(exc)[:300]}")
        return 1

    print(f"OK: database '{database_name}' and table dbo.Sessions are ready.")
    return 0


if __name__ == "__main__":
    sys.exit(main())