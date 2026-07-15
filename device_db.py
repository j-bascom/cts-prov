import sqlite3
import os
from datetime import datetime, timedelta

DB_PATH = os.getenv("DB_PATH", "/opt/cts-prov/devices.db")


def _connect():
    return sqlite3.connect(DB_PATH)


def init_db():
    con = _connect()
    con.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            mac       TEXT PRIMARY KEY,
            label     TEXT NOT NULL DEFAULT '',
            tenant    TEXT NOT NULL DEFAULT '',
            added_at  DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    con.commit()
    # Migration: add last_seen column if it doesn't exist yet
    try:
        con.execute("ALTER TABLE devices ADD COLUMN last_seen DATETIME")
        con.commit()
    except Exception:
        pass  # Column already exists
    con.close()


def get_device(mac: str) -> dict | None:
    con = _connect()
    row = con.execute(
        "SELECT mac, label, tenant, added_at, last_seen FROM devices WHERE mac = ?", (mac,)
    ).fetchone()
    con.close()
    if not row:
        return None
    return {"mac": row[0], "label": row[1], "tenant": row[2], "added_at": row[3], "last_seen": row[4]}


def add_device(mac: str, label: str = "", tenant: str = ""):
    con = _connect()
    con.execute(
        "INSERT OR REPLACE INTO devices (mac, label, tenant) VALUES (?, ?, ?)",
        (mac, label, tenant)
    )
    con.commit()
    con.close()


def delete_device(mac: str):
    con = _connect()
    con.execute("DELETE FROM devices WHERE mac = ?", (mac,))
    con.commit()
    con.close()


def list_devices() -> list:
    con = _connect()
    rows = con.execute(
        "SELECT mac, label, tenant, added_at, last_seen FROM devices ORDER BY added_at DESC"
    ).fetchall()
    con.close()
    return [
        {"mac": r[0], "label": r[1], "tenant": r[2], "added_at": r[3], "last_seen": r[4]}
        for r in rows
    ]


def update_last_seen(mac: str):
    """Set last_seen to CURRENT_TIMESTAMP for the given MAC."""
    con = _connect()
    con.execute(
        "UPDATE devices SET last_seen = CURRENT_TIMESTAMP WHERE mac = ?", (mac,)
    )
    con.commit()
    con.close()


def delete_stale_devices(days: int, exclude_macs: set) -> list:
    """
    Delete devices where last_seen IS NULL OR last_seen < (now - days),
    excluding any MAC in exclude_macs. Returns list of deleted MACs.
    """
    cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()
    con = _connect()
    rows = con.execute(
        "SELECT mac FROM devices WHERE (last_seen IS NULL OR last_seen < ?)",
        (cutoff,)
    ).fetchall()
    deleted = []
    for (mac,) in rows:
        if mac not in exclude_macs:
            con.execute("DELETE FROM devices WHERE mac = ?", (mac,))
            deleted.append(mac)
    con.commit()
    con.close()
    return deleted
