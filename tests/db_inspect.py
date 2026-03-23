"""
SQLite Database Inspector
Run: python db_inspect.py
Gives you a MySQL-like view of your database structure and data.
"""

import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ids.db")


def connect():
    return sqlite3.connect(DB_PATH)


def show_databases():
    """Like MySQL: SHOW DATABASES;"""
    print("\n" + "=" * 60)
    print("  DATABASE FILE")
    print("=" * 60)
    size = os.path.getsize(DB_PATH) / 1024
    print(f"  Path : {DB_PATH}")
    print(f"  Size : {size:.1f} KB")
    print("=" * 60)


def show_tables():
    """Like MySQL: SHOW TABLES;"""
    conn = connect()
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
    tables = cursor.fetchall()
    conn.close()

    print("\n" + "=" * 60)
    print("  TABLES")
    print("=" * 60)
    for i, (name,) in enumerate(tables, 1):
        print(f"  {i}. {name}")
    print("=" * 60)
    return [t[0] for t in tables]


def describe_table(table_name):
    """Like MySQL: DESCRIBE table_name;"""
    conn = connect()
    cursor = conn.cursor()
    cursor.execute(f"PRAGMA table_info('{table_name}')")
    columns = cursor.fetchall()
    conn.close()

    print(f"\n{'=' * 70}")
    print(f"  DESCRIBE `{table_name}`")
    print(f"{'=' * 70}")
    print(f"  {'#':<4} {'Column':<25} {'Type':<15} {'Null':<6} {'Default':<10} {'PK'}")
    print(f"  {'-'*4} {'-'*25} {'-'*15} {'-'*6} {'-'*10} {'-'*3}")
    for col in columns:
        cid, name, col_type, notnull, default, pk = col
        null_str = "NO" if notnull else "YES"
        default_str = str(default) if default is not None else "None"
        pk_str = "YES" if pk else ""
        print(f"  {cid:<4} {name:<25} {col_type:<15} {null_str:<6} {default_str:<10} {pk_str}")
    print(f"{'=' * 70}")
    return columns


def show_indexes(table_name):
    """Like MySQL: SHOW INDEX FROM table_name;"""
    conn = connect()
    cursor = conn.cursor()
    cursor.execute(f"PRAGMA index_list('{table_name}')")
    indexes = cursor.fetchall()
    conn.close()

    if indexes:
        print(f"\n  Indexes on `{table_name}`:")
        for idx in indexes:
            print(f"    - {idx[1]} (unique={idx[2]})")
    else:
        print(f"\n  No indexes on `{table_name}`")


def select_data(table_name, limit=10):
    """Like MySQL: SELECT * FROM table_name LIMIT 10;"""
    conn = connect()
    cursor = conn.cursor()

    # Get row count
    cursor.execute(f"SELECT COUNT(*) FROM '{table_name}'")
    count = cursor.fetchone()[0]

    # Get column names
    cursor.execute(f"PRAGMA table_info('{table_name}')")
    columns = [col[1] for col in cursor.fetchall()]

    # Get data
    cursor.execute(f"SELECT * FROM '{table_name}' LIMIT {limit}")
    rows = cursor.fetchall()
    conn.close()

    print(f"\n{'=' * 70}")
    print(f"  SELECT * FROM `{table_name}` LIMIT {limit};  (Total rows: {count})")
    print(f"{'=' * 70}")

    if not rows:
        print("  (empty table - no data)")
        print(f"{'=' * 70}")
        return

    # Calculate column widths
    col_widths = []
    for i, col in enumerate(columns):
        max_width = len(col)
        for row in rows:
            val = str(row[i]) if row[i] is not None else "NULL"
            max_width = max(max_width, min(len(val), 40))  # cap at 40 chars
        col_widths.append(max_width)

    # Print header
    header = "  | ".join(col.ljust(w) for col, w in zip(columns, col_widths))
    separator = "-+-".join("-" * w for w in col_widths)
    print(f"  {header}")
    print(f"  {separator}")

    # Print rows
    for row in rows:
        values = []
        for i, val in enumerate(row):
            s = str(val) if val is not None else "NULL"
            if len(s) > 40:
                s = s[:37] + "..."
            values.append(s.ljust(col_widths[i]))
        print(f"  {'  | '.join(values)}")

    print(f"{'=' * 70}")
    if count > limit:
        print(f"  ... and {count - limit} more rows")


def show_create_table(table_name):
    """Like MySQL: SHOW CREATE TABLE table_name;"""
    conn = connect()
    cursor = conn.cursor()
    cursor.execute(f"SELECT sql FROM sqlite_master WHERE name='{table_name}'")
    result = cursor.fetchone()
    conn.close()

    print(f"\n{'=' * 70}")
    print(f"  CREATE TABLE statement for `{table_name}`:")
    print(f"{'=' * 70}")
    if result and result[0]:
        print(f"  {result[0]}")
    print(f"{'=' * 70}")


def full_report():
    """Generate a complete MySQL-like report of the database."""
    print("\n" + "#" * 70)
    print("#  SQLite Database Inspector - Full Report")
    print("#" * 70)

    show_databases()
    tables = show_tables()

    for table in tables:
        if table == "sqlite_sequence":
            continue  # Skip internal table
        print(f"\n\n{'*' * 70}")
        print(f"  TABLE: {table}")
        print(f"{'*' * 70}")
        show_create_table(table)
        describe_table(table)
        show_indexes(table)
        select_data(table, limit=10)


if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        print(f"Database not found at: {DB_PATH}")
    else:
        full_report()
