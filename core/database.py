import sqlite3

DB="data/scan.db"

def init_db():

    conn=sqlite3.connect(DB)
    c=conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS scans(
        target TEXT,
        port INTEGER,
        service TEXT
    )
    """)

    conn.commit()
    conn.close()


def save_port(target,port,service):

    conn=sqlite3.connect(DB)
    c=conn.cursor()

    c.execute(
        "INSERT INTO scans VALUES(?,?,?)",
        (target,port,service)
    )

    conn.commit()
    conn.close()