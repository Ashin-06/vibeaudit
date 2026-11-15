import subprocess


def order_by_ref(conn, ref):
    return conn.execute(f"SELECT * FROM orders WHERE ref = '{ref}'")  # expect: BE001


def export(fmt):
    return _run(fmt)


def _run(fmt):
    subprocess.run("export-orders --format " + fmt, shell=True)  # expect: BE002


def order_by_id(conn, order_id):
    return conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,))
