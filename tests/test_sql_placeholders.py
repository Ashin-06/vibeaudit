"""BE001 must accept SQL whose only formatted part is a list of bind markers, and still flag everything else."""
from vibeaudit.external import parse_bandit
from vibeaudit.scanner import Options, scan

SAFE = '''\
from flask import request


def rubicon_drop(db, chunk):
    db.execute(f"DELETE FROM rubicon_journal WHERE tx IN ({','.join('?' * len(chunk))})", chunk)


def list_times_n(db, ids):
    db.execute(f"SELECT * FROM t WHERE id IN ({','.join(['?'] * len(ids))})", ids)


def generator(db, ids):
    db.execute(f"SELECT * FROM t WHERE id IN ({', '.join('?' for _ in ids)})", ids)


def percent_s_with_percent_operator(cur, ids):
    cur.execute("SELECT * FROM t WHERE id IN (%s)" % ",".join(["%s"] * len(ids)), ids)


def percent_s_with_format(cur, ids):
    cur.execute("SELECT * FROM t WHERE id IN ({})".format(", ".join(["%s"] * len(ids))), ids)


def concatenation(db, ids):
    db.execute("SELECT * FROM t WHERE id IN (" + ",".join("?" * len(ids)) + ")", ids)


def named_from_range(conn, ids):
    conn.execute(f"SELECT * FROM t WHERE id IN ({', '.join(f':p{i}' for i in range(len(ids)))})",
                 {f"p{i}": v for i, v in enumerate(ids)})


def named_from_enumerate_index(conn, ids):
    marks = ", ".join(f":p{i}" for i, _ in enumerate(ids))
    conn.execute(f"SELECT * FROM t WHERE id IN ({marks})", {f"p{i}": v for i, v in enumerate(ids)})


def separate_variables(db, ids):
    placeholders = ",".join("?" * len(ids))
    query = f"DELETE FROM t WHERE id IN ({placeholders})"
    db.execute(query, ids)


def leading_comma_run(db, ids):
    db.execute(f"SELECT * FROM t WHERE id IN (?{',?' * (len(ids) - 1)})", ids)


def numbered_postgres(cur, ids):
    cur.execute(f"SELECT * FROM t WHERE id IN ({', '.join(f'${i + 1}' for i in range(len(ids)))})", ids)


@app.get("/api/items")
def request_ids_as_parameters():
    ids = request.args.getlist("id")
    rows = db.execute(f"SELECT * FROM t WHERE id IN ({','.join('?' * len(ids))})", ids)
    return {"rows": rows}
'''

UNSAFE = '''\
from flask import request


def join_over_values(db, ids):
    db.execute(f"SELECT * FROM t WHERE id IN ({','.join(ids)})")  # unsafe


def value_in_quotes(db, name):
    db.execute(f"SELECT * FROM t WHERE name = '{name}'")  # unsafe


def identifier_from_caller(db, table):
    db.execute(f"SELECT * FROM {table} WHERE id = ?", (1,))  # unsafe


def named_markers_from_data(db, cols):
    db.execute(f"SELECT * FROM t WHERE x IN ({', '.join(f':{c}' for c in cols)})")  # unsafe


def enumerate_element_not_index(db, ids):
    marks = ", ".join(f":{v}" for i, v in enumerate(ids))
    db.execute(f"SELECT * FROM t WHERE id IN ({marks})")  # unsafe


def stringified_values(db, ids):
    marks = ",".join(str(i) for i in ids)
    db.execute(f"DELETE FROM t WHERE id IN ({marks})")  # unsafe


def placeholders_plus_a_value(db, ids, owner):
    db.execute(f"SELECT * FROM t WHERE id IN ({','.join('?' * len(ids))}) AND owner = '{owner}'", ids)  # unsafe


def percent_operator_with_value(cur, name):
    cur.execute("SELECT * FROM t WHERE name = '%s'" % name)  # unsafe


@app.get("/api/search")
def request_values_joined():
    ids = request.args.getlist("id")
    rows = db.execute(f"SELECT * FROM t WHERE id IN ({','.join(ids)})")  # unsafe
    return {"rows": rows}
'''


def _be001_lines(tmp_path, name, source):
    (tmp_path / name).write_text(source)
    res = scan(str(tmp_path), Options(offline=True, external="none"))
    return {f.line: f.severity for f in res.findings if f.rule_id == "BE001" and f.file == name}


def test_placeholder_only_formatting_is_not_sql_injection(tmp_path):
    assert _be001_lines(tmp_path, "safe.py", SAFE) == {}


def test_formatting_values_identifiers_or_data_is_still_reported(tmp_path):
    expected = {i for i, line in enumerate(UNSAFE.splitlines(), 1) if line.endswith("# unsafe")}
    found = _be001_lines(tmp_path, "unsafe.py", UNSAFE)
    assert set(found) == expected
    request_line = max(expected)
    assert found[request_line] == "high"  # request data joined into the query
    assert all(found[line] == "medium" for line in expected - {request_line})


def test_bandit_checks_covered_by_builtin_rules_are_dropped(tmp_path):
    results = [{"test_id": t, "test_name": "x", "issue_text": "x", "issue_severity": "MEDIUM", "issue_confidence": "MEDIUM",
                "filename": "a.py", "line_number": 1, "code": "x"} for t in ("B608", "B307", "B602", "B324")]
    assert [f.rule_id for f in parse_bandit({"results": results}, tmp_path)] == ["bandit:B324"]
