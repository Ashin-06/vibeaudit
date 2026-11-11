"""False positives found when the corpus grew to 53 repositories (0.7.3); each test failed before its fix.
All of them were seen on the tuned split (alerta, dvga, nodegoat, wsgidav, flexible-graphrag, express)."""
from vibeaudit.scanner import Options, scan


def write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def found(root, *rules):
    res = scan(str(root), Options(offline=True, external="none", min_severity="low"))
    assert res.meta.get("internal_errors", []) == []
    return sorted((f.file, f.line, f.rule_id) for f in res.findings if f.rule_id in rules)


def test_permission_decorator_is_authentication_and_replaces_a_webhook_signature(tmp_path):
    # alerta: @permission('write:alerts') on every route, @permission('write:webhooks') on webhooks
    write(tmp_path, "views.py", "from auth import permission\n"
          "@api.route('/alert/<alert_id>', methods=['DELETE'])\n@permission('write:alerts')\ndef delete_alert(alert_id):\n"
          "    db.alerts.delete(alert_id)\n    return ''\n\n"
          "@api.route('/webhooks/grafana', methods=['POST'])\n@permission('write:webhooks')\ndef grafana():\n"
          "    db.alerts.insert(request.json)\n    return ''\n\n"
          "@api.route('/webhooks/open', methods=['POST'])\ndef open_hook():\n    db.alerts.insert(request.json)\n    return ''\n\n"
          "@api.route('/note/<note_id>', methods=['DELETE'])\ndef delete_note(note_id):\n    db.notes.delete(note_id)\n    return ''\n")
    assert found(tmp_path, "AUTH001", "AUTH004") == [("views.py", 15, "AUTH004"), ("views.py", 20, "AUTH001")]


def test_unminified_vendored_libraries_are_not_application_code(tmp_path):
    # dvga static/jquery/jquery.js and static/bootstrap/css/bootstrap.css
    lib = "function f(el, value) {\n  try { el.innerHTML = value; } catch (e) {}\n}\n" * 400
    write(tmp_path, "static/jquery/jquery.js", lib)
    write(tmp_path, "static/js/app.js", lib)
    write(tmp_path, "static/bootstrap/css/bootstrap.css", ".custom-range:focus {\n  outline: none;\n}\n" * 400)
    assert {f for f, _l, _r in found(tmp_path, "FE001", "QA003", "UI016")} == {"static/js/app.js"}


def test_helper_scripts_seed_files_and_fixed_table_loops(tmp_path):
    # flexible-graphrag scripts/, nodegoat artifacts/db-reset.js, alerta destroy()
    write(tmp_path, "scripts/get_token.py", "import os\nSECRET = os.environ.get('CLIENT_SECRET', 'local-dev-default')\n"
          "token = fetch(SECRET)\nprint('access_token :', token.get('access_token'))\n")
    write(tmp_path, "artifacts/db-reset.js", "const USERS = [{ userName: 'admin', password: 'Adm1n_Xy9!q' }];\n")
    write(tmp_path, "db.py", "def destroy(cursor):\n    for table in ['alerts', 'users']:\n"
          "        cursor.execute('DROP TABLE IF EXISTS %s' % table)\n"
          "def find(cursor, table):\n    cursor.execute('SELECT * FROM %s' % table)\n")
    assert found(tmp_path, "SEC004", "SEC010", "SEC011", "BE001") == [("db.py", 5, "BE001")]


def test_signed_webhook_may_be_csrf_exempt_and_libraries_ship_no_lockfile(tmp_path):
    # djangoproject.com receive_webhook, express package.json, wsgidav docs/source/requirements.txt
    write(tmp_path, "views.py", "@csrf_exempt\ndef receive_webhook(request):\n"
          "    event = stripe.Webhook.construct_event(request.body, request.headers['stripe-signature'], SECRET)\n"
          "    return handle(event)\n\n@csrf_exempt\ndef update_profile(request):\n    return save(request.POST)\n")
    write(tmp_path, "package.json", '{"name": "mylib", "main": "index.js", "files": ["lib/"], "dependencies": {"debug": "^4.0.0"}}')
    write(tmp_path, "docs/source/requirements.txt", "sphinx~=7.0\nfuro~=2024.1\n")
    write(tmp_path, "app/package.json", '{"name": "app", "private": true, "dependencies": {"debug": "^4.0.0"}}')
    assert found(tmp_path, "AUTH009", "DEP005") == [("app/package.json", 1, "DEP005"), ("views.py", 6, "AUTH009")]
