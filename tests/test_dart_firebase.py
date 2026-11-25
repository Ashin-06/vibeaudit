"""Tests for Flutter/Dart checks (preview) and enhanced Firebase security rules."""
from __future__ import annotations

from pathlib import Path

from vibeaudit.scanner import Options, scan


def _scan(tmp_path: Path, files: dict[str, str]):
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return scan(str(tmp_path), Options(offline=True, external="none", min_severity="low", include_preview=True))


def test_flutter_dart_checks_and_stack(tmp_path: Path):
    res = _scan(tmp_path, {
        "pubspec.yaml": "name: myapp\ndependencies:\n  flutter:\n    sdk: flutter\n  firebase_core: ^3.0.0\n",
        "lib/api.dart": """import 'dart:io';
import 'package:http/http.dart' as http;

void badClient(HttpClient client, dynamic db, dynamic prefs, dynamic webview, String userId, String name) async {
  client.badCertificateCallback = (X509Certificate cert, String host, int port) => true;
  await db.rawQuery("SELECT * FROM users WHERE id = '$userId'");
  await prefs.setString('auth_token', 'secret');
  await webview.runJavaScript("setName('$name')");
  await http.post(Uri.parse('https://api.openai.com/v1/chat/completions'));
}
""",
        "lib/safe.dart": """import 'package:http/http.dart' as http;

void safeClient(dynamic db, dynamic prefs) async {
  // client.badCertificateCallback = (c, h, p) => true;
  await db.rawQuery('SELECT * FROM users WHERE id = ?', [1]);
  await prefs.setString('theme_mode', 'dark');
  await http.get(Uri.parse('https://example.com')).timeout(Duration(seconds: 5));
}
""",
    })
    assert "Flutter" in res.meta["stack"]
    assert "Dart" in res.meta["stack"]
    assert "Firebase" in res.meta["stack"]
    by_file = {(f.file, f.rule_id) for f in res.findings}
    for rule in ("BE013", "BE001", "FE004", "FE001", "FE002", "REL001"):
        assert ("lib/api.dart", rule) in by_file
    assert not any(f.file == "lib/safe.dart" for f in res.findings)
    assert all(f.preview for f in res.findings if f.file == "lib/api.dart")


def test_firebase_user_owned_rule_without_uid_check(tmp_path: Path):
    res = _scan(tmp_path, {
        "firestore.rules": """rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /users/{userId} {
      allow read, write: if request.auth != null;
    }
    match /profiles/{profileId} {
      allow read, write: if request.auth != null && request.auth.uid == profileId;
    }
  }
}
""",
    })
    auth007 = [f for f in res.findings if f.rule_id == "AUTH007"]
    assert len(auth007) == 1
    assert auth007[0].line == 5
