"""Detection added from misses on the tune split of benchmark/advisories.json; each test failed before its fix."""
from vibeaudit.scanner import Options, scan


def write(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return root


def found(root, rule):
    res = scan(str(root), Options(offline=True, external="none", include_preview=True, min_severity="low"))
    return sorted((f.file, f.line) for f in res.findings if f.rule_id == rule)


def test_sympy_parsing_request_data_runs_code(tmp_path):
    # QWED (GHSA): parse_expr(request["expression"]) evaluates Python
    write(tmp_path, {"app.py": "from fastapi import FastAPI, Request\nfrom sympy.parsing.sympy_parser import parse_expr\n"
                               "app = FastAPI()\n\n@app.post('/solve')\nasync def solve(request: Request):\n"
                               "    body = await request.json()\n    return str(parse_expr(body['expression']))\n"})
    assert found(tmp_path, "BE003") == [("app.py", 8)]


def test_go_signing_key_as_a_byte_slice(tmp_path):
    # KubePi (GHSA): var JwtSigKey = []byte("signature_hmac_secret_shared_key")
    write(tmp_path, {"session.go": 'package session\n\nvar JwtSigKey = []byte("signature_hmac_secret_shared_key")\n'
                                   'var buf = []byte("not a key")\n'})
    assert found(tmp_path, "SEC004") == [("session.go", 3)]


def test_rails_whole_param_as_conditions(tmp_path):
    # curupira (GHSA): User.find_by(params[:user])
    write(tmp_path, {"app/controllers/passwords_controller.rb": "class PasswordsController < ApplicationController\n"
                     "  def create\n    @user = User.find_by(params[:user])\n    ok = User.find_by(email: params[:email])\n  end\nend\n"})
    assert found(tmp_path, "BE001") == [("app/controllers/passwords_controller.rb", 3)]


def test_php_url_fetches_through_symfony_and_guzzle(tmp_path):
    # bolt (GHSA): $this->filesystem->copy($request->get('url'), $tmp)
    write(tmp_path, {"src/Controller/UploadController.php": "<?php\nclass UploadController {\n"
                     "  public function upload(Request $request) {\n    $url = $request->get('url', '');\n"
                     "    $this->filesystem->copy($url, $tmpFile);\n    $this->client->request('GET', $url);\n"
                     "    $this->client->request('GET', 'https://api.example.com/x');\n  }\n}\n"})
    assert found(tmp_path, "BE005") == [("src/Controller/UploadController.php", 5),
                                         ("src/Controller/UploadController.php", 6)]
