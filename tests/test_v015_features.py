"""Tests for v0.15.0 features: Swift/Vapor, Elixir/Phoenix, XXE (BE021), GCP/Azure Terraform (CFG020),
and deterministic BE013/BE011 codemods in vibeaudit fix.
"""
from pathlib import Path

from test_lang_precision_fixes import _scan

from vibeaudit.fix import plan_findings


def _rules(res):
    return {f.rule_id for f in res.findings}


# ----------------------------------------------------------------- Swift / iOS / Vapor
def test_swift_vapor_routes_and_security_findings(tmp_path: Path):
    res = _scan(tmp_path, {
        "Package.swift": (
            "// swift-tools-version:5.9\nimport PackageDescription\n"
            'let package = Package(name: "Srv", dependencies: [.package(url: "https://github.com/vapor/vapor.git", from: "4.0.0")])\n'
        ),
        "Sources/App/routes.swift": (
            "import Vapor\n"
            "import Foundation\n"
            "func routes(_ app: Application) throws {\n"
            '    let protected = app.grouped(AuthMiddleware())\n'
            '    protected.post("items") { req async throws -> HTTPStatus in\n'
            "        return .created\n"
            "    }\n"
            '    app.delete("orders", ":id") { req async throws -> HTTPStatus in\n'
            '        let id = req.parameters.get("id") ?? ""\n'
            '        _ = try await db.raw("DELETE FROM orders WHERE id = \\(id)")\n'
            "        return .ok\n"
            "    }\n"
            "    let p = Process()\n"
            '    p.arguments = ["-c", "echo \\(cmd)"]\n'
            '    _ = URLCredential(trust: challenge.protectionSpace.serverTrust!)\n'
            '    UserDefaults.standard.set(token, forKey: "auth_token")\n'
            '    let _ = "https://api.openai.com/v1/chat/completions"\n'  # Vapor server: no FE002
            "}\n"
        ),
        "ios/Info.plist": "<dict><key>NSAllowsArbitraryLoads</key><true/></dict>\n",
    })
    assert res.meta.get("internal_errors", []) == []
    assert "Swift" in res.meta["stack"] and "Vapor" in res.meta["stack"]
    rules = _rules(res)
    assert {"AUTH001", "BE001", "BE002", "BE013", "FE005"} <= rules
    assert "FE002" not in rules
    route_by_path = {r.path: r for r in res.routes}
    assert route_by_path["/items"].has_auth is True
    assert route_by_path["/orders/:id"].has_auth is False
    plist_be013 = [f for f in res.findings if f.file == "ios/Info.plist" and f.rule_id == "BE013"]
    assert len(plist_be013) == 1


def test_swift_ios_client_llm_flagged_without_vapor(tmp_path: Path):
    res = _scan(tmp_path, {
        "App/AIClient.swift": 'let endpoint = "https://api.openai.com/v1/chat/completions"\n',
    })
    assert "FE002" in _rules(res)


# ----------------------------------------------------------------- Elixir / Phoenix
def test_elixir_phoenix_routes_and_security_findings(tmp_path: Path):
    res = _scan(tmp_path, {
        "mix.exs": 'defmodule MyApp.MixProject do\n  def deps, do: [{:phoenix, "~> 1.7"}]\nend\n',
        "lib/my_app_web/router.ex": (
            "defmodule MyAppWeb.Router do\n"
            "  use MyAppWeb, :router\n"
            '  scope "/api", MyAppWeb do\n'
            '    delete "/records/:id", RecordController, :delete\n'
            "  end\n"
            '  scope "/secure", MyAppWeb do\n'
            "    pipe_through [:api, :require_authenticated_user]\n"
            '    delete "/account", AccountController, :delete\n'
            "  end\n"
            "end\n"
        ),
        "lib/my_app/work.ex": (
            "defmodule MyApp.Work do\n"
            '  def bad_sql(id), do: Ecto.Adapters.SQL.query!(Repo, "SELECT * FROM u WHERE id = #{id}", [])\n'
            '  def bad_cmd(arg), do: System.cmd("sh", ["-c", "ls #{arg}"])\n'
            "  def bad_deser(bin), do: :erlang.binary_to_term(bin)\n"
            "  def safe_deser(bin), do: :erlang.binary_to_term(bin, [:safe])\n"
            "  def bad_html(h), do: Phoenix.HTML.raw(h)\n"
            "  def bad_tls(u), do: Mint.HTTP.connect(:https, u, 443, transport_opts: [verify: :verify_none])\n"
            "end\n"
        ),
    })
    assert res.meta.get("internal_errors", []) == []
    assert "Elixir" in res.meta["stack"] and "Phoenix" in res.meta["stack"]
    rules = _rules(res)
    assert {"AUTH001", "BE001", "BE002", "BE004", "FE001", "BE013"} <= rules
    be004 = [f for f in res.findings if f.rule_id == "BE004"]
    assert len(be004) == 1  # safe_deser with [:safe] must not trigger
    route_by_path = {r.path: r for r in res.routes}
    assert route_by_path["/api/records/:id"].has_auth is False
    assert route_by_path["/secure/account"].has_auth is True
    assert "require_authenticated_user" in (route_by_path["/secure/account"].to_dict()["auth_evidence"] or "")


# ----------------------------------------------------------------- XXE (BE021)
def test_xxe_be021_across_languages_and_safe_counterparts(tmp_path: Path):
    res = _scan(tmp_path, {
        "vuln.py": "from lxml import etree\np = etree.XMLParser(resolve_entities=True)\n",
        "safe.py": "from lxml import etree\np = etree.XMLParser(resolve_entities=False)\n",
        "Vuln.java": "import javax.xml.parsers.DocumentBuilderFactory;\nclass V { void f() { var dbf = DocumentBuilderFactory.newInstance(); } }\n",
        "Safe.java": (
            "import javax.xml.parsers.DocumentBuilderFactory;\n"
            'class S { void f() throws Exception { var dbf = DocumentBuilderFactory.newInstance(); dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true); } }\n'
        ),
        "Vuln.kt": "import javax.xml.parsers.SAXParserFactory\nfun f() { val s = SAXParserFactory.newInstance() }\n",
        "Vuln.cs": "using System.Xml;\nclass C { void F() { var s = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse }; } }\n",
        "Safe.cs": "using System.Xml;\nclass S { void F() { var s = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null }; } }\n",
        "vuln.php": "<?php\n$doc = DOMDocument::loadXML($xml, LIBXML_NOENT);\nlibxml_disable_entity_loader(false);\n",
        "vuln.js": 'const libxmljs = require("libxmljs");\nlibxmljs.parseXml(body, { noent: true });\n',
        "safe.js": 'const libxmljs = require("libxmljs");\nlibxmljs.parseXml(body, { noent: false });\n',
    })
    xxe_files = {f.file for f in res.findings if f.rule_id == "BE021"}
    assert xxe_files == {"vuln.py", "Vuln.java", "Vuln.kt", "Vuln.cs", "vuln.php", "vuln.js"}


# ----------------------------------------------------------------- Multi-cloud Terraform (CFG020)
def test_multicloud_gcp_and_azure_terraform_cfg020(tmp_path: Path):
    res = _scan(tmp_path, {
        "gcp.tf": (
            'resource "google_storage_bucket_iam_member" "pub" {\n'
            '  bucket = "b"\n  role = "roles/storage.objectViewer"\n  member = "allUsers"\n'
            "}\n"
            'resource "google_compute_firewall" "ssh" {\n'
            '  name = "allow-ssh"\n  source_ranges = ["0.0.0.0/0"]\n'
            '  allow {\n    protocol = "tcp"\n    ports = ["22"]\n  }\n'
            "}\n"
            'resource "google_sql_database_instance" "db" {\n'
            "  settings {\n    ip_configuration {\n      require_ssl = false\n"
            '      authorized_networks { value = "0.0.0.0/0" }\n'
            "    }\n  }\n}\n"
            'resource "google_container_cluster" "gke" {\n  enable_legacy_abac = true\n}\n'
        ),
        "azure.tf": (
            'resource "azurerm_storage_account" "sa" {\n'
            "  allow_blob_public_access = true\n  enable_https_traffic_only = false\n"
            "}\n"
            'resource "azurerm_storage_container" "cnt" {\n  container_access_type = "blob"\n}\n'
            'resource "azurerm_network_security_rule" "rdp" {\n'
            '  direction = "Inbound"\n  access = "Allow"\n'
            '  source_address_prefix = "*"\n  destination_port_range = "3389"\n'
            "}\n"
            'resource "azurerm_mssql_firewall_rule" "fw" {\n'
            '  start_ip_address = "0.0.0.0"\n  end_ip_address = "255.255.255.255"\n'
            "}\n"
        ),
        "safe.tf": (
            'resource "google_compute_firewall" "web" {\n'
            '  source_ranges = ["0.0.0.0/0"]\n  allow {\n    protocol = "tcp"\n    ports = ["443"]\n  }\n'
            "}\n"
            'resource "azurerm_storage_account" "priv" {\n'
            "  allow_blob_public_access = false\n  enable_https_traffic_only = true\n"
            "}\n"
        ),
    })
    cfg20 = [f for f in res.findings if f.rule_id == "CFG020"]
    assert len([f for f in cfg20 if f.file == "gcp.tf"]) == 5
    assert len([f for f in cfg20 if f.file == "azure.tf"]) == 5
    assert all(f.file != "safe.tf" for f in cfg20)


# ----------------------------------------------------------------- Fix codemods (BE013 & BE011)
def test_fix_codemods_be013_and_be011_roundtrip_and_idempotent(tmp_path: Path):
    files = {
        "client.py": 'import requests\ndef fetch(url):\n    return requests.get(url, verify=False, timeout=10)\n',
        "client.js": 'const https = require("https");\nconst agent = new https.Agent({ rejectUnauthorized: false });\n',
        "flask_app.py": 'from flask import Flask\napp = Flask(__name__)\napp.run(debug=True)\n',
        "settings.py": "DEBUG = True\n",
    }
    res = _scan(tmp_path, files)
    target_findings = [f for f in res.findings if f.rule_id in ("BE013", "BE011")]
    assert len(target_findings) == 4
    plan = plan_findings(tmp_path, target_findings)
    assert len(plan.fixed) == 4 and not plan.skipped
    written = set(plan.apply())
    assert written == set(files)
    assert "verify=True" in (tmp_path / "client.py").read_text(encoding="utf-8")
    assert "rejectUnauthorized: true" in (tmp_path / "client.js").read_text(encoding="utf-8")
    assert "debug=False" in (tmp_path / "flask_app.py").read_text(encoding="utf-8")
    settings_txt = (tmp_path / "settings.py").read_text(encoding="utf-8")
    assert "import os" in settings_txt and 'os.environ.get("DEBUG"' in settings_txt

    res2 = _scan(tmp_path, {k: (tmp_path / k).read_text(encoding="utf-8") for k in files})
    assert [f for f in res2.findings if f.rule_id in ("BE013", "BE011")] == []
