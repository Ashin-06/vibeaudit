"""npm scope confusion (Phase 1 "registry confusion", npm half): a scoped package that is not on npm and has no
registry in .npmrc is DEP001; a scope mapped to a private registry is not looked up on npm."""
from vibeaudit import deps
from vibeaudit.scanner import Options, scan


def dep_rules(root):
    return sorted(f.rule_id for f in scan(str(root), Options(offline=False, external="none")).findings if f.rule_id.startswith("DEP00"))


def test_unregistered_private_scope_is_reported_and_a_mapped_scope_is_not(tmp_path, monkeypatch):
    looked_up = []

    def registry(d):
        looked_up.append(d.name)
        return ("missing", None, "")
    monkeypatch.setattr(deps, "registry_info", registry)
    monkeypatch.setattr(deps, "osv_lookup", lambda ds: {})
    (tmp_path / "package.json").write_text('{"dependencies": {"@acme-internal-zz9/ui-kit": "1.0.0"}}')
    (tmp_path / "package-lock.json").write_text('{"lockfileVersion": 3, "packages": {}}')
    assert "DEP001" in dep_rules(tmp_path)
    (tmp_path / ".npmrc").write_text("@acme-internal-zz9:registry=https://npm.internal.example.com/\n")
    looked_up.clear()
    assert "DEP001" not in dep_rules(tmp_path) and "@acme-internal-zz9/ui-kit" not in looked_up
