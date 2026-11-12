"""CI, supply-chain and infrastructure-as-code rules added in 0.7.0 (CFG010-CFG016, DEP008)."""
from test_graduation_090 import GRADUATED
from vibeaudit.rules import RULES
from vibeaudit.scanner import Options, scan

NEW = ("CFG010", "CFG011", "CFG012", "CFG013", "CFG014", "CFG015", "CFG016", "DEP008")


def write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def found(root, *rules):
    res = scan(str(root), Options(offline=True, external="none", min_severity="low"))
    return sorted((f.file, f.line, f.rule_id) for f in res.findings if f.rule_id in (rules or NEW))


def test_new_rules_start_as_preview():
    # rules that later met the bar (STABILITY.md) left preview in 0.9.0; see test_graduation_090.py
    assert all(RULES[r].preview and RULES[r].preview_reason for r in NEW if r not in GRADUATED)


def test_unpinned_third_party_actions_and_write_all_tokens(tmp_path):
    write(tmp_path, ".github/workflows/ci.yml",
          "on: push\npermissions: write-all\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
          "      - uses: actions/checkout@v5\n"                                              # 7: first party
          "      - uses: pnpm/action-setup@v4\n"                                             # 8
          "      - uses: tj-actions/changed-files@0123456789abcdef0123456789abcdef01234567\n"  # 9: pinned
          "      - uses: ./.github/actions/local\n"                                          # 10: local
          "      - uses: 'docker://alpine:3.20'\n"
          "  r:\n    uses: org/shared/.github/workflows/release.yml@main\n"                   # 13
          "    permissions:\n      contents: write\n")
    write(tmp_path, "action.yml", "runs:\n  using: composite\n  steps:\n    - uses: some/tool@v1\n")
    assert found(tmp_path, "CFG010", "CFG011") == [
        (".github/workflows/ci.yml", 2, "CFG011"), (".github/workflows/ci.yml", 8, "CFG010"),
        (".github/workflows/ci.yml", 13, "CFG010"), ("action.yml", 4, "CFG010")]


def test_extra_package_index(tmp_path):
    write(tmp_path, "requirements.txt", "--index-url https://pypi.org/simple\n--extra-index-url https://pkgs.corp/simple\nflask==3.0\n")
    write(tmp_path, "pip.conf", "[global]\nextra-index-url = https://pkgs.corp/simple\n")
    write(tmp_path, "requirements-dev.txt", "# --extra-index-url is not used here\npytest\n")
    assert found(tmp_path, "DEP008") == [("pip.conf", 2, "DEP008"), ("requirements.txt", 2, "DEP008")]


def test_kubernetes_privileged_host_access_and_limits(tmp_path):
    write(tmp_path, "k8s/app.yaml",
          "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      hostNetwork: true\n"   # 6
          "      containers:\n        - name: app\n          securityContext:\n            privileged: true\n"  # 7, 10
          "      volumes:\n        - name: d\n          hostPath:\n            path: /var/run\n"               # 13
          "---\napiVersion: v1\nkind: Service\nspec:\n  ports: []\n"
          "---\napiVersion: batch/v1\nkind: Job\nspec:\n  template:\n    spec:\n      containers:\n"          # 26
          "        - name: j\n          resources:\n            limits:\n              memory: 64Mi\n"
          "          # privileged: true\n")
    write(tmp_path, "chart/templates/deploy.yaml", "kind: Deployment\nspec:\n  containers:\n"
          "    - name: x\n      resources: {{- toYaml .Values.resources | nindent 8 }}\n")
    write(tmp_path, "config.yaml", "privileged: true\ncontainers: []\n")  # not a Kubernetes workload
    assert found(tmp_path) == [("k8s/app.yaml", 6, "CFG012"), ("k8s/app.yaml", 7, "CFG013"),
                               ("k8s/app.yaml", 10, "CFG012"), ("k8s/app.yaml", 13, "CFG012")]


def test_terraform_public_buckets_open_ports_and_encryption(tmp_path):
    write(tmp_path, "infra/main.tf", """resource "aws_s3_bucket_acl" "site" {
  acl = "public-read"
}
resource "aws_s3_bucket_public_access_block" "logs" {
  block_public_acls = false
}
resource "aws_security_group" "web" {
  ingress {
    from_port   = 443
    to_port     = 443
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 5432
    to_port     = 5432
    cidr_blocks = ["10.0.0.0/16"]
  }
}
resource "aws_security_group_rule" "all" {
  type        = "ingress"
  protocol    = "-1"
  from_port   = 0
  to_port     = 0
  cidr_blocks = ["0.0.0.0/0"]
}
resource "aws_db_instance" "main" {
  engine = "postgres"  # storage_encrypted = true is a comment here
}
resource "aws_db_instance" "safe" {
  storage_encrypted = true
}
resource "aws_ebs_volume" "data" {
  size = 10
}
""")
    assert found(tmp_path) == [("infra/main.tf", 1, "CFG014"), ("infra/main.tf", 4, "CFG014"),
                               ("infra/main.tf", 13, "CFG015"), ("infra/main.tf", 24, "CFG015"),
                               ("infra/main.tf", 31, "CFG016"), ("infra/main.tf", 37, "CFG016")]


def test_cloudformation(tmp_path):
    write(tmp_path, "template.yaml", """AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: PublicRead
  Sg:
    Type: AWS::EC2::SecurityGroup
    Properties:
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 3389
          ToPort: 3389
          CidrIp: 0.0.0.0/0
  Db:
    Type: AWS::RDS::DBInstance
    Properties:
      StorageEncrypted: false
""")
    assert found(tmp_path) == [("template.yaml", 6, "CFG014"), ("template.yaml", 14, "CFG015"), ("template.yaml", 18, "CFG016")]


def test_iac_parsing_survives_hostile_files(tmp_path):
    import time

    write(tmp_path, "a.tf", 'resource "aws_security_group" "x" {\n' + "ingress {\n" * 5000 + '"' * 3000)
    write(tmp_path, "b.yaml", "kind: Pod\n" + "privileged: true\n" * 2 + "---\n" * 20000)
    start = time.time()
    found(tmp_path)
    assert time.time() - start < 15


def test_nested_terraform_blocks_are_read_once(tmp_path):
    import time

    write(tmp_path, "a.tf", 'resource "a" "b" {\n' * 3000 + "}\n" * 3000)
    write(tmp_path, "b.tf", 'resource "aws_security_group" "x" {\n' + "ingress {\n" * 3000 + "}\n" * 3001)
    start = time.time()
    found(tmp_path)
    assert time.time() - start < 3


def test_unclosed_terraform_blocks_do_not_rescan_the_file(tmp_path):
    import time

    write(tmp_path, "c.tf", 'resource "a" "b" {\n' * 3000)
    start = time.time()
    found(tmp_path)
    assert time.time() - start < 3


def test_encryption_inherited_or_always_on_is_not_reported(tmp_path):
    write(tmp_path, "db.tf", 'resource "aws_rds_cluster" "s" {\n  engine_mode = "serverless"\n}\n'
          'resource "aws_db_instance" "replica" {\n  replicate_source_db = aws_db_instance.main.id\n}\n')
    assert found(tmp_path, "CFG016") == []
