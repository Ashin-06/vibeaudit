"""Infrastructure as code: Kubernetes manifests, Terraform and CloudFormation (CFG012-CFG016)."""
from __future__ import annotations

import re
from typing import Callable, Iterator, Optional, Tuple

from .guard import GUARD, finditer

Add = Callable[..., None]  # ProjectScanner.add(sf, line, rule, message, severity="")

K8S_KIND = re.compile(
    r"(?m)^kind:[ \t]*['\"]?(Pod|Deployment|StatefulSet|DaemonSet|Job|CronJob|ReplicaSet|ReplicationController)\b")
ADMIN_PORTS = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL", 1433: "SQL Server", 1521: "Oracle",
               27017: "MongoDB", 6379: "Redis", 9200: "Elasticsearch", 5984: "CouchDB"}
OPEN_CIDR = re.compile(r"['\"]?(?:0\.0\.0\.0/0|::/0)['\"]?")


def scan(sf, add: Add) -> None:
    text = sf.text or ""
    if sf.rel.endswith(".tf"):
        terraform(sf, _blank(text, r"#[^\n]*|//[^\n]*|/\*[\s\S]*?\*/"), add)
    elif sf.kind in ("yaml", "json"):
        clean = _blank(text, r"(?m)^[ \t]*#[^\n]*") if sf.kind == "yaml" else text
        if "AWSTemplateFormatVersion" in text or re.search(r"\bAWS::(?:S3|EC2|RDS)::", text):
            cloudformation(sf, clean, add)
        elif K8S_KIND.search(clean):
            kubernetes(sf, clean, add)


def _blank(text: str, pattern: str) -> str:
    """Comments replaced by spaces, so offsets and line numbers stay the same."""
    return re.sub(pattern, lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)


# ----------------------------------------------------------------- kubernetes
def kubernetes(sf, text: str, add: Add) -> None:
    starts = [0] + [m.end() for m in re.finditer(r"(?m)^---[^\n]*$", text)]
    for i, start in enumerate(starts):
        end = starts[i + 1] if i + 1 < len(starts) else len(text)
        doc = text[start:end]
        if not K8S_KIND.search(doc):
            continue
        for m in finditer(r"\bprivileged:[ \t]*['\"]?true\b|\bhostPath:|\bhost(?:Network|PID|IPC):[ \t]*['\"]?true\b", doc):
            what = m.group(0).split(":")[0]
            add(sf, sf.line_at(start + m.start()), "CFG012",
                "The container runs privileged." if what == "privileged" else f"The pod uses `{what}` from the node.")
        containers = re.search(r"(?m)^[ \t]*containers:", doc)
        # Helm charts usually template the block: `resources: {{- toYaml .Values.resources | nindent 12 }}`
        if containers and not re.search(r"\blimits:|\bresources:[ \t]*\{\{", doc):
            add(sf, sf.line_at(start + containers.start()), "CFG013", "No container in this workload sets resource limits.")


# ------------------------------------------------------------------ terraform
def _blocks(text: str, head: str) -> Iterator[Tuple[str, int, int, str]]:
    """(first label, offset of the block, offset of its body, body) for every `head "LABEL" ... {` block."""
    rx, pos = re.compile(r'(?m)^[ \t]*%s[ \t]+"([\w.-]+)"[^{\n]*\{' % head), 0
    while True:  # each block read once and skipped: nested heads cannot make this quadratic
        m = rx.search(text, pos)
        if m is None:
            return
        GUARD.tick()
        body = _body(text, m.end())
        if body is None:
            return  # unbalanced braces to the end of the file: a malformed file, stop rather than rescan
        pos = m.end() + len(body) + 1
        yield m.group(1), m.start(), m.end(), body


def _body(text: str, i: int) -> Optional[str]:
    depth, j, in_str = 1, i, False
    while j < len(text):
        c = text[j]
        if in_str:
            if c == "\\":
                j += 1
            elif c == '"':
                in_str = False
        elif c == '"':
            in_str = True
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[i:j]
        j += 1
        if j % 4096 == 0:
            GUARD.tick()
    return None


def _int(body: str, key: str) -> Optional[int]:
    m = re.search(r"\b%s['\"]?\s*=\s*['\"]?(-?\d+)" % key, body)
    return int(m.group(1)) if m else None


def _open_admin_port(body: str, from_key: str, to_key: str, proto_key: str) -> Optional[str]:
    if not OPEN_CIDR.search(body):
        return None
    if re.search(r"\b%s['\"]?\s*=\s*['\"]?(?:-1|all)\b" % proto_key, body):
        return "every port"
    low, high = _int(body, from_key), _int(body, to_key)
    if low is None:
        return None
    high = low if high is None else high
    if low <= 0 and high >= 65535 or low == -1:
        return "every port"
    hits = [f"{name} ({port})" for port, name in ADMIN_PORTS.items() if low <= port <= high]
    return ", ".join(hits) if hits else None


def terraform(sf, text: str, add: Add) -> None:
    for kind, off, body_off, body in _blocks(text, "resource"):
        line = sf.line_at(off)
        if kind in ("aws_s3_bucket", "aws_s3_bucket_acl") and re.search(r'\bacl\s*=\s*"public-read(?:-write)?"', body):
            add(sf, line, "CFG014", "The bucket ACL is public-read.")
        elif kind == "aws_s3_bucket_public_access_block" and re.search(
                r"\b(?:block_public_acls|block_public_policy|ignore_public_acls|restrict_public_buckets)\s*=\s*false\b", body):
            add(sf, line, "CFG014", "The bucket's public access block is switched off.")
        elif kind == "aws_security_group":
            ingress, pos = re.compile(r"(?m)^[ \t]*ingress[ \t]*\{"), 0
            while True:  # top-level ingress blocks only, each read once: nested braces cannot make it quadratic
                m = ingress.search(body, pos)
                inner = _body(body, m.end()) if m else None
                if m is None or inner is None:
                    break
                pos = m.end() + len(inner) + 1
                ports = _open_admin_port(inner, "from_port", "to_port", "protocol")
                if ports:
                    add(sf, sf.line_at(body_off + m.start()), "CFG015", f"Ingress from anywhere on {ports}.")
        elif kind == "aws_security_group_rule" and re.search(r'\btype\s*=\s*"ingress"', body):
            ports = _open_admin_port(body, "from_port", "to_port", "protocol")
            if ports:
                add(sf, line, "CFG015", f"Ingress from anywhere on {ports}.")
        elif kind == "aws_vpc_security_group_ingress_rule":
            ports = _open_admin_port(body, "from_port", "to_port", "ip_protocol")
            if ports:
                add(sf, line, "CFG015", f"Ingress from anywhere on {ports}.")
        elif kind in ("aws_db_instance", "aws_rds_cluster") and not re.search(r"\bstorage_encrypted\s*=\s*true\b", body) \
                and not re.search(r"\b(?:replicate_source_db|snapshot_identifier)\s*=|\bengine_mode\s*=\s*\"serverless\"", body):
            # a read replica or restored snapshot inherits its source's setting; Aurora Serverless v1 is always encrypted
            add(sf, line, "CFG016", f"`{kind}` does not set storage_encrypted = true (the default is unencrypted).")
        elif kind == "aws_ebs_volume" and not re.search(r"\bencrypted\s*=\s*true\b", body) and "snapshot_id" not in body:
            add(sf, line, "CFG016", "The EBS volume does not set encrypted = true.")
        elif re.search(r"\bencrypted\s*=\s*false\b", body):
            add(sf, line, "CFG016", "Encryption at rest is switched off.")


# ------------------------------------------------------------- cloudformation
def cloudformation(sf, text: str, add: Add) -> None:
    for m in finditer(r"['\"]?AccessControl['\"]?\s*:\s*['\"]?Public(?:Read|ReadWrite)\b", text):
        add(sf, sf.line_at(m.start()), "CFG014", "The bucket ACL is public.")
    for m in finditer(r"['\"]?(?:BlockPublicAcls|BlockPublicPolicy|IgnorePublicAcls|RestrictPublicBuckets)['\"]?\s*:\s*['\"]?false\b", text):
        add(sf, sf.line_at(m.start()), "CFG014", "The bucket's public access block is switched off.")
        break
    for m in finditer(r"['\"]?CidrIpv?6?['\"]?\s*:\s*['\"]?(?:0\.0\.0\.0/0|::/0)", text):
        # the ports are keys of the same rule: look in the few lines around it
        line = sf.line_at(m.start())
        window = "\n".join(sf.lines[max(0, line - 6):line + 5]).replace(":", " =")
        ports = _open_admin_port(window, "FromPort", "ToPort", "IpProtocol")
        if ports:
            add(sf, line, "CFG015", f"Ingress from anywhere on {ports}.")
    for m in finditer(r"['\"]?(?:StorageEncrypted|Encrypted)['\"]?\s*:\s*['\"]?false\b", text):
        add(sf, sf.line_at(m.start()), "CFG016", "Encryption at rest is switched off.")
