"""Infrastructure as code: Kubernetes manifests, Terraform (AWS, GCP, Azure) and CloudFormation (CFG012-CFG016, CFG020)."""
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
        else:
            _gcp_azure_terraform(sf, kind, off, line, body_off, body, add)


GCP_PUBLIC_IAM = re.compile(r'["\'](?:allUsers|allAuthenticatedUsers)["\']')
GCP_PORTS_LIST = re.compile(r"\bports\s*=\s*\[([^\]]{0,300})\]")
AZ_PUBLIC_SA = re.compile(r"\b(?:allow_blob_public_access|allow_nested_items_to_be_public)\s*=\s*true\b")
AZ_NO_HTTPS = re.compile(r"\b(?:enable_https_traffic_only|https_traffic_only_enabled)\s*=\s*false\b")
AZ_OPEN_SRC = re.compile(r'(?i)\bsource_address_prefix(?:es)?\s*=[^\n]{0,120}"(?:\*|Internet|Any|0\.0\.0\.0/0|::/0)"')
AZ_PORT_LIST = re.compile(r"\bdestination_port_ranges?\s*=\s*(\[[^\]]{0,300}\]|\"[^\n\"]{1,60}\")")


def _ports_hit(spec: str) -> Optional[str]:
    if '"*"' in spec or '"0-65535"' in spec:
        return "every port"
    hits = []
    for tok in re.findall(r'"(\d+(?:-\d+)?)"', spec):
        if "-" in tok:
            a, b = tok.split("-", 1)
            lo, hi = int(a), int(b)
            for p, name in ADMIN_PORTS.items():
                if lo <= p <= hi and f"{name} ({p})" not in hits:
                    hits.append(f"{name} ({p})")
        else:
            p = int(tok)
            if p in ADMIN_PORTS and f"{ADMIN_PORTS[p]} ({p})" not in hits:
                hits.append(f"{ADMIN_PORTS[p]} ({p})")
    return ", ".join(hits) if hits else None


def _gcp_open_firewall(body: str) -> Optional[str]:
    if re.search(r'(?i)\bdirection\s*=\s*"EGRESS"', body) or not OPEN_CIDR.search(body):
        return None
    allow_rx, pos = re.compile(r"(?m)^[ \t]*allow[ \t]*\{"), 0
    while True:
        m = allow_rx.search(body, pos)
        inner = _body(body, m.end()) if m else None
        if m is None or inner is None:
            return None
        pos = m.end() + len(inner) + 1
        if re.search(r'(?i)\bprotocol\s*=\s*"all"', inner):
            return "every port"
        pm = GCP_PORTS_LIST.search(inner)
        if pm:
            hit = _ports_hit(pm.group(1))
            if hit:
                return hit


def _az_open_rule(body: str) -> Optional[str]:
    if not re.search(r'(?i)\bdirection\s*=\s*"Inbound"', body):
        return None
    if not re.search(r'(?i)\baccess\s*=\s*"Allow"', body):
        return None
    if not AZ_OPEN_SRC.search(body):
        return None
    pm = AZ_PORT_LIST.search(body)
    return _ports_hit(pm.group(1)) if pm else None


def _gcp_azure_terraform(sf, kind: str, off: int, line: int, body_off: int, body: str, add: Add) -> None:
    if kind in ("google_storage_bucket_iam_member", "google_storage_bucket_iam_binding",
                "google_storage_bucket_iam_policy") and GCP_PUBLIC_IAM.search(body):
        add(sf, line, "CFG020", "GCS bucket IAM policy grants public access (`allUsers` / `allAuthenticatedUsers`).")
    elif kind == "google_compute_firewall":
        ports = _gcp_open_firewall(body)
        if ports:
            add(sf, line, "CFG020", f"GCP firewall rule opens {ports} to the internet (`0.0.0.0/0`).")
    elif kind == "google_sql_database_instance":
        if OPEN_CIDR.search(body):
            add(sf, line, "CFG020", "Cloud SQL authorized_networks allows connections from `0.0.0.0/0`.")
        if re.search(r"\brequire_ssl\s*=\s*false\b", body):
            add(sf, line, "CFG020", "Cloud SQL instance disables required SSL (`require_ssl = false`).")
    elif kind == "google_container_cluster" and re.search(r"\benable_legacy_abac\s*=\s*true\b", body):
        add(sf, line, "CFG020", "GKE cluster enables legacy ABAC (`enable_legacy_abac = true`).")
    elif kind == "azurerm_storage_account":
        if AZ_PUBLIC_SA.search(body):
            add(sf, line, "CFG020", "Azure Storage account allows public blob access.")
        if AZ_NO_HTTPS.search(body):
            add(sf, line, "CFG020", "Azure Storage account disables HTTPS-only traffic enforcement.")
    elif kind == "azurerm_storage_container" and re.search(r'(?i)\bcontainer_access_type\s*=\s*"(?:blob|container)"', body):
        add(sf, line, "CFG020", "Azure Storage container grants anonymous `blob` or `container` access.")
    elif kind == "azurerm_network_security_rule":
        ports = _az_open_rule(body)
        if ports:
            add(sf, line, "CFG020", f"Azure NSG rule opens inbound {ports} to the internet.")
    elif kind == "azurerm_network_security_group":
        rule_rx, pos = re.compile(r"(?m)^[ \t]*security_rule[ \t]*\{"), 0
        while True:
            m = rule_rx.search(body, pos)
            inner = _body(body, m.end()) if m else None
            if m is None or inner is None:
                break
            pos = m.end() + len(inner) + 1
            ports = _az_open_rule(inner)
            if ports:
                add(sf, sf.line_at(body_off + m.start()), "CFG020",
                    f"Azure NSG rule opens inbound {ports} to the internet.")
    elif kind in ("azurerm_mssql_firewall_rule", "azurerm_sql_firewall_rule") \
            and re.search(r'\bstart_ip_address\s*=\s*"0\.0\.0\.0"', body) \
            and re.search(r'\bend_ip_address\s*=\s*"255\.255\.255\.255"', body):
        add(sf, line, "CFG020", "Azure SQL firewall rule exposes the server to `0.0.0.0`-`255.255.255.255`.")


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
