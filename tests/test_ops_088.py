"""Data and operations rules added in 0.8.8 (DATA014-DATA016, CFG018)."""
import time

from vibeaudit.rules import RULES
from vibeaudit.scanner import Options, scan

NEW = ("DATA014", "DATA015", "DATA016", "CFG018")


def write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def found(root, *rules):
    res = scan(str(root), Options(offline=True, external="none", min_severity="low"))
    assert res.meta.get("internal_errors", []) == []
    return sorted((f.file, f.line, f.rule_id) for f in res.findings if f.rule_id in (rules or NEW))


def test_new_rules_start_as_preview():
    assert all(RULES[r].preview and RULES[r].preview_reason for r in NEW)


def test_personal_data_in_vector_metadata(tmp_path):
    write(tmp_path, "index.py",
          "from pinecone import Pinecone\nindex = Pinecone().Index('docs')\n\n"
          "def save(user, vec):\n    index.upsert(vectors=[{'id': user.id, 'values': vec,\n"
          "        'metadata': {'email': user.email, 'plan': user.plan}}])\n"     # 6
          "    index.upsert(vectors=[{'id': user.id, 'values': vec, 'metadata': {'user_id': user.id}}])\n")
    write(tmp_path, "requirements.txt", "pinecone\n")
    assert found(tmp_path, "DATA014") == [("index.py", 6, "DATA014")]


def test_cache_stampede(tmp_path):
    write(tmp_path, "stats.py",
          "import redis\nr = redis.Redis()\n\ndef stats(db):\n    cached = r.get('stats')\n"     # 5
          "    if cached is None:\n        cached = db.execute('select count(*) from orders').fetchone()[0]\n"
          "        r.set('stats', cached, ex=60)\n    return cached\n")
    write(tmp_path, "locked.py",
          "import redis\nr = redis.Redis()\n\ndef stats(db):\n    cached = r.get('stats')\n"
          "    if cached is None:\n        with r.lock('stats-lock', timeout=10):\n"
          "            cached = db.execute('select count(*) from orders').fetchone()[0]\n"
          "            r.set('stats', cached, ex=60)\n    return cached\n")
    write(tmp_path, "requirements.txt", "redis\n")
    assert found(tmp_path, "DATA015") == [("stats.py", 5, "DATA015")]


def test_jobs_that_are_not_safe_to_retry(tmp_path):
    write(tmp_path, "tasks.py",
          "import stripe\nfrom celery import shared_task\n\n@shared_task\ndef charge(order_id, amount):\n"   # 5
          "    stripe.PaymentIntent.create(amount=amount, currency='usd')\n\n"
          "@shared_task\ndef charge_safe(order_id, amount):\n"
          "    stripe.PaymentIntent.create(amount=amount, currency='usd', idempotency_key=f'order-{order_id}')\n")
    write(tmp_path, "worker.ts",
          "import { Worker } from 'bullmq';\nnew Worker('mail', async (job) => {\n"      # 2
          "  await mailer.sendMail({ to: job.data.to, subject: 'Hi' });\n});\n"
          "new Worker('mail2', async (job) => {\n  if (await sent.exists(job.id)) return;\n  await mailer.sendMail({ to: job.data.to });\n});\n")
    write(tmp_path, "requirements.txt", "stripe\ncelery\n")
    write(tmp_path, "package.json", '{"dependencies": {"bullmq": "5.0.0"}}')
    assert found(tmp_path, "DATA016") == [("tasks.py", 5, "DATA016"), ("worker.ts", 2, "DATA016")]


def test_pull_request_target_with_head_checkout(tmp_path):
    write(tmp_path, ".github/workflows/preview.yml",
          "on:\n  pull_request_target:\n    types: [opened]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
          "      - uses: actions/checkout@0ad4b8fadaa221de15dcec353f45205ec38ea70b\n        with:\n"
          "          ref: ${{ github.event.pull_request.head.sha }}\n"     # 10
          "      - run: npm ci && npm run build\n        env:\n          TOKEN: ${{ secrets.DEPLOY_TOKEN }}\n")
    write(tmp_path, ".github/workflows/label.yml",
          "on:\n  pull_request_target:\njobs:\n  label:\n    runs-on: ubuntu-latest\n    steps:\n"
          "      - run: echo label\n        env:\n          TOKEN: ${{ secrets.DEPLOY_TOKEN }}\n")
    assert found(tmp_path, "CFG018") == [(".github/workflows/preview.yml", 10, "CFG018")]


def test_ops_checks_are_linear_on_hostile_input(tmp_path):
    write(tmp_path, "a.py", "import pinecone\n" + "metadata = {" * 20000 + "\n" + "x = cache.get(k)\n" * 20000)
    write(tmp_path, "b.ts", "new Worker('q', async () => {\n" * 3000 + "cron.schedule('* * * * *', () => {" * 3000)
    start = time.time()
    found(tmp_path)
    assert time.time() - start < 60


def test_match_close_fast_path_equals_the_scan():
    import random
    from vibeaudit import lexer

    def slow(s, i):
        depth = 0
        for j in range(i, len(s)):
            if s[j] in "([{":
                depth += 1
            elif s[j] in ")]}":
                depth -= 1
                if depth == 0:
                    return j
        return -1

    rnd = random.Random(7)
    for _ in range(30):
        s = "".join(rnd.choice("(){}[]ab ") for _ in range(6000))
        for i in range(0, len(s), 7):
            if s[i] in "([{":
                assert lexer.match_close(s, i) == slow(s, i)


def test_unclosed_brackets_stay_linear(tmp_path):
    write(tmp_path, "b.ts", "new Worker('q', async () => {\n" * 3000 + "\nconst g = (" * 3000)
    start = time.time()
    found(tmp_path)
    assert time.time() - start < 20


def test_stmt_end_fast_path_equals_the_scan_on_balanced_code():
    import random
    from vibeaudit import lexer

    def slow(bare, i):
        depth, n, j = 0, len(bare), i
        while j < n:
            ch = bare[j]
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                if depth == 0:
                    return j
                depth -= 1
            elif depth == 0 and ch in ";,":
                return j
            elif depth == 0 and ch == "\n":
                before = bare[i:j].rstrip()
                if before and before[-1] not in "=(,+-*/&|?:{[" and not before.endswith("=>"):
                    if not lexer._CONT_START.match(bare, j + 1):
                        return j
            j += 1
        return n

    def balanced(rnd, depth=0):
        out = []
        for _ in range(rnd.randint(1, 6)):
            r = rnd.random()
            if r < 0.3 and depth < 6:
                o = rnd.choice("([{")
                out.append(o + balanced(rnd, depth + 1) + {"(": ")", "[": "]", "{": "}"}[o])
            else:
                out.append(rnd.choice(["a", " b", ";", ",", "\n", "x =", " + ", ".c", "=> "]))
        return "".join(out)

    rnd = random.Random(11)
    for _ in range(20):
        s = "".join(balanced(rnd) for _ in range(800))
        assert len(s) > 4000
        for i in range(0, len(s), 13):
            assert lexer.stmt_end(s, i) == slow(s, i), i
