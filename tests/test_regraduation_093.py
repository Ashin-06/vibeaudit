"""False-positive fixes for UI014 (images sized by a CSS-module class) and AUTH001 (dev-only server actions),
written from synthetic cases, not from the held-out findings."""
from vibeaudit.scanner import Options, scan


def write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def found(root, rule):
    res = scan(str(root), Options(offline=True, external="none", min_severity="low"))
    return sorted((f.file, f.line) for f in res.findings if f.rule_id == rule)


def test_images_sized_by_a_css_module_class(tmp_path):
    write(tmp_path, "package.json", '{"dependencies": {"react": "18.0.0"}}')
    write(tmp_path, "Avatar.tsx",
          "import styles from './Avatar.module.css';\n"
          "export function A({ src }: { src: string }) {\n"
          "  return (<div>\n"
          "    <img src={src} alt='' className={styles.avatar} />\n"
          "    <img src={src} alt='' className='rounded' />\n"      # 5: no size anywhere
          "  </div>);\n}\n")
    assert found(tmp_path, "UI014") == [("Avatar.tsx", 5)]


def test_server_actions_that_throw_outside_development(tmp_path):
    write(tmp_path, "package.json", '{"dependencies": {"next": "15.0.0"}}')
    write(tmp_path, "app/actions.ts",
          "'use server';\nimport { db } from '@/lib/db';\nimport { assertDevelopment } from '@/lib/env';\n\n"
          "export async function seedDemo() {\n  assertDevelopment();\n  await db.post.deleteMany();\n}\n\n"
          "export async function resetAll() {\n  if (process.env.NODE_ENV !== 'development') throw new Error('dev only');\n"
          "  await db.user.deleteMany();\n}\n\n"
          "export async function deletePost(id: string) {\n  await db.post.delete({ where: { id } });\n}\n")   # 15
    assert [line for _, line in found(tmp_path, "AUTH001")] == [15]
