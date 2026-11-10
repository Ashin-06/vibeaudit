"""UI, UX and accessibility rules (UI001-UI013)."""
from vibeaudit.scanner import Options, scan


def write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def _rules(tmp_path):
    res = scan(str(tmp_path), Options(offline=True, external="none"))
    assert res.meta.get("internal_errors", []) == []  # a crash inside a check is isolated per file, so look for it
    return sorted((f.file, f.line, f.rule_id) for f in res.findings if f.rule_id.startswith("UI"))


def component(body, head=""):
    return f'import {{ useState, useEffect }} from "react";\n{head}export default function C(props) {{\n{body}\n}}\n'


def test_alt_text_labels_and_keyboard_access(tmp_path):
    write(tmp_path, "c.tsx", component(
        "  return (<div>\n"
        '    <img src="/a.png" />\n'                                    # 4 UI001
        '    <img src="/b.png" alt="" />\n'
        "    <div onClick={() => go()}>open</div>\n"                    # 6 UI002
        "    <div role=\"button\" onClick={() => go()} onKeyDown={k}>open</div>\n"
        "    <div onClick={e => e.stopPropagation()}>menu</div>\n"
        '    <input name="q" placeholder="Search" />\n'                  # 9 UI003
        '    <input id="email" name="email" />\n'
        '    <label>Name <input name="name" /></label>\n'
        '    <input type="file" className="hidden" />\n'
        '    <input tabIndex={-1} className="sr-trap" />\n'
        "    <input {...props} />\n"
        "  </div>)"))
    assert _rules(tmp_path) == [("c.tsx", 4, "UI001"), ("c.tsx", 6, "UI002"), ("c.tsx", 9, "UI003")]


def test_dead_controls(tmp_path):
    write(tmp_path, "c.tsx", component(
        "  return (<div>\n"
        "    <button onClick={() => {}}>Save</button>\n"                # 4
        "    <button onClick={() => console.log('clicked')}>Pay</button>\n"  # 5
        '    <a href="#">Docs</a>\n'                                     # 5
        '    <a href="#" onClick={open}>Menu</a>\n'
        "    <button onClick={() => save()}>Save</button>\n"
        "  </div>)"))
    assert _rules(tmp_path) == [("c.tsx", 4, "UI004"), ("c.tsx", 5, "UI004"), ("c.tsx", 6, "UI004")]


def test_index_keys_only_where_items_hold_state_and_the_list_changes(tmp_path):
    body = ("  const [todos, setTodos] = useState([]);\n"
            "  const remove = (id) => setTodos(todos.filter(t => t.id !== id));\n"
            "  return (<ul>\n"
            "    {todos.map((t, i) => <li key={i}><input defaultValue={t.text} aria-label=\"todo\" /></li>)}\n"  # 6
            "    {todos.map((t, i) => <li key={i}>{t.text}</li>)}\n"
            "    {todos.map((t, i) => <li key={t.id}><input defaultValue={t.text} aria-label=\"todo\" /></li>)}\n"
            "  </ul>)")
    write(tmp_path, "c.tsx", component(body))
    assert _rules(tmp_path) == [("c.tsx", 6, "UI005")]
    write(tmp_path, "c.tsx", component(body.replace("todos.filter(t => t.id !== id)", "[...todos, id]")))
    assert _rules(tmp_path) == []  # append-only: indexes stay stable


def test_destructive_actions_need_confirmation_but_removing_from_a_list_does_not(tmp_path):
    write(tmp_path, "a.tsx", component("  return <button onClick={() => handleDelete(props.id)}>Delete</button>"))
    write(tmp_path, "b.tsx", component("  return <button onClick={() => onRemoveAttachment(props.id)}>x</button>"))
    write(tmp_path, "c.tsx", component(
        "  return <button onClick={() => { if (confirm('Delete?')) handleDelete(props.id) }}>Delete</button>"))
    assert _rules(tmp_path) == [("a.tsx", 3, "UI006")]


def test_hydration_traps_in_server_rendered_apps(tmp_path):
    body = ("  return (<footer>\n"
            "    <p>Rendered at {new Date().toLocaleTimeString()}</p>\n"     # 4
            "    <p>Id {Math.random()}</p>\n"                               # 5
            "    <p>&copy; {new Date().getFullYear()} Acme</p>\n"
            "  </footer>)")
    write(tmp_path, "c.tsx", component(body))
    assert _rules(tmp_path) == []  # plain React SPA: nothing is server-rendered
    write(tmp_path, "package.json", '{"dependencies": {"next": "14.0.0"}}')
    assert _rules(tmp_path) == [("c.tsx", 4, "UI007"), ("c.tsx", 5, "UI007")]


def test_effects_cleanup_and_loading_error_states(tmp_path):
    write(tmp_path, "a.tsx", component(
        "  useEffect(() => {\n    const t = setInterval(tick, 1000);\n  }, []);\n"              # 3 UI008
        "  useEffect(() => {\n    window.addEventListener('resize', f);\n"
        "    return () => window.removeEventListener('resize', f);\n  }, []);\n"
        "  return <p>x</p>"))
    write(tmp_path, "b.tsx", component(
        "  const [rows, setRows] = useState([]);\n"
        "  useEffect(() => {\n    fetch('/api/rows').then(r => r.json()).then(setRows);\n  }, []);\n"  # 4 UI009
        "  return <p>{rows.length}</p>"))
    write(tmp_path, "c.tsx", component(
        "  const [rows, setRows] = useState(null);\n  const [error, setError] = useState(null);\n"
        "  useEffect(() => {\n    fetch('/api/rows').then(r => r.json()).then(setRows).catch(setError);\n  }, []);\n"
        "  if (error) return <p>Failed</p>;\n  if (!rows) return <p>Loading</p>;\n  return <p>{rows.length}</p>"))
    write(tmp_path, "useRows.ts", 'import { useState, useEffect } from "react";\nexport function useRows() {\n'
          "  const [rows, setRows] = useState<Row[] | null>(null);\n"
          "  useEffect(() => {\n    fetch('/api/rows').then(r => r.json()).then(setRows);\n  }, []);\n  return rows;\n}\n")
    res = scan(str(tmp_path), Options(offline=True, external="none"))
    got = sorted((f.file, f.line, f.rule_id, f.message.split(";")[0]) for f in res.findings if f.rule_id.startswith("UI"))
    assert got == [("a.tsx", 3, "UI008", "The effect starts `setInterval` but never cleans it up"),
                   ("b.tsx", 4, "UI009", "Data is fetched with no loading or error state"),
                   ("useRows.ts", 4, "UI009", "Data is fetched with no error state")]


def test_placeholder_content_and_viewport(tmp_path):
    write(tmp_path, "package.json", '{"dependencies": {"vite": "5.0.0"}}')
    write(tmp_path, "index.html", "<!doctype html>\n<html>\n<head><title>x</title></head>\n<body><p>Lorem ipsum dolor sit amet</p></body>\n</html>\n")
    write(tmp_path, "public/widget/index.html", "<!doctype html>\n<html><body>embed</body></html>\n")
    write(tmp_path, "src/stories/Hero.tsx", component("  return <p>Lorem ipsum</p>"))
    assert _rules(tmp_path) == [("index.html", 2, "UI012"), ("index.html", 4, "UI010")]
    write(tmp_path, "index.html", '<!doctype html>\n<html>\n<head><meta name="viewport" content="width=device-width"></head>\n</html>\n')
    assert _rules(tmp_path) == []


def test_next_error_page_and_metadata(tmp_path):
    write(tmp_path, "package.json", '{"dependencies": {"next": "14.0.0"}}')
    write(tmp_path, "app/layout.tsx", "export default function L({ children }) { return <html><body>{children}</body></html> }\n")
    for p in ("page.tsx", "about/page.tsx", "blog/[slug]/page.tsx"):
        write(tmp_path, "app/" + p, "export default function P() { return <main>hi</main> }\n")
    assert _rules(tmp_path) == [("app/layout.tsx", 1, "UI011"), ("app/layout.tsx", 1, "UI012")]
    write(tmp_path, "app/error.tsx", '"use client";\nexport default function E() { return <p>Something went wrong</p> }\n')
    write(tmp_path, "app/layout.tsx", "export const metadata = { title: 'x' };\n"
          "export default function L({ children }) { return <html><body>{children}</body></html> }\n")
    assert _rules(tmp_path) == []


def test_links_to_missing_pages(tmp_path):
    write(tmp_path, "package.json", '{"dependencies": {"next": "14.0.0"}}')
    write(tmp_path, "app/layout.tsx", "export const metadata = {};\nexport default function L({ children }) { return children }\n")
    write(tmp_path, "app/error.tsx", "export default function E() { return null }\n")
    for p in ("page.tsx", "(marketing)/pricing/page.tsx", "blog/[slug]/page.tsx", "docs/[[...path]]/page.tsx", "api/chat/route.ts"):
        write(tmp_path, "app/" + p, "export default function P() { return null }\n")
    write(tmp_path, "public/logo.svg", "<svg/>")
    write(tmp_path, "components/Nav.tsx", 'import Link from "next/link";\nexport function Nav({ router }) {\n  return (<nav>\n'
          '    <Link href="/pricing">Pricing</Link>\n    <Link href="/blog/hello">Post</Link>\n    <Link href="/docs">Docs</Link>\n'
          '    <Link href="/docs/a/b">Deep</Link>\n    <Link href="/logo.svg">Logo</Link>\n    <Link href="/prices">Typo</Link>\n'  # 9
          '    <a href="/blog">Blog index</a>\n'                                                                                  # 10
          "    <button onClick={() => router.push('/pricing?plan=pro')}>Go</button>\n"
          "  </nav>)\n}\n")
    assert _rules(tmp_path) == [("components/Nav.tsx", 9, "UI013"), ("components/Nav.tsx", 10, "UI013")]
    write(tmp_path, "next.config.js", "module.exports = { async rewrites() { return [] } };\n")
    assert _rules(tmp_path) == []


def test_spa_pages_folder_is_not_mapped_as_next_routes(tmp_path):
    write(tmp_path, "package.json", '{"dependencies": {"react-router-dom": "6.0.0"}}')
    write(tmp_path, "src/pages/Home.tsx", component("  return <a href=\"/login\">Log in</a>"))
    write(tmp_path, "src/pages/About.tsx", component("  return <p>About</p>"))
    assert _rules(tmp_path) == []
