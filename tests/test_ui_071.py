"""UI rules added in 0.7.1 (UI014-UI017) and the UI007 extension."""
import time

from vibeaudit.rules import RULES
from vibeaudit.scanner import Options, scan

NEW = ("UI014", "UI015", "UI016", "UI017")


def write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def found(root, *rules):
    res = scan(str(root), Options(offline=True, external="none", min_severity="low"))
    assert res.meta.get("internal_errors", []) == []
    return sorted((f.file, f.line, f.rule_id) for f in res.findings if f.rule_id in (rules or NEW))


def component(body):
    return f'import {{ useState }} from "react";\nexport default function C(props) {{\n{body}\n}}\n'


def test_new_rules_start_as_preview():
    assert all(RULES[r].preview and RULES[r].preview_reason for r in NEW)


def test_images_without_dimensions(tmp_path):
    write(tmp_path, "c.tsx", component(
        "  return (<div>\n"
        '    <img src="/a.png" alt="a" />\n'                                  # 4
        '    <img src="/b.png" alt="b" width={40} height={40} />\n'
        '    <img src="/c.png" alt="c" className="h-8 w-8 rounded" />\n'
        '    <img src="/d.png" alt="d" style={{ aspectRatio: "1" }} />\n'
        "    <img {...props} />\n"
        "  </div>)"))
    write(tmp_path, "page.html", '<img src="a.png" alt="">\n<img src="b.png" alt="" width="10" height="10">\n<img class="logo" src="c.png" alt="">\n')
    assert found(tmp_path, "UI014") == [("c.tsx", 4, "UI014"), ("page.html", 1, "UI014")]


def test_form_errors_need_to_be_announced(tmp_path):
    form = ("  return (<form>\n    <label>Email <input name=\"email\" {extra}/></label>\n"
            "    {errors.email && <p className=\"text-red-500\"{role}>{errors.email.message}</p>}\n  </form>)")
    write(tmp_path, "a.tsx", component(form.replace("{extra}", "").replace("{role}", "")))
    write(tmp_path, "b.tsx", component(form.replace("{extra}", 'aria-describedby="email-error" ').replace("{role}", "")))
    write(tmp_path, "c.tsx", component(form.replace("{extra}", "").replace("{role}", ' role="alert"')))
    assert found(tmp_path, "UI015") == [("a.tsx", 5, "UI015")]


def test_focus_outline_removed_without_a_replacement(tmp_path):
    write(tmp_path, "c.tsx", component(
        "  return (<div>\n"
        '    <button className="rounded px-2 outline-none">a</button>\n'                                        # 4
        '    <button className="rounded focus:outline-none">b</button>\n'                                       # 5
        '    <button className="focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">c</button>\n'
        '    <input aria-label="q" className="outline-none focus:border-blue-500" />\n'
        '    <div className="outline-nonesense">d</div>\n'
        "  </div>)"))
    write(tmp_path, "app.css", "a:focus { outline: none; }\n"                                                # 1
          "button:focus-visible { outline: 0; box-shadow: 0 0 0 2px blue; }\n"
          "/* input:focus { outline: none } */\n.x { outline: none; }\n")
    assert found(tmp_path, "UI016") == [("app.css", 1, "UI016"), ("c.tsx", 4, "UI016"), ("c.tsx", 5, "UI016")]


def test_asset_links_to_missing_files(tmp_path):
    write(tmp_path, "public/logo.svg", "<svg/>")
    write(tmp_path, "public/fonts/inter.woff2", "x")
    write(tmp_path, "app/favicon.ico", "x")
    write(tmp_path, "app/page.tsx", component(
        "  return (<div>\n"
        '    <img src="/logo.svg" alt="" width={1} height={1} />\n'
        '    <img src="/hero.png" alt="" width={1} height={1} />\n'            # 5
        '    <link rel="icon" href="/favicon.ico" />\n'
        '    <a href="/docs/guide.pdf">Guide</a>\n'                            # 7
        '    <img src={`/avatars/${props.id}.png`} alt="" width={1} height={1} />\n'
        '    <img src="https://cdn.example.com/x.png" alt="" width={1} height={1} />\n'
        "  </div>)"))
    write(tmp_path, "app/globals.css", "@font-face { src: url('/fonts/inter.woff2'); }\n@font-face { src: url('/fonts/gone.woff2'); }\n")
    assert found(tmp_path, "UI017") == [("app/globals.css", 2, "UI017"), ("app/page.tsx", 5, "UI017"), ("app/page.tsx", 7, "UI017")]


def test_no_public_folder_means_no_asset_findings(tmp_path):
    write(tmp_path, "src/App.tsx", component('  return <img src="/hero.png" alt="" width={1} height={1} />'))
    assert found(tmp_path, "UI017") == []


def test_hydration_window_size_and_random_ids(tmp_path):
    write(tmp_path, "package.json", '{"dependencies": {"next": "15.0.0"}}')
    write(tmp_path, "c.tsx", component(
        "  return (<div>\n"
        "    <p>{window.innerWidth > 600 ? 'wide' : 'narrow'}</p>\n"   # 4
        "    <p id={ok}>{crypto.randomUUID()}</p>\n"                    # 5
        "  </div>)"))
    assert found(tmp_path, "UI007") == [("c.tsx", 4, "UI007"), ("c.tsx", 5, "UI007")]


def test_new_ui_patterns_are_linear_on_hostile_input(tmp_path):
    write(tmp_path, "a.tsx", component("  return <div className=\"" + "outline-none " * 30000 + "\" />"))
    write(tmp_path, "b.css", ":focus " * 20000 + "{ outline: none }\n" + "a:focus {" * 5000)
    write(tmp_path, "public/x.png", "x")
    write(tmp_path, "c.tsx", component("  return <img src=\"/" + "a/" * 40000 + "\" />"))
    start = time.time()
    found(tmp_path)
    assert time.time() - start < 15


def test_focus_outline_on_state_styled_parts_text_fields_and_containers_is_fine(tmp_path):
    # the shadcn/ui and Radix patterns that made 55 of 65 corpus findings false
    write(tmp_path, "ui.tsx", component(
        "  return (<div>\n"
        '    <PopoverPrimitive.Content className={cn("z-50 rounded-md border p-4 shadow-md outline-none data-[state=open]:animate-in")} />\n'
        '    <CommandPrimitive.Item className="px-2 outline-none aria-selected:bg-accent" />\n'
        '    <CommandPrimitive.Input className="h-11 bg-transparent outline-none placeholder:text-muted-foreground" />\n'
        '    <textarea aria-label="t" className="w-full outline-none" />\n'
        '    <button className={cn("rounded border outline-none", "focus-visible:ring-2")}>ok</button>\n'
        '    <DialogContent className={cn("flex outline-none", "bg-transparent")} />\n'
        '    <TabsPrimitive.Content className={cn("flex-1 outline-none", props.className)} />\n'   # 10
        "  </div>)"))
    write(tmp_path, "editor.tsx", "const e = useEditor({ editorProps: { attributes: { class: cn('focus:outline-none min-h-[320px]') } } });\n")
    write(tmp_path, "a.css", "textarea:focus-visible { outline: none; }\nh2 { &:focus { color: red; outline: none; } }\n")
    write(tmp_path, "vendor.min.css", "a:focus{outline:0}\n")
    assert found(tmp_path, "UI016") == [("ui.tsx", 10, "UI016")]
