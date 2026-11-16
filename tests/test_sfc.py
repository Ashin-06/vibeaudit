"""Vue and Svelte single-file components get the template and script UI checks."""
from pathlib import Path

from vibeaudit.scanner import Options, scan

SEEDED = Path(__file__).parent.parent / "benchmark" / "seeded" / "sfc_app"


def ui(root):
    res = scan(str(root), Options(offline=True, external="none", include_preview=True, min_severity="low"))
    assert res.meta.get("internal_errors", []) == []
    return sorted((f.rule_id, f.file.rsplit("/", 1)[-1], f.line) for f in res.findings if f.rule_id.startswith("UI"))


def test_seeded_vue_and_svelte_components():
    assert ui(SEEDED) == [
        ("UI002", "Feed.svelte", 9), ("UI002", "TodoList.vue", 3), ("UI003", "TodoList.vue", 4),
        ("UI004", "Feed.svelte", 9), ("UI004", "Feed.svelte", 11), ("UI005", "TodoList.vue", 8),
        ("UI006", "TodoList.vue", 6), ("UI008", "Feed.svelte", 4), ("UI008", "TodoList.vue", 24),
        ("UI009", "TodoList.vue", 24)]


def test_accessible_and_cleaned_up_components_are_quiet(tmp_path):
    (tmp_path / "Ok.vue").write_text(
        '<template>\n  <div role="button" tabindex="0" @click="go" @keydown.enter="go">Go</div>\n'
        '  <div class="overlay" @click.self="close"></div>\n  <label for="q">Search</label><input id="q" v-model="q" />\n'
        '  <button @click="deleteItem">Delete</button>\n  <ConfirmDialog />\n</template>\n'
        '<script setup>\nimport { onMounted, onUnmounted } from "vue";\n'
        'onMounted(() => { window.addEventListener("resize", f); });\nonUnmounted(() => window.removeEventListener("resize", f));\n</script>\n')
    (tmp_path / "Ok.svelte").write_text(
        '<script>\nimport { onMount } from "svelte";\nonMount(() => {\n  const t = setInterval(load, 1000);\n  return () => clearInterval(t);\n})\n</script>\n'
        '<button on:click={load}>Reload</button>\n')
    assert ui(tmp_path) == []
