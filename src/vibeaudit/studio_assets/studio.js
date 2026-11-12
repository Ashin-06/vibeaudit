// vibeaudit studio. Everything from the scanned repository is untrusted text: it is only ever put into the
// page with textContent (the el() helper below); nothing is parsed as HTML.
"use strict";

const token = new URLSearchParams(location.hash.slice(1)).get("token") || sessionStorage.getItem("vibeaudit-token") || "";
if (token) {
  sessionStorage.setItem("vibeaudit-token", token);
  history.replaceState(null, "", location.pathname);  // keep the token out of the address bar and history
}
let data = null;
let view = "score";

function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "class") node.className = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
}

async function api(path, method) {
  const resp = await fetch(path, { method: method || "GET", headers: { "X-Studio-Token": token } });
  if (!resp.ok) throw new Error((await resp.json().catch(() => ({}))).error || resp.statusText);
  return resp.json();
}

function fail(err) {
  const box = document.getElementById("error");
  box.hidden = false;
  box.textContent = "Error: " + err.message + (token ? "" : " (open the link printed by `vibeaudit studio`)");
}

function wrap(table) { return el("div", { class: "table-wrap" }, table); }
function sev(s) { return el("span", { class: "badge sev-" + s }, s); }
function yesno(v, yes, no) { return el("span", { class: "badge " + (v ? "yes" : "no") }, v ? yes : no); }
function byFp(fp) { return data.findings.find((f) => f.fingerprint === fp); }

function render() {
  const root = document.getElementById("view");
  root.replaceChildren();
  document.querySelectorAll("nav button").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.view === view)));
  ({ score: renderScore, routes: renderRoutes, flows: renderFlows, findings: renderFindings })[view](root);
}

function renderScore(root) {
  root.append(el("div", { class: "cards" },
    el("div", { class: "card" }, "Score", el("b", {}, `${data.score}/100`), `Grade ${data.grade}`),
    data.domains.map((d) => el("div", { class: "card" }, d.domain, el("b", {}, d.score),
      el("div", { class: "bar", role: "img", "aria-label": `${d.domain} ${d.score} of 100` },
        el("span", {}))))));
  root.querySelectorAll(".bar span").forEach((bar, i) => { bar.style.width = data.domains[i].score + "%"; });
  for (const d of data.domains) {
    if (!d.categories.length) continue;
    root.append(el("h2", {}, `${d.domain}: ${d.score}/100`));
    for (const c of d.categories) {
      root.append(el("details", {},
        el("summary", {}, `${c.category}: -${c.points} points`),
        wrap(el("table", {}, el("tbody", {}, c.rules.map((r) => el("tr", {},
          el("td", {}, el("code", {}, r.rule_id)), el("td", {}, r.title), el("td", {}, `-${r.points}`),
          el("td", {}, r.findings.map((fp) => {
            const f = byFp(fp);
            return el("button", { type: "button", onclick: () => showFinding(fp) }, `${f.file}:${f.line}`);
          })))))))));
    }
  }
  if (data.notes.length) root.append(el("h3", {}, "Notes"), el("ul", {}, data.notes.map((n) => el("li", {}, n))));
}

function renderRoutes(root) {
  root.append(el("h2", {}, `${data.routes.length} routes`));
  root.append(wrap(el("table", {}, el("thead", {}, el("tr", {}, ["Method", "Path", "Auth", "Writes", "AI", "Findings", "Location"].map((h) => el("th", {}, h)))),
    el("tbody", {}, data.routes.map((r) => el("tr", { class: "clickable", tabindex: "0",
      onclick: () => showCode(r.file, r.line), onkeydown: (e) => { if (e.key === "Enter") showCode(r.file, r.line); } },
      el("td", {}, r.methods.join("/")), el("td", {}, el("code", {}, r.path)),
      el("td", {}, yesno(r.authenticated, "auth", "no auth")),
      el("td", {}, r.writes_data ? el("span", { class: "badge neutral" }, "writes") : ""),
      el("td", {}, r.calls_llm ? el("span", { class: "badge neutral" }, "calls AI") : ""),
      el("td", {}, r.findings.length ? r.findings.map((fp) => sev(byFp(fp).severity)) : ""),
      el("td", {}, el("code", {}, `${r.file}:${r.line}`))))))));
}

function renderFlows(root) {
  const groups = {};
  for (const f of data.flows) (groups[`${f.source} -> ${f.sink}`] = groups[`${f.source} -> ${f.sink}`] || []).push(f);
  root.append(el("h2", {}, `${data.flows.length} data-flow findings`),
    el("p", { class: "muted" }, "Where request data or model output reaches a model prompt, a database, a shell, HTML or a request. Traces follow variables within a function or file."));
  for (const [key, flows] of Object.entries(groups).sort()) {
    root.append(el("h3", {}, `${key} (${flows.length})`));
    for (const f of flows) {
      root.append(el("details", {},
        el("summary", {}, sev(f.severity), `${f.rule_id} ${f.title} `, el("code", {}, `${f.file}:${f.line}`)),
        f.steps.length ? el("ol", { class: "flow" }, f.steps.map((s) => el("li", { class: s.role },
          el("code", {}, `${f.file}:${s.line}  ${s.code}`), s.note ? el("div", { class: "muted" }, s.note) : "")))
          : el("p", { class: "muted" }, "No source traced: the rule matched the line itself."),
        el("button", { type: "button", onclick: () => showFinding(f.fingerprint) }, "Details")));
    }
  }
}

function renderFindings(root) {
  root.append(el("h2", {}, `${data.findings.length} findings`));
  root.append(wrap(el("table", {}, el("thead", {}, el("tr", {}, ["Severity", "Rule", "Location", "Message"].map((h) => el("th", {}, h)))),
    el("tbody", {}, data.findings.map((f) => el("tr", { class: "clickable", tabindex: "0",
      onclick: () => showFinding(f.fingerprint), onkeydown: (e) => { if (e.key === "Enter") showFinding(f.fingerprint); } },
      el("td", {}, sev(f.severity), f.gating ? "" : el("span", { class: "badge neutral" }, "preview")),
      el("td", {}, el("code", {}, f.rule_id)), el("td", {}, el("code", {}, `${f.file}:${f.line}`)), el("td", {}, f.message)))))));
}

function codeBlock(lines) {
  return el("pre", {}, lines.map((c) => el("span", { class: "code-line" + (c.current ? " current" : "") },
    `${String(c.line).padStart(5)} | ${c.code}`)));
}

function openDetail(...children) {
  const box = document.getElementById("detail");
  box.replaceChildren(el("button", { type: "button", onclick: () => { box.hidden = true; document.querySelector("main").classList.remove("with-detail"); } }, "Close"), ...children);
  box.hidden = false;
  document.querySelector("main").classList.add("with-detail");
  box.focus();
}

async function showFinding(fp) {
  try {
    const e = await api("/api/explain?fingerprint=" + encodeURIComponent(fp));
    openDetail(el("h2", {}, sev(e.severity), `${e.rule_id} ${e.title}`), el("p", {}, el("code", {}, `${e.file}:${e.line}`)),
      el("p", {}, e.message), el("h3", {}, "Why it matters"), el("p", {}, e.why), el("h3", {}, "How to fix it"), el("p", {}, e.fix),
      e.code.length ? [el("h3", {}, "Code"), codeBlock(e.code)] : "",
      e.flow.length ? [el("h3", {}, "Data flow"), el("ol", { class: "flow" }, e.flow.map((s) => el("li", { class: s.role },
        el("code", {}, `${e.file}:${s.line}  ${s.code}`), s.note ? el("div", { class: "muted" }, s.note) : "")))] : "",
      el("p", { class: "muted" }, `Fingerprint ${e.fingerprint}`));
  } catch (err) { fail(err); }
}

async function showCode(file, line) {
  try {
    const c = await api(`/api/code?file=${encodeURIComponent(file)}&line=${line}`);
    openDetail(el("h2", {}, el("code", {}, `${c.file}:${line}`)), codeBlock(c.lines));
  } catch (err) { fail(err); }
}

function summarize() {
  const c = data.counts;
  document.getElementById("summary").textContent =
    `${data.root}: ${data.files_scanned} files, score ${data.score}/100 (${data.grade}); ` +
    `${c.critical} critical, ${c.high} high, ${c.medium} medium, ${c.low} low (vibeaudit ${data.version})`;
}

async function load(method) {
  try {
    data = await api(method === "POST" ? "/api/rescan" : "/api/scan", method);
    document.getElementById("error").hidden = true;
    summarize();
    render();
  } catch (err) { fail(err); }
}

document.querySelectorAll("nav button").forEach((b) => b.addEventListener("click", () => { view = b.dataset.view; render(); }));
document.getElementById("rescan").addEventListener("click", () => load("POST"));
document.getElementById("detail").setAttribute("tabindex", "-1");
load("GET");
