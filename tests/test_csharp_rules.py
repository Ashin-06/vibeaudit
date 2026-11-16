"""C# and ASP.NET Core: the lexer, routes and authorization, request data into the generic sinks, CSHARP001-003."""
import time

from vibeaudit.csharp import CsScanner, cs_views
from vibeaudit.deps import nuget_dependencies
from vibeaudit.files import Project
from vibeaudit.rules import RULES
from vibeaudit.scanner import Options, scan

CONTROLLER = """using Microsoft.AspNetCore.Mvc;

namespace App.Controllers;

[ApiController]
[Route("api/[controller]")]
public class UsersController : ControllerBase
{
    [HttpGet("search")]
    public IActionResult Search([FromQuery] string name)
    {
        var sql = $"SELECT * FROM Users WHERE Name = '{name}'";
        return Ok(_db.Users.FromSqlRaw(sql).ToList());
    }

    [HttpGet("safe")]
    public IActionResult Safe(string name) => Ok(_db.Users.FromSqlInterpolated($"SELECT * FROM Users WHERE Name = {name}"));

    [HttpPost("run")]
    public IActionResult Run([FromBody] RunRequest req)
    {
        Process.Start("git", req.Args);
        return Ok();
    }

    [HttpGet("file")]
    public IActionResult Download(string path)
    {
        var full = Path.Combine("/srv/files", path);
        return PhysicalFile(full, "application/octet-stream");
    }

    [HttpGet("go")]
    public IActionResult Go(string returnUrl) => Redirect(returnUrl);

    [HttpGet("go-local")]
    public IActionResult GoLocal(string returnUrl)
    {
        if (Url.IsLocalUrl(returnUrl)) return Redirect(returnUrl);
        return Redirect("/");
    }

    [HttpGet("fetch")]
    public async Task<string> Fetch(string url) => await _http.GetStringAsync(url);

    [HttpGet("fixed")]
    public async Task<string> Fixed(string id) => await _http.GetStringAsync($"https://api.example.com/items/{id}");
}
"""

MINIMAL = """var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();
var api = app.MapGroup("/api").RequireAuthorization();
var admin = api.MapGroup("/admin");
app.MapPost("/notes", (Note n, AppDb db) => db.Add(n)).RequireAuthorization();
app.MapPost("/login", (Login l) => Results.Ok()).AllowAnonymous();
admin.MapDelete("/users/{id}", (int id, AppDb db) => db.Remove(id));
app.MapGet("/q", (HttpContext ctx) => Results.Redirect(ctx.Request.Query["next"]));
app.Run();
"""


def write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def found(root):
    res = scan(str(root), Options(offline=True, external="none", min_severity="low"))
    assert res.meta.get("internal_errors", []) == []
    return {(f.file, f.line, f.rule_id) for f in res.findings}


def routes(root):
    return {(r.path, r.methods[0]): r.has_auth for r in CsScanner(Project(root), lambda f: None).run()}


def test_csharp_rules_are_preview():
    assert all(RULES[r].preview and RULES[r].preview_reason for r in ("CSHARP001", "CSHARP002", "CSHARP003"))


def test_lexer_blanks_every_string_form():
    src = 'var a = @"C:\\\\x ""q"" y"; var b = $"{n} \\" z"; var c = """\n raw "" text \n"""; char d = \'"\'; // "c"\nint e;'
    v = cs_views(src)
    assert "raw" not in v.bare and "q" not in v.bare and "z" not in v.bare and "c\"" not in v.code
    assert v.bare.endswith("int e;") and len(v.bare) == len(src)


def test_request_data_into_sinks(tmp_path):
    write(tmp_path, "Controllers/UsersController.cs", CONTROLLER)
    f = {(x[1], x[2]) for x in found(tmp_path) if x[0] == "Controllers/UsersController.cs" and x[2].startswith("BE")}
    assert f == {(13, "BE001"), (22, "BE002"), (30, "BE006"), (34, "BE008"), (44, "BE005")}


def test_routes_and_authorization(tmp_path):
    write(tmp_path, "Program.cs", MINIMAL)
    write(tmp_path, "Controllers/OrdersController.cs",
          "[Authorize]\n[Route(\"orders\")]\npublic class OrdersController : Controller\n{\n"
          "    [HttpPost]\n    public IActionResult Create(Order o) { _db.Add(o); return Ok(); }\n\n"
          "    [AllowAnonymous]\n    [HttpGet(\"{id}\")]\n    [ProducesResponseType(200)]\n"
          "    public IActionResult Get(int id) => Ok(_db.Find(id));\n}\n")
    got = routes(tmp_path)
    assert got[("/notes", "POST")] and got[("/api/admin/users/{id}", "DELETE")]
    assert not got[("/login", "POST")] and not got[("/q", "GET")]
    assert got[("/orders", "POST")] and not got[("/orders/{id}", "GET")]
    assert (str("Program.cs"), 8, "BE008") in found(tmp_path)


def test_no_authorization_anywhere(tmp_path):
    write(tmp_path, "Controllers/NotesController.cs",
          "[ApiController]\n[Route(\"api/notes\")]\npublic class NotesController : ControllerBase\n{\n"
          "    [HttpPost]\n    public IActionResult Create(Note n) { _db.Notes.Add(n); _db.SaveChanges(); return Ok(); }\n"
          "    [HttpDelete(\"{id}\")]\n    public IActionResult Delete(int id) { _db.Remove(id); _db.SaveChanges(); return Ok(); }\n}\n")
    f = found(tmp_path)
    assert ("Controllers/NotesController.cs", 5, "CSHARP001") in f
    assert not [x for x in f if x[2] == "AUTH001"]
    # a fallback policy, or a project's own API-key filter, is authorization
    write(tmp_path, "Program.cs", "builder.Services.AddAuthorization(o => o.FallbackPolicy = new AuthorizationPolicyBuilder()"
                                  ".RequireAuthenticatedUser().Build());\n")
    assert not [x for x in found(tmp_path) if x[2] in ("CSHARP001", "AUTH001")]
    (tmp_path / "Program.cs").unlink()
    write(tmp_path, "Filters/ApiKeyAuthFilter.cs", "public class ApiKeyAuthFilter : IAuthorizationFilter { }\n")
    assert not [x for x in found(tmp_path) if x[2] in ("CSHARP001", "AUTH001")]


def test_deserialization_and_developer_page(tmp_path):
    write(tmp_path, "Json.cs", "class J {\n  object R(string s) {\n    var o = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All };\n"
                               "    return JsonConvert.DeserializeObject(s, o);\n  }\n}\n")
    write(tmp_path, "Bound.cs", "class B {\n  JsonSerializerSettings S() => new() { TypeNameHandling = TypeNameHandling.Auto, "
                                "SerializationBinder = new KnownTypes() };\n}\n")
    write(tmp_path, "Bin.cs", "class C {\n  object R(Stream s) {\n    return new BinaryFormatter().Deserialize(s);\n  }\n}\n")
    write(tmp_path, "Program.cs", "var app = builder.Build();\napp.UseDeveloperExceptionPage();\n"
                                  "if (app.Environment.IsDevelopment())\n{\n    app.UseMigrationsEndPoint();\n}\n")
    f = sorted(x for x in found(tmp_path) if x[2] in ("CSHARP002", "CSHARP003"))
    assert f == [("Bin.cs", 3, "CSHARP002"), ("Json.cs", 3, "CSHARP002"), ("Program.cs", 2, "CSHARP003")]


def test_nuget_dependencies():
    text = ('<ItemGroup>\n  <PackageReference Include="Newtonsoft.Json" Version="12.0.1" />\n'
            '  <PackageReference Include="Serilog">\n    <Version>2.10.0</Version>\n  </PackageReference>\n'
            '  <PackageReference Include="Floating" Version="1.*" />\n  <PackageReference Include="NoVersion" />\n'
            '  <PackageVersion Include="Exact" Version="[3.1.0]" />\n</ItemGroup>\n')
    assert nuget_dependencies(text) == [("Newtonsoft.Json", "12.0.1", 2), ("Serilog", "2.10.0", 3), ("Exact", "3.1.0", 8)]


def test_csharp_checks_are_linear_on_hostile_input(tmp_path):
    write(tmp_path, "H.cs", "[ApiController]\npublic class H : ControllerBase {\n"
          + "  [HttpPost(\"x\")]\n  public IActionResult M([FromQuery] string a) {\n" * 3000
          + "var s = $\"" * 3000 + "@\"" * 3000 + "\"\"\"" * 1000 + "\n}\n")
    write(tmp_path, "P.cs", "app.MapGet(\"/" + "a" * 5000 + "\n" + "var g = app.MapGroup(\"/x\")" * 3000 + "\n")
    write(tmp_path, "App.csproj", "<PackageReference Include=\"a\"" * 5000)
    start = time.time()
    found(tmp_path)
    assert time.time() - start < 30


def test_group_role_policy_reset_endpoints_and_ef_fromsql(tmp_path):
    write(tmp_path, "Endpoints/Codes.cs",
          "public static class Codes {\n  public static void Map(IEndpointRouteBuilder app) {\n"
          "    var admin = app.MapGroup(\"/api/admin/codes\")\n        .WithTags(\"Admin\")\n"
          "        .RequireAuthorization(policy => policy.RequireRole(\"Admin\"));\n"
          "    admin.MapPost(\"/\", Create);\n    admin.MapDelete(\"/{id}\", Delete);\n  }\n}\n")
    write(tmp_path, "Controllers/PasswordResetsController.cs",
          "[Route(\"api/[controller]\")]\npublic class PasswordResetsController : Controller {\n"
          "  [HttpPost]\n  public IActionResult Create(Reset r) { _db.Add(r); _db.SaveChanges(); return Ok(); }\n}\n")
    write(tmp_path, "Controllers/ProductsController.cs",
          "[Authorize]\n[Route(\"api/[controller]\")]\npublic class ProductsController : Controller {\n"
          "  [HttpGet(\"search\")]\n  public IActionResult Search(string keyword) {\n"
          "    var query = $\"SELECT * FROM Products WHERE name LIKE '%{keyword}%'\";\n"
          "    var a = _db.Products.FromSql(query).ToList();\n"
          "    var b = _db.Products.FromSql($\"SELECT * FROM Products WHERE name = {keyword}\").ToList();\n"
          "    var client = new HttpClient();\n    return Ok(a);\n  }\n}\n")
    f = found(tmp_path)
    assert not [x for x in f if x[2] in ("AUTH001", "AUTH002", "REL001")]  # .NET's HttpClient times out after 100 s
    assert [x[1] for x in f if x[2] == "BE001"] == [7]


def test_versioned_route_template_and_service_get_async(tmp_path):
    write(tmp_path, "Controllers/AdminAudioController.cs",
          "[ApiController]\n[Route(\"api/v{version:apiVersion}/admin/audio\")]\n[Authorize]\n"
          "public class AdminAudioController : ControllerBase {\n"
          "  [HttpDelete(\"{id}\")]\n  public async Task<IActionResult> Delete(Guid id) { await _db.RemoveAsync(id); return NoContent(); }\n"
          "  [HttpGet(\"fetch\")]\n  public async Task<IActionResult> Fetch(string id, string url) {\n"
          "    var job = await jobs.GetAsync(id);\n    var page = await _httpClient.GetStringAsync(url);\n    return Ok(job);\n  }\n}\n")
    got = routes(tmp_path)
    assert ("/api/v{version:apiVersion}/admin/audio/{id}", "DELETE") in got
    assert [(x[1], x[2]) for x in found(tmp_path) if x[2] == "BE005"] == [(10, "BE005")]


def test_repeated_json_record_keys_are_not_secrets(tmp_path):
    rows = ",\n".join('    {"token": "%032x", "title": "t%d"}' % (0x5f3a9c2e7b1d4086a2c4e6f8091b3d5e + i * 7919, i) for i in range(6))
    write(tmp_path, "contract/captures/releases.json", '{\n  "releases": [\n' + rows + "\n  ]\n}\n")
    write(tmp_path, "config/app.json", '{\n  "token": "5f3a9c2e7b1d4086a2c4e6f8091b3d5e"\n}\n')
    assert sorted(x[0] for x in found(tmp_path) if x[2] == "SEC003") == ["config/app.json"]


def test_dotnet_test_projects_are_tests(tmp_path):
    for i in range(3):
        write(tmp_path, f"Todo.Web/wwwroot/js/app{i}.js", f"export const a{i} = {i};\n")
    write(tmp_path, "Todo.Api/Program.cs", "var app = WebApplication.Create();\napp.Run();\n")
    write(tmp_path, "Todo.Api.Tests/TestHelper.cs",
          "class TestHelper {\n  const string ApiToken = \"9f2c4e6a8b1d3f5a7c9e0b2d4f6a8c1e\";\n}\n")
    f = found(tmp_path)
    assert not [x for x in f if x[2] in ("QA001", "SEC003")]


# found on the front ends of the C# corpus
def test_validation_messages_and_placeholders_are_not_secrets_or_calls(tmp_path):
    write(tmp_path, "web/src/UserModal.tsx",
          "export function v(formData) {\n  const newErrors = {};\n"
          "  if (!formData.password) {\n    newErrors.password = \"\u8bf7\u8f93\u5165\u5bc6\u7801\";\n  }\n"
          "  const password = \"hunter2Xq9\";\n  return newErrors;\n}\n")
    write(tmp_path, "web/src/AccountModal.tsx",
          "\"use client\";\nexport const F = () => <input placeholder=\"\u4f8b\u5982\uff1ahttps://api.openai.com/v1\" />;\n"
          "export const G = () => fetch(\"https://api.openai.com/v1/chat/completions\");\n")
    f = found(tmp_path)
    assert [x[1] for x in f if x[2] == "SEC011"] == [6]
    assert [x[1] for x in f if x[2] == "FE002"] == [3]
