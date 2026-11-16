"""Java and Kotlin: request data into the generic sinks, and JAVA002-JAVA004."""
import time

from vibeaudit.rules import RULES
from vibeaudit.scanner import Options, scan

CONTROLLER = """package x;

import org.springframework.web.bind.annotation.*;

@RestController
public class C {
    @GetMapping("/users")
    public List<User> users(@RequestParam String name) {
        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
        return jdbc.query(sql, mapper);
    }

    @GetMapping("/safe")
    public List<User> safe(@RequestParam String name) {
        return jdbc.query("SELECT * FROM users WHERE name = ?", mapper, name);
    }

    @PostMapping("/run")
    public String run(@RequestBody Cmd cmd) throws IOException {
        Process p = Runtime.getRuntime().exec(cmd.line);
        return "ok";
    }

    @GetMapping("/file")
    public byte[] file(@RequestParam("p") String path) throws IOException {
        return Files.readAllBytes(Paths.get("/srv/files", path));
    }

    @GetMapping("/go")
    public String go(@RequestParam String next) {
        return "redirect:" + next;
    }

    @GetMapping("/fetch")
    public String fetch(@RequestParam String url) {
        return rest.getForObject(url, String.class);
    }

    @GetMapping("/servlet")
    public void servlet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.sendRedirect(req.getParameter("to"));
    }
}
"""

KOTLIN = """package x

@RestController
class K(private val em: EntityManager) {
    @GetMapping("/k")
    fun k(@RequestParam q: String): Any {
        return em.createQuery("SELECT u FROM User u WHERE u.name = '$q'").resultList
    }
}
"""


def write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def found(root):
    res = scan(str(root), Options(offline=True, external="none", min_severity="low"))
    assert res.meta.get("internal_errors", []) == []
    return {(f.file, f.line, f.rule_id) for f in res.findings}


def test_java_rules_are_preview():
    assert all(RULES[r].preview and RULES[r].preview_reason for r in ("JAVA002", "JAVA003", "JAVA004"))


def test_request_data_into_sinks(tmp_path):
    write(tmp_path, "src/main/java/x/C.java", CONTROLLER)
    write(tmp_path, "src/main/kotlin/x/K.kt", KOTLIN)
    f = found(tmp_path)
    java = "src/main/java/x/C.java"
    assert {(java, 10, "BE001"), (java, 20, "BE002"), (java, 26, "BE006"), (java, 31, "BE008"), (java, 36, "BE005"),
            (java, 41, "BE008"), ("src/main/kotlin/x/K.kt", 7, "BE001")} <= f
    assert (java, 15, "BE001") not in f  # bound parameter


def test_actuator_permit_all_and_polymorphic_deserialization(tmp_path):
    write(tmp_path, "src/main/resources/application.properties",
          "server.port=8080\nmanagement.endpoints.web.exposure.include=*\nmanagement.endpoint.shutdown.enabled=true\n")
    write(tmp_path, "src/main/resources/application-prod.yml",
          "management:\n  endpoints:\n    web:\n      exposure:\n        include: health,info\n")
    write(tmp_path, "src/main/java/x/Sec.java",
          "class Sec {\n  SecurityFilterChain chain(HttpSecurity http) throws Exception {\n"
          "    return http.authorizeHttpRequests(a -> a.anyRequest().permitAll()).build();\n  }\n}\n")
    write(tmp_path, "src/main/java/x/Json.java",
          "class Json {\n  ObjectMapper m() {\n    ObjectMapper m = new ObjectMapper();\n    m.enableDefaultTyping();\n    return m;\n  }\n}\n")
    write(tmp_path, "src/main/java/x/Safe.java",
          "class Safe {\n  void s(ObjectMapper m) {\n    m.activateDefaultTyping(BasicPolymorphicTypeValidator.builder().allowIfBaseType(Base.class).build());\n  }\n}\n")
    write(tmp_path, "src/main/java/x/Xml.java", "class Xml {\n  Object read(String s) {\n    return new XStream().fromXML(s);\n  }\n}\n")
    f = sorted(x for x in found(tmp_path) if x[2].startswith("JAVA00") and x[2] != "JAVA001")
    assert f == [("src/main/java/x/Json.java", 4, "JAVA004"), ("src/main/java/x/Sec.java", 3, "JAVA003"),
                 ("src/main/java/x/Xml.java", 3, "JAVA004"),
                 ("src/main/resources/application.properties", 2, "JAVA002"),
                 ("src/main/resources/application.properties", 3, "JAVA002")]


def test_java_checks_are_linear_on_hostile_input(tmp_path):
    write(tmp_path, "src/main/java/x/H.java", "class H {\n" + "  public void m(@RequestParam String a) {\n" * 3000
          + "String s = \"" * 3000 + "\n}\n")
    write(tmp_path, "src/main/resources/application.yml", "exposure:\n" * 5000 + "  include: *\n")
    start = time.time()
    found(tmp_path)
    assert time.time() - start < 30


def test_custom_auth_interceptor_and_authority_checks(tmp_path):
    write(tmp_path, "src/main/java/x/AuthorizationInterceptor.java",
          "public class AuthorizationInterceptor implements HandlerInterceptor {\n"
          "  public boolean preHandle(HttpServletRequest r, HttpServletResponse s, Object h) { return check(r); }\n}\n")
    write(tmp_path, "src/main/java/x/Notes.java",
          "@RestController\npublic class Notes {\n  @PostMapping(\"/notes\")\n  public void create(@RequestBody Note n) { repo.save(n); }\n}\n")
    f = found(tmp_path)
    assert not [x for x in f if x[2] in ("JAVA001", "AUTH001")]


def test_has_authority_is_an_admin_role_check(tmp_path):
    write(tmp_path, "src/main/java/x/SecurityConfig.java",
          "@EnableWebSecurity\nclass SecurityConfig {\n  SecurityFilterChain c(HttpSecurity http) {\n"
          "    return http.authorizeHttpRequests(a -> a.anyRequest().authenticated()).build();\n  }\n}\n")
    write(tmp_path, "src/main/java/x/UserResource.java",
          "@RestController\n@RequestMapping(\"/api/admin\")\npublic class UserResource {\n"
          "  @DeleteMapping(\"/users/{login}\")\n"
          "  @PreAuthorize(\"hasAuthority(\\\"\" + AuthoritiesConstants.ADMIN + \"\\\")\")\n"
          "  public void delete(@PathVariable String login) { users.delete(login); }\n}\n")
    assert not [x for x in found(tmp_path) if x[2] == "AUTH002"]


def test_matchers_scoped_to_an_http_method(tmp_path):
    # the chain spans lines and scopes permitAll to GET: writes to the same paths still need a login
    write(tmp_path, "src/main/java/x/WebSecurityConfig.java",
          "@EnableWebSecurity\nclass WebSecurityConfig extends WebSecurityConfigurerAdapter {\n"
          "  protected void configure(HttpSecurity http) throws Exception {\n    http.authorizeRequests()\n"
          "        .antMatchers(HttpMethod.POST, \"/users\", \"/users/login\")\n        .permitAll()\n"
          "        .antMatchers(HttpMethod.GET, \"/articles/**\")\n        .permitAll()\n"
          "        .anyRequest()\n        .authenticated();\n  }\n}\n")
    write(tmp_path, "src/main/java/x/ArticleApi.java",
          "@RestController\n@RequestMapping(\"/articles/{slug}\")\npublic class ArticleApi {\n"
          "  @GetMapping\n  public Article get(@PathVariable String slug) { return repo.find(slug); }\n"
          "  @PutMapping\n  public Article update(@PathVariable String slug, @RequestBody Article a) { return repo.save(a); }\n"
          "  @DeleteMapping\n  public void delete(@PathVariable String slug) { repo.delete(slug); }\n}\n")
    from vibeaudit.files import Project
    from vibeaudit.jvm import JvmScanner
    got = {(r.path, r.methods[0]): r.has_auth for r in JvmScanner(Project(tmp_path), lambda f: None).run()}
    assert got[("/articles/{slug}", "GET")] is False
    assert got[("/articles/{slug}", "PUT")] is True and got[("/articles/{slug}", "DELETE")] is True
    assert not [x for x in found(tmp_path) if x[2] == "AUTH001"]


def test_java_ownership_checks_are_recognised(tmp_path):
    write(tmp_path, "src/main/java/x/SecurityConfig.java",
          "@EnableWebSecurity\nclass SecurityConfig {\n  SecurityFilterChain c(HttpSecurity http) {\n"
          "    return http.authorizeHttpRequests(a -> a.anyRequest().authenticated()).build();\n  }\n}\n")
    write(tmp_path, "src/main/java/x/ArticleApi.java",
          "@RestController\n@RequestMapping(\"/articles/{slug}\")\npublic class ArticleApi {\n"
          "  @PutMapping\n  public Article update(@PathVariable(\"slug\") String slug, @AuthenticationPrincipal User user, @RequestBody P p) {\n"
          "    Article a = repo.findBySlug(slug);\n    if (!AuthorizationService.canWriteArticle(user, a)) throw new NoAuthorizationException();\n"
          "    return repo.save(a.update(p));\n  }\n"
          "  @DeleteMapping\n  public void delete(@PathVariable(\"slug\") String slug) {\n    repo.delete(repo.findBySlug(slug));\n  }\n}\n")
    assert [x[1] for x in found(tmp_path) if x[2] == "AUTH003"] == [10]


def test_a_parsed_url_is_not_a_request(tmp_path):
    write(tmp_path, "src/main/java/x/S.java",
          "@RestController\npublic class S {\n  @GetMapping(\"/cb\")\n  public String cb(@RequestParam String redirectUrl) throws Exception {\n"
          "    String host = new URL(redirectUrl).getHost();\n"
          "    InputStream in = new URL(redirectUrl).openStream();\n    return host;\n  }\n}\n")
    assert [x[1] for x in found(tmp_path) if x[2] == "BE005"] == [6]
