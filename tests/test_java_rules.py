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
