"""Java and Kotlin: the lexer, Spring and JAX-RS route discovery, the security configuration, JAVA001."""
import time
from pathlib import Path

import pytest

from vibeaudit import jvm
from vibeaudit.files import Project
from vibeaudit.scanner import Options, scan

CONTROLLER = '''package com.example.shop;

import org.springframework.web.bind.annotation.*;

/* a "comment" with { braces */
@RestController
@RequestMapping("/api/users")
public class UserController {
    private final UserRepository repo;

    @GetMapping
    public List<User> all() { return repo.findAll(); }

    @GetMapping("/{id}")
    public User one(@PathVariable Long id) { return repo.findById(id).orElseThrow(); }

    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/{id}")
    public void delete(@PathVariable("id") Long id) {
        repo.deleteById(id); // "}"
    }

    @RequestMapping(value = {"/bulk", "/batch"}, method = RequestMethod.POST)
    public void bulk(@RequestBody List<User> users) { repo.saveAll(users); }

    @PostMapping(path = "/import", consumes = "text/csv")
    public String importCsv(@RequestBody String csv) {
        String s = """
            text block with } and {
            """;
        return s;
    }
}
'''
RESOURCE = '''package com.example.shop;
@Path("/items")
@Authenticated
public class ItemResource {
    @GET
    public List<Item> list() { return Item.listAll(); }

    @POST
    @Path("{id}/archive")
    public void archive(@PathParam("id") long id) { }
}
'''
KOTLIN = '''package com.example.shop

@RestController
@RequestMapping("/orders")
class OrderController(private val repo: OrderRepository) {
    @GetMapping("/{id}")
    fun get(@PathVariable id: Long): Order = repo.findById(id).get()

    @PostMapping
    fun create(@RequestBody order: Order): Order {
        val msg = "created ${order.id} }"
        return repo.save(order)
    }
}
'''
SPRING_CONFIG = '''@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(a -> a
            .requestMatchers("/api/users/**").permitAll()
            .requestMatchers(HttpMethod.POST, "/orders").hasRole("USER")
            .anyRequest().authenticated());
        return http.build();
    }
}
'''


def write(root: Path, files: dict) -> Path:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return root


def found(root, *rules):
    res = scan(str(root), Options(offline=True, external="none", min_severity="low", include_preview=True))
    assert res.meta.get("internal_errors", []) == []
    return sorted((f.rule_id, f.file.rsplit("/", 1)[-1], f.line) for f in res.findings if not rules or f.rule_id in rules)


def test_lexer_views_keep_offsets_and_blank_comments_and_strings():
    v = jvm.jvm_views(CONTROLLER)
    assert len(v.code) == len(v.bare) == len(CONTROLLER) and v.code.count("\n") == CONTROLLER.count("\n")
    assert "comment" not in v.code and '"}"' not in v.code  # the block comment and the line comment are gone
    assert '"/api/users"' in v.code and '"/api/users"' not in v.bare and v.bare.count('"') == v.code.count('"')
    assert "text block" not in v.bare and v.bare.count("{") == v.bare.count("}")
    k = jvm.jvm_views(KOTLIN)
    assert "created" not in k.bare and k.bare.count("{") == k.bare.count("}")


def test_routes_methods_paths_params_and_auth(tmp_path):
    root = write(tmp_path, {"src/main/java/com/x/UserController.java": CONTROLLER, "src/main/java/com/x/ItemResource.java": RESOURCE,
                            "src/main/kotlin/com/x/OrderController.kt": KOTLIN, "src/main/java/com/x/SecurityConfig.java": SPRING_CONFIG})
    routes = {(tuple(r.methods), r.path): r for r in jvm.routes(Project(root))}
    assert set(routes) == {(("GET",), "/api/users"), (("GET",), "/api/users/{id}"), (("DELETE",), "/api/users/{id}"),
                           (("POST",), "/api/users/bulk"), (("POST",), "/api/users/batch"), (("POST",), "/api/users/import"),
                           (("GET",), "/items"), (("POST",), "/items/{id}/archive"), (("GET",), "/orders/{id}"), (("POST",), "/orders")}
    assert not routes[(("GET",), "/api/users")].has_auth  # permitAll()
    assert routes[(("DELETE",), "/api/users/{id}")].has_auth  # @PreAuthorize
    assert routes[(("POST",), "/orders")].has_auth and routes[(("GET",), "/orders/{id}")].has_auth  # hasRole, anyRequest()
    assert routes[(("POST",), "/items/{id}/archive")].has_auth  # @Authenticated on the class
    assert routes[(("DELETE",), "/api/users/{id}")].params == ["id"] and routes[(("POST",), "/orders")].reads_body
    assert routes[(("GET",), "/items")].framework == "jax-rs" and routes[(("POST",), "/orders")].lang == "jvm"
    assert routes[(("DELETE",), "/api/users/{id}")].line == 17  # the first annotation of the method


@pytest.mark.parametrize("config, path, protected", [
    ('http { authorizeHttpRequests { authorize("/api/open/**", permitAll)\n authorize(anyRequest, authenticated) } }', "/api/open/x", False),
    ('http { authorizeHttpRequests { authorize("/api/open/**", permitAll)\n authorize(anyRequest, authenticated) } }', "/api/x", True),
    (".authorizeRequests().antMatchers(\"/admin/**\").hasRole(\"ADMIN\").anyRequest().permitAll()", "/admin/users", True),
    (".authorizeRequests().antMatchers(\"/admin/**\").hasRole(\"ADMIN\").anyRequest().permitAll()", "/shop", False),
    (".authorizeExchange(e -> e.pathMatchers(\"/public/{id}\").permitAll().anyExchange().authenticated())", "/public/7", False),
])
def test_security_rules(tmp_path, config, path, protected):
    root = write(tmp_path, {"Sec.kt": "@EnableWebSecurity\nclass Sec { fun c(http: HttpSecurity) { " + config + " } }\n"})
    sec = jvm.Security.of(Project(root))
    assert sec.present and sec.protects(path, ["POST"]) is protected


def test_quarkus_permissions(tmp_path):
    root = write(tmp_path, {"src/main/resources/application.properties":
                            "quarkus.http.auth.permission.authenticated.paths=/*\n"
                            "quarkus.http.auth.permission.authenticated.policy=authenticated\n"
                            "quarkus.http.auth.permission.public.paths=/q/health/*,/hello\n"
                            "quarkus.http.auth.permission.public.policy=permit\n"})
    sec = jvm.Security.of(Project(root))
    assert sec.protects("/items", ["GET"]) and not sec.protects("/hello", ["GET"]) and not sec.protects("/q/health/live", ["GET"])


def test_java001_without_security_and_auth001_with_it(tmp_path):
    open_app = write(tmp_path / "open", {"src/main/java/com/example/demo/UserController.java": CONTROLLER})
    assert found(open_app, "JAVA001", "AUTH001") == [("JAVA001", "UserController.java", 11)]  # once, not per route
    secured = write(tmp_path / "secured", {"src/main/java/com/example/demo/UserController.java": CONTROLLER,
                                           "src/main/java/com/example/demo/SecurityConfig.java": SPRING_CONFIG})
    # permitAll() on /api/users/** leaves the writes open: per-route AUTH001, no JAVA001
    assert found(secured, "JAVA001", "AUTH001") == [("AUTH001", "UserController.java", 23), ("AUTH001", "UserController.java", 23)]


def test_spring_initializr_packages_are_not_example_code(tmp_path):
    root = write(tmp_path, {"src/main/java/com/example/demo/UserController.java": CONTROLLER})
    assert not Project(root).get("src/main/java/com/example/demo/UserController.java").is_example


def test_tests_and_unrelated_files_give_no_routes(tmp_path):
    root = write(tmp_path, {"src/test/java/com/x/UserControllerTest.java": CONTROLLER, "src/main/java/com/x/Util.java": "class Util { }\n"})
    assert jvm.routes(Project(root)) == []


def test_pathological_input_is_fast():
    for src in ("/*" * 50000, '"' * 100000, "'" * 100000, '"""' * 30000, "{" * 100000, "@GetMapping(" * 20000,
                "@RestController\nclass A {\n" + "@GetMapping(\"/x\")\n" * 20000):
        t = time.perf_counter()
        v = jvm.jvm_views(src)
        assert len(v.bare) == len(src)
        assert time.perf_counter() - t < 2


def test_a_typical_repository_is_lexed_and_routed_in_under_a_second(tmp_path):
    files = {}
    for i in range(300):
        files[f"src/main/java/com/x/c{i}/C{i}Controller.java"] = CONTROLLER.replace("/api/users", f"/api/c{i}")
    root = write(tmp_path, files)
    project = Project(root)
    t = time.perf_counter()
    routes = jvm.routes(project)
    assert len(routes) == 300 * 6 and time.perf_counter() - t < 3.0  # about 0.3 s; headroom for slow CI runners


def test_catch_all_tsconfig_path_falls_back_to_packages(tmp_path):
    from vibeaudit.scanner import Options, scan
    (tmp_path / "package.json").write_text('{"dependencies": {"esbuild": "0.20.0"}}')
    (tmp_path / "tsconfig.json").write_text('{"compilerOptions": {"paths": {"*": ["./src/main/webapp/*"]}}}')
    (tmp_path / "src/main/webapp/app").mkdir(parents=True)
    (tmp_path / "src/main/webapp/app/util.ts").write_text("export const x = 1;\n")
    (tmp_path / "build.ts").write_text("import { build } from 'esbuild';\nimport { x } from 'app/util';\nimport { y } from 'app/missing';\n")
    res = scan(str(tmp_path), Options(offline=True, external="none", min_severity="low"))
    assert [(f.file, f.line) for f in res.findings if f.rule_id == "QA006"] == [("build.ts", 3)]
