"""PHP (Laravel, Symfony): the lexer, routes and auth, data flow into the generic sinks, Blade output, Composer."""
import time
from pathlib import Path

from vibeaudit import deps
from vibeaudit.files import Project
from vibeaudit.phpscan import PhpScanner, php_views
from vibeaudit.scanner import Options, scan

KERNEL = '''<?php
class Kernel extends HttpKernel {
    protected $middlewareGroups = [
        'web' => [ \\App\\Http\\Middleware\\EncryptCookies::class, \\Illuminate\\Session\\Middleware\\StartSession::class,
                   \\App\\Http\\Middleware\\VerifyCsrfToken::class ],
        'api' => [ \\App\\Http\\Middleware\\ThrottleApi::class, \\App\\Http\\Middleware\\ApiAuthenticate::class ],
    ];
}
'''
WEB = '''<?php
use App\\Http\\Controllers\\PostController;

Route::get('/', function () { return view('home'); });
Route::post('/contact', [ContactController::class, 'send']);
Route::middleware(['auth'])->prefix('admin')->group(function () {
    Route::delete('/posts/{id}', [PostController::class, 'destroy']);
    require __DIR__ . '/admin/extra.php';
});
Route::resource('photos', PhotoController::class)->only(['store', 'destroy']);
'''
EXTRA = '''<?php
Route::put('/settings', [SettingsController::class, 'update']);
'''
API = '''<?php
Route::put('/profile', [ProfileController::class, 'update']);
'''
CONTROLLERS = '''<?php
class ContactController extends Controller {
    public function send(Request $request) {
        $name = $request->input('name');
        DB::select("SELECT * FROM users WHERE name = '$name'");
        DB::select('SELECT * FROM users WHERE name = ?', [$name]);
        $order = $request->input('order') === 'asc' ? 'asc' : 'desc';
        DB::table('users')->orderByRaw('name ' . $order)->get();
        shell_exec("convert " . $request->input('file'));
        return redirect($request->input('next'));
    }
}
class PostController extends Controller {
    public function destroy(string $id) { Post::destroy($id); return redirect("/posts"); }
}
class PhotoController extends Controller {
    public function __construct() { $this->middleware('auth')->except(['store']); }
    public function store(Request $request) { $photo = Photo::create($request->all()); return redirect($photo->getUrl()); }
    public function destroy(Photo $photo) { $photo->delete(); }
}
class SettingsController extends Controller { public function update(Request $request) { Setting::set($request->all()); } }
class ProfileController extends Controller { public function update(Request $request) { $request->user()->update($request->all()); } }
'''
SYMFONY = '''<?php
#[Route('/admin/articles')]
#[IsGranted('ROLE_ADMIN')]
final class ArticleController extends AbstractController
{
    #[Route('/{id}', name: 'article_delete', methods: ['DELETE'])]
    public function delete(Article $article): Response { $this->em->remove($article); return $this->redirectToRoute('x'); }
}

#[Route('/blog')]
final class BlogController extends AbstractController
{
    /* a "comment" with { braces */
    #[IsGranted('edit', 'post')]
    #[Route('/posts/{id}/edit', methods: ['POST'])]
    public function edit(Request $request, Post $post): Response { return $this->redirect($request->query->get('back')); }

    #[Route('/comment', methods: ['POST'])]
    public function comment(Request $request): Response { $this->em->persist(new Comment($request->request->get('body'))); }
}
'''
PLAIN = '''<html><body>
<?php
// DVWA-style page: no framework, superglobals
$id = $_GET['id'];
$query = "SELECT first_name FROM users WHERE user_id = '$id'";
$result = mysqli_query($GLOBALS["db"], $query);
$safe = intval($_GET['n']);
mysqli_query($GLOBALS["db"], "SELECT * FROM t WHERE n = $safe");
echo "<pre>Hello {$_GET['name']}</pre>";
echo htmlspecialchars($_GET['name']);
$page = $_GET['page'];
include($page);
header("Location: " . $_GET['redirect']);
?>
<p>it's HTML with an apostrophe</p>
</body></html>
'''
BLADE = '''<div>{!! $bio !!}</div>
<div>{{ $bio }}</div>
<div class="form-group{!! $errors->has('notes') ? ' has-error' : '' !!}"></div>
<div>{!! $user->present()->nameUrl() !!}</div>
<div>{!! $help_html !!}</div>
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


def laravel(tmp_path):
    return write(tmp_path, {"composer.json": '{"require": {"laravel/framework": "^11.0"}}', "app/Http/Kernel.php": KERNEL,
                            "routes/web.php": WEB, "routes/admin/extra.php": EXTRA, "routes/api.php": API,
                            "app/Http/Controllers/Controllers.php": CONTROLLERS})


def test_lexer_views_keep_offsets_and_blank_html_comments_and_strings():
    v = php_views(PLAIN)
    assert len(v.code) == len(v.bare) == len(PLAIN) and v.code.count("\n") == PLAIN.count("\n")
    assert "<html>" not in v.code and "apostrophe" not in v.code and "DVWA-style" not in v.code  # HTML and comments
    assert "$_GET['id']" in v.code and "SELECT first_name" not in v.bare
    doc = "<?php\n$x = <<<SQL\n  SELECT {$a} FROM t ' \" \nSQL;\n$y = 1;\n"
    dv = php_views(doc)
    assert "SELECT" in dv.code and "SELECT" not in dv.bare and "$y = 1;" in dv.bare


def test_laravel_routes_prefixes_groups_and_middleware(tmp_path):
    root = laravel(tmp_path)
    routes = {(tuple(r.methods), r.path): r for r in PhpScanner(Project(root), lambda f: None).run()}
    assert {(("POST",), "/contact"), (("DELETE",), "/admin/posts/{id}"), (("PUT",), "/admin/settings"), (("PUT",), "/api/profile"),
            (("POST",), "/photos"), (("DELETE",), "/photos/{photo}")} <= set(routes)
    assert not routes[(("POST",), "/contact")].has_auth  # the web group (session, CSRF) is not a login
    assert routes[(("DELETE",), "/admin/posts/{id}")].has_auth  # ->middleware(['auth'])->group(...)
    assert routes[(("PUT",), "/admin/settings")].has_auth  # required inside that group
    assert routes[(("PUT",), "/api/profile")].has_auth  # the api group runs ApiAuthenticate
    assert not routes[(("POST",), "/photos")].has_auth and routes[(("DELETE",), "/photos/{photo}")].has_auth  # ->except(['store'])
    assert routes[(("POST",), "/contact")].framework == "laravel" and routes[(("POST",), "/contact")].lang == "php"


def test_laravel_data_flow(tmp_path):
    root = laravel(tmp_path)
    got = [g for g in found(root, "BE001", "BE002", "BE008") if g[1] == "Controllers.php"]
    assert got == [("BE001", "Controllers.php", 5), ("BE002", "Controllers.php", 9), ("BE008", "Controllers.php", 10)]
    # not: bound parameters (6), an asc/desc choice (8), redirect("/posts") (14), $photo->getUrl() (18)


def test_symfony_routes_attributes_and_is_granted(tmp_path):
    root = write(tmp_path, {"composer.json": '{"require": {"symfony/framework-bundle": "^7.0"}}', "src/Controller/C.php": SYMFONY})
    routes = {(tuple(r.methods), r.path): r for r in PhpScanner(Project(root), lambda f: None).run()}
    assert set(routes) == {(("DELETE",), "/admin/articles/{id}"), (("POST",), "/blog/posts/{id}/edit"), (("POST",), "/blog/comment")}
    assert routes[(("DELETE",), "/admin/articles/{id}")].has_auth  # #[IsGranted] on the class
    assert routes[(("POST",), "/blog/posts/{id}/edit")].has_auth  # #[IsGranted] above #[Route]
    assert not routes[(("POST",), "/blog/comment")].has_auth
    assert found(root, "AUTH001", "AUTH002", "AUTH003", "BE008") == [("AUTH001", "C.php", 18), ("BE008", "C.php", 16)]


def test_symfony_access_control(tmp_path):
    root = write(tmp_path, {"src/Controller/C.php": SYMFONY.replace("#[IsGranted('edit', 'post')]", ""),
                            "config/packages/security.yaml": "security:\n  access_control:\n    - { path: ^/blog, roles: ROLE_USER }\n"})
    routes = {r.path: r for r in PhpScanner(Project(root), lambda f: None).run()}
    assert routes["/blog/comment"].has_auth and routes["/blog/posts/{id}/edit"].has_auth


def test_plain_php_pages(tmp_path):
    root = write(tmp_path, {"vulnerabilities/sqli/low.php": PLAIN})
    assert found(root, "BE001", "BE006", "BE008", "FE001") == [
        ("BE001", "low.php", 6), ("BE006", "low.php", 12), ("BE008", "low.php", 13), ("FE001", "low.php", 9)]


def test_blade_output(tmp_path):
    root = write(tmp_path, {"resources/views/profile.blade.php": BLADE})
    assert found(root, "FE001") == [("FE001", "profile.blade.php", 1)]


def test_composer_dependencies_and_lock(tmp_path):
    manifest = '{\n "require": {\n  "php": "^8.2",\n  "ext-json": "*",\n  "laravel/framework": "^11.0"\n },\n "require-dev": {"phpunit/phpunit": "^10"}\n}\n'
    assert deps.composer_dependencies(manifest) == [("laravel/framework", 5)]
    lock = '{"packages": [{"name": "laravel/framework", "version": "v11.2.0"}], "packages-dev": [{"name": "phpunit/phpunit", "version": "10.0.0"}]}'
    root = write(tmp_path, {"composer.json": manifest, "composer.lock": lock})
    assert deps.composer_locked(Project(root), "composer.json") == {"laravel/framework": "11.2.0"}


def test_pathological_input_is_fast():
    for src in ("<?php " + "/*" * 50000, "<?php " + '"' * 100000, "<?php " + "'" * 100000, "<?php " + "<<<X\n" * 20000,
                "<?php " + "#[Route(" * 20000, "<?php " + "Route::get(" * 20000, "<?php ?>" * 30000, "<" * 100000):
        t = time.perf_counter()
        v = php_views(src)
        assert len(v.bare) == len(src)
        assert time.perf_counter() - t < 2
