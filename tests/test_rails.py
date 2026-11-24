"""Ruby on Rails: routes and before_action auth (AUTH001-003), Brakeman-style sinks and raw ERB output."""
from vibeaudit.files import Project
from vibeaudit.rubyscan import RubyScanner
from vibeaudit.scanner import Options, scan


def write(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return root


ROUTES = """Rails.application.routes.draw do
  # get 'commented', to: 'posts#index'
  resources :posts, only: [:index, :show, :create, :update, :destroy]
  resources :comments, only: [:create]
  namespace :admin do
    resources :users, only: [:destroy]
  end
  post 'search', to: 'search#run'
  get 'go', to: 'search#go'
end
"""
APP = """class ApplicationController < ActionController::Base
  before_action :authenticate_user!
end
"""
POSTS = """class PostsController < ApplicationController
  skip_before_action :authenticate_user!, only: [:index, :show]

  def index
    @posts = Post.order(params[:sort])
  end

  def show
    @post = Post.find(params[:id])
  end

  def create
    @post = current_user.posts.new(post_params)
    @post.save
  end

  def update
    @post = Post.find(params[:id])
    @post.update(post_params)
  end

  def destroy
    current_user.posts.find(params[:id]).destroy
  end

  private

  def post_params
    params.require(:post).permit(:title, :body, :admin)
  end
end
"""
COMMENTS = """class CommentsController < ActionController::Base
  def create
    Comment.create(params.permit!)
  end
end
"""
ADMIN_USERS = """module Admin
  class UsersController < ApplicationController
    def destroy
      User.find(params[:id]).destroy
    end
  end
end
"""
SEARCH = """class SearchController < ActionController::Base
  def run
    q = params[:q]
    @results = Post.where("title LIKE '%#{q}%'")
    safe = Post.where("id = ?", params[:id])
    `grep #{q} /tmp/index`
    system("convert", params[:file])
    send_file params[:path]
    params[:klass].constantize
  end

  def go
    redirect_to params[:next]
  end
end
"""
VIEW = """<h1><%= @post.title %></h1>
<div><%== @post.body %></div>
<p><%= raw t('welcome') %></p>
<p><%= params[:msg].html_safe %></p>
"""


def found(root):
    res = scan(str(root), Options(offline=True, external="none", include_preview=True))
    return sorted((f.rule_id, f.file.rsplit("/", 1)[-1], f.line) for f in res.findings
                  if f.rule_id.startswith(("AUTH00", "BE0", "FE001")))


def project(tmp_path):
    return write(tmp_path, {"config/routes.rb": ROUTES, "app/controllers/application_controller.rb": APP,
                            "app/controllers/posts_controller.rb": POSTS,
                            "app/controllers/comments_controller.rb": COMMENTS,
                            "app/controllers/admin/users_controller.rb": ADMIN_USERS,
                            "app/controllers/search_controller.rb": SEARCH,
                            "app/views/posts/show.html.erb": VIEW})


def test_routes_and_filters(tmp_path):
    routes = {(r.methods[0], r.path): r for r in RubyScanner(Project(project(tmp_path)), lambda f: None).run()}
    assert set(routes) == {("GET", "/posts"), ("GET", "/posts/:id"), ("POST", "/posts"), ("PATCH", "/posts/:id"),
                           ("DELETE", "/posts/:id"), ("POST", "/comments"), ("DELETE", "/admin/users/:id"),
                           ("POST", "/search"), ("GET", "/go")}
    assert not routes[("GET", "/posts")].has_auth  # skipped for index and show
    assert routes[("POST", "/posts")].has_auth and routes[("DELETE", "/admin/users/:id")].has_auth
    assert not routes[("POST", "/comments")].has_auth  # does not inherit ApplicationController


def test_rails_findings(tmp_path):
    assert found(project(tmp_path)) == [
        ("AUTH001", "comments_controller.rb", 2),          # anonymous create
        ("AUTH003", "posts_controller.rb", 17),            # update finds any post by id
        ("AUTH003", "users_controller.rb", 3),             # no roles in the project: AUTH003, not AUTH002
        ("BE001", "posts_controller.rb", 5),               # order(params[:sort])
        ("BE001", "search_controller.rb", 4),              # interpolated where
        ("BE002", "search_controller.rb", 6),              # backticks; the array-form system() is not reported
        ("BE003", "search_controller.rb", 9),              # constantize
        ("BE006", "search_controller.rb", 8),
        ("BE008", "search_controller.rb", 13),
        ("BE009", "comments_controller.rb", 3),            # permit!
        ("BE009", "posts_controller.rb", 29),              # permit(:admin)
        ("FE001", "show.html.erb", 2),                     # <%== @post.body %>
        ("FE001", "show.html.erb", 4),                     # params html_safe; raw t(...) is fine
    ]


def test_rails7_raises_on_open_redirects(tmp_path):
    root = project(tmp_path)
    write(root, {"config/application.rb": "module App\n  class Application < Rails::Application\n"
                                          "    config.load_defaults 7.1\n  end\nend\n"})
    assert ("BE008", "search_controller.rb", 13) not in found(root)


def test_css_urls_served_by_the_rails_asset_pipeline(tmp_path):
    # theodinproject: url('/icons/link.svg') with the file in app/assets/images/icons (Propshaft)
    write(tmp_path, {"public/robots.txt": "", "app/assets/images/icons/link.svg": "<svg/>",
                     "app/assets/stylesheets/a.css": "a::before { mask-image: url('/icons/link.svg'); }\n"
                                                     "b::before { mask-image: url('/icons/gone.svg'); }\n"})
    res = scan(str(tmp_path), Options(offline=True, external="none", include_preview=True))
    assert [(f.file, f.line) for f in res.findings if f.rule_id == "UI017"] == [("app/assets/stylesheets/a.css", 2)]


def test_rails_tuned_causes(tmp_path):
    # lobsters: Rack::Attack rate limiting, finders and helpers do not carry taint, ownership predicates;
    # rails-realworld: a commented-out devise secret_key
    write(tmp_path, {"Gemfile": 'gem "rack-attack"\n', "config/routes.rb": "Rails.application.routes.draw do\n"
                     "  post 'login', to: 'login#login'\n  resources :stories, only: [:destroy]\nend\n",
                     "app/controllers/login_controller.rb": "class LoginController < ActionController::Base\n"
                     "  def login\n    User.find_by(email: params[:email]).authenticate(params[:password])\n  end\nend\n",
                     "app/controllers/stories_controller.rb": "class StoriesController < ActionController::Base\n"
                     "  before_action :require_logged_in_user\n  def destroy\n    @story = Story.find(params[:id])\n"
                     "    return head(:forbidden) unless @story.is_editable_by_user?(@user)\n    @story.destroy\n  end\n"
                     "  def show\n    short_id = params[:short_id]\n    story = Story.where(short_id: short_id).first!\n"
                     "    image = StoryImage.new(story)\n    send_file image.path, type: \"image/png\"\n  end\nend\n",
                     "config/initializers/devise.rb": "Devise.setup do |config|\n"
                     "  # config.secret_key = 'b8008800973c064ef11a8e1a7477c983f7526dc8e44e45b7713c1e92ad8cb1095e1b'\nend\n"})
    assert [f for f in found(tmp_path) if not f[0].startswith("AUTH001")] == []
    res = scan(str(tmp_path), Options(offline=True, external="none", include_preview=True))
    assert not [f for f in res.findings if f.rule_id in ("AUTH010", "SEC004", "SEC003")]


CONCERN = """module Authentication
  extend ActiveSupport::Concern

  included do
    before_action :require_authentication
  end

  class_methods do
    def require_unauthenticated_access(**options)
      allow_unauthenticated_access **options
      before_action :redirect_signed_in_user_to_root, **options
    end

    def allow_unauthenticated_access(**options)
      skip_before_action :require_authentication, **options
      before_action :resume_authentication, **options
    end
  end
end
"""


def test_authentication_concern_and_its_macros(tmp_path):
    # writebook (the Rails 8 generator's pattern): filters added in `included do`, skipped through class macros
    write(tmp_path, {
        "config/routes.rb": "Rails.application.routes.draw do\n  resources :books, only: [:create, :destroy]\n"
                            "  resource :session, only: [:create]\n  resources :users, only: [:create]\nend\n",
        "app/controllers/concerns/authentication.rb": CONCERN,
        "app/controllers/application_controller.rb": "class ApplicationController < ActionController::Base\n"
                                                     "  include Authentication\nend\n",
        "app/controllers/books_controller.rb": "class BooksController < ApplicationController\n"
                                               "  allow_unauthenticated_access only: :destroy\n"
                                               "  def create\n    Book.create!(book_params)\n  end\n"
                                               "  def destroy\n    Book.find(params[:id]).destroy\n  end\nend\n",
        "app/controllers/sessions_controller.rb": "class SessionsController < ApplicationController\n"
                                                  "  require_unauthenticated_access\n"
                                                  "  def create\n    Session.create!(user: User.first)\n  end\nend\n",
        "app/controllers/users_controller.rb": "class UsersController < ApplicationController\n"
                                               "  def create\n    User.create!(user_params)\n  end\nend\n"})
    routes = {(r.methods[0], r.path): r.has_auth for r in RubyScanner(Project(tmp_path), lambda f: None).run()}
    assert routes == {("POST", "/books"): True, ("DELETE", "/books/:id"): False, ("POST", "/session"): False,
                      ("POST", "/users"): True}


def test_include_list_continued_on_the_next_line(tmp_path):
    test_authentication_concern_and_its_macros(tmp_path)
    write(tmp_path, {"app/controllers/application_controller.rb": "class ApplicationController < ActionController::Base\n"
                     "  include Localize, Authentication,\n          Notifiable\nend\n"})
    routes = {(r.methods[0], r.path): r.has_auth for r in RubyScanner(Project(tmp_path), lambda f: None).run()}
    assert routes[("POST", "/books")] and not routes[("DELETE", "/books/:id")]
