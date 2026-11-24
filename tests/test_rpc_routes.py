"""tRPC procedures, GraphQL resolvers and gRPC handlers are routes: AUTH001-003 apply to them."""
from vibeaudit.scanner import Options, scan


def write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def auth(root):
    res = scan(str(root), Options(offline=True, external="none"))
    return sorted((f.file, f.line, f.rule_id) for f in res.findings if f.rule_id in ("AUTH001", "AUTH002", "AUTH003"))


def test_trpc_public_and_protected_procedures(tmp_path):
    write(tmp_path, "src/server/trpc.ts",
          "import { initTRPC, TRPCError } from '@trpc/server';\n"
          "const t = initTRPC.create();\n"
          "export const publicProcedure = t.procedure;\n"
          "export const protectedProcedure = t.procedure.use(({ ctx, next }) => {\n"
          "  if (!ctx.session) throw new TRPCError({ code: 'UNAUTHORIZED' });\n  return next();\n});\n"
          "export const adminProcedure = protectedProcedure.use(({ ctx, next }) => {\n"
          "  if (ctx.session.user.role !== 'admin') throw new TRPCError({ code: 'FORBIDDEN' });\n  return next();\n});\n")
    write(tmp_path, "src/server/routers/post.ts",
          "import { publicProcedure, protectedProcedure } from '../trpc';\n"
          "export const postRouter = router({\n"
          "  list: publicProcedure.query(() => db.post.findMany()),\n"
          "  create: publicProcedure.input(z.object({ title: z.string() })).mutation(async ({ input }) => {\n"
          "    return db.post.create({ data: input });\n  }),\n"
          "  remove: protectedProcedure.input(z.object({ id: z.string() })).mutation(async ({ input }) => {\n"
          "    return db.post.delete({ where: { id: input.id } });\n  }),\n"
          "});\n")
    write(tmp_path, "src/server/routers/admin.ts",
          "export const adminRouter = router({\n"
          "  ban: adminProcedure.input(z.object({ id: z.string() })).mutation(({ input }) => db.user.update({ where: { id: input.id } })),\n"
          "  wipe: protectedProcedure.mutation(() => db.user.deleteMany()),\n"
          "});\n")
    assert auth(tmp_path) == [("src/server/routers/admin.ts", 3, "AUTH002"),
                              ("src/server/routers/post.ts", 4, "AUTH001"),
                              ("src/server/routers/post.ts", 7, "AUTH003")]


def test_graphql_resolver_maps(tmp_path):
    write(tmp_path, "src/resolvers.js",
          "const resolvers = {\n"
          "  Query: { posts: () => Post.find() },\n"
          "  Mutation: {\n"
          "    createPost: async (_, args) => Post.create(args),\n"
          "    deletePost: async (_, { id }, context) => {\n"
          "      if (!context.user) throw new Error('no');\n      return Post.deleteOne({ _id: id });\n    },\n"
          "    likePost: likeResolver,\n"
          "  },\n};\nmodule.exports = resolvers;\n")
    assert auth(tmp_path) == [("src/resolvers.js", 4, "AUTH001")]
    write(tmp_path, "src/permissions.js", "module.exports = shield({ Mutation: { createPost: isAuthenticated } });\n")
    assert auth(tmp_path) == []


def test_strawberry_and_graphene_mutations(tmp_path):
    write(tmp_path, "app/schema.py",
          "import strawberry\nimport graphene\n\n"
          "@strawberry.type\nclass Mutation:\n"
          "    @strawberry.mutation\n    def add_book(self, title: str) -> Book:\n        return Book.objects.create(title=title)\n\n"
          "    @strawberry.mutation(permission_classes=[IsAuthenticated])\n"
          "    def delete_book(self, id: int) -> bool:\n        Book.objects.filter(id=id).delete()\n        return True\n\n\n"
          "class CreateAuthor(graphene.Mutation):\n    class Arguments:\n        name = graphene.String()\n\n"
          "    def mutate(root, info, name):\n        return Author.objects.create(name=name)\n")
    assert auth(tmp_path) == [("app/schema.py", 7, "AUTH001"), ("app/schema.py", 16, "AUTH001")]


def test_grpc_handlers_and_auth_interceptors(tmp_path):
    write(tmp_path, "server/users.go",
          "package server\n\ntype userServer struct {\n\tpb.UnimplementedUserServiceServer\n}\n\n"
          "func (s *userServer) DeleteUser(ctx context.Context, req *pb.DeleteUserRequest) (*pb.Empty, error) {\n"
          "\treturn &pb.Empty{}, s.db.Delete(req.Id)\n}\n\n"
          "func (s *userServer) GetUser(ctx context.Context, req *pb.GetUserRequest) (*pb.User, error) {\n"
          "\treturn s.db.Get(req.Id)\n}\n")
    write(tmp_path, "svc/greeter.py",
          "class Greeter(pb2_grpc.GreeterServicer):\n"
          "    def RemoveGreeting(self, request, context):\n        db.greetings.delete(request.id)\n")
    write(tmp_path, "src/main/java/Svc.java",
          "class OrderService extends OrderServiceGrpc.OrderServiceImplBase {\n"
          "  @Override\n  public void deleteOrder(DeleteRequest req, StreamObserver<Empty> out) {\n"
          "    repo.deleteById(req.getId());\n  }\n}\n")
    assert auth(tmp_path) == [("server/users.go", 7, "AUTH001"), ("src/main/java/Svc.java", 3, "AUTH001"),
                              ("svc/greeter.py", 2, "AUTH001")]
    # an auth interceptor makes the Go handlers authenticated; deleting by a caller-supplied id still needs an owner check
    write(tmp_path, "cmd/main.go", "package main\n\nfunc main() {\n\tgrpc.NewServer(grpc.UnaryInterceptor(authInterceptor))\n}\n")
    assert auth(tmp_path) == [("server/users.go", 7, "AUTH003"), ("src/main/java/Svc.java", 3, "AUTH001"),
                              ("svc/greeter.py", 2, "AUTH001")]
