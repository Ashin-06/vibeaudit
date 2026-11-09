import { auth } from "@/lib/auth";
import { db } from "@/lib/db";

export async function PATCH(req: Request, { params }: { params: { id: string } }) { // expect: AUTH003
  const session = await auth();
  if (!session) return new Response("Unauthorized", { status: 401 });
  const body = await req.json();
  await db.profile.update({ where: { id: params.id }, data: body }); // expect: BE009
  return Response.json({ ok: true });
}
