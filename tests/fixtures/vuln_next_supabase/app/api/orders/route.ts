import { PrismaClient } from "@prisma/client";
import { auth } from "@/lib/auth";

export async function POST(req: Request) { // expect: DATA010
  const session = await auth();
  if (!session) return new Response("Unauthorized", { status: 401 });
  const prisma = new PrismaClient(); // expect: DATA008
  const { items } = await req.json();
  for (const item of items) {
    await prisma.product.update({ where: { id: item.id }, data: { stock: { decrement: 1 } } }); // expect: DATA001
  }
  await prisma.order.create({ data: { userId: session.userId, total: 10 } });
  const user = await prisma.user.findUnique({ where: { id: session.userId } }); // expect: DATA002
  return Response.json({ user, plan: process.env.STRIPE_PRICE_ID }); // expect: DATA007
}
