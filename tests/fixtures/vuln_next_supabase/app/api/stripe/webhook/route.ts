export async function POST(req: Request) { // expect: AUTH004
  const event = await req.json();
  if (event.type === "checkout.session.completed") {
    await markPaid(event.data.object.id);
  }
  return new Response("ok");
}

async function markPaid(orderId: string) {
  return orderId;
}
