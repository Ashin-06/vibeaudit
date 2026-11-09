import { createClient } from "@supabase/supabase-js";

const supabase = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);

export async function DELETE(req: Request) { // expect: AUTH002
  const { searchParams } = new URL(req.url);
  const id = searchParams.get("id");
  await supabase.from("profiles").delete().eq("id", id);
  return Response.json({ ok: true });
}
