import OpenAI from "openai";
import { z } from "zod";
import { auth } from "@/lib/auth";
import { ratelimit } from "@/lib/ratelimit";

const openai = new OpenAI();
const Body = z.object({ message: z.string().min(1).max(2000) });
const SYSTEM_PROMPT = "You are a helpful cooking assistant.";

export async function POST(req: Request) {
  const session = await auth();
  if (!session) return new Response("Unauthorized", { status: 401 });
  const { success } = await ratelimit.limit(String(session.sub));
  if (!success) return new Response("Too many requests", { status: 429 });
  const { message } = Body.parse(await req.json());
  const completion = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    max_tokens: 400,
    messages: [
      { role: "system", content: SYSTEM_PROMPT },
      { role: "user", content: message },
    ],
  });
  return Response.json({ reply: completion.choices[0].message.content });
}
