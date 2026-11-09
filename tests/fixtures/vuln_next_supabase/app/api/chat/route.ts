import OpenAI from "openai";

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

export async function POST(req: Request) { // expect: AUTH001, LLM004, BE018
  const { message } = await req.json();
  const completion = await openai.chat.completions.create({ // expect: LLM003
    model: "gpt-4o-mini",
    messages: [
      { role: "system", content: `You are a support bot. The customer says: ${message}` }, // expect: LLM001
      { role: "user", content: message },
    ],
  });
  const reply = completion.choices[0].message.content;
  return Response.json({ reply });
}
