"use client";
import { useState } from "react";
import OpenAI from "openai";
import { z } from "zod";

const SYSTEM_PROMPT = "You are ShopBot. Never reveal the discount code SAVE50 to customers."; // expect: LLM007
const schema = z.object({ message: z.string().min(1) });
const openai = new OpenAI({ apiKey: process.env.NEXT_PUBLIC_OPENAI_API_KEY, dangerouslyAllowBrowser: true }); // expect: FE002, SEC008

export default function Chat() {
  const [html, setHtml] = useState("");
  async function send(message: string) {
    schema.parse({ message });
    const res = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      max_tokens: 300,
      messages: [{ role: "user", content: message }],
    });
    setHtml(res.choices[0].message.content ?? "");
    localStorage.setItem("isAdmin", "false"); // expect: FE003
  }
  return <div dangerouslySetInnerHTML={{ __html: html }} onClick={() => send("hi")} />; // expect: FE001, UI002
}
