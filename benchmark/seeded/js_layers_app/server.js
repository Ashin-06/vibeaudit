import express from "express";
import OpenAI from "openai";
import { orderByRef, orderById, exportOrders as exportAll } from "./lib/orders";

const app = express();
const client = new OpenAI();

function summarise(text) {
  return eval(text); // expect: LLM002
}

app.get("/orders/:ref", async (req, res) => {
  await orderByRef(app.pool, req.params.ref);
  await orderById(app.pool, Number(req.params.ref));
  res.send("ok");
});

app.post("/export", (req, res) => {
  exportAll(req.body.format);
  res.send("ok");
});

app.post("/summary", async (req, res) => {
  const out = await client.chat.completions.create({ model: "gpt-4o-mini", max_tokens: 50, messages: [] });
  summarise(out.choices[0].message.content);
  res.send("ok");
});
