"use client";
import { useState } from "react";

export default function Chat() {
  const [reply, setReply] = useState("");
  async function send(message: string) {
    const res = await fetch("/api/chat", { method: "POST", body: JSON.stringify({ message }) });
    const data = await res.json();
    setReply(data.reply);
  }
  return <div onClick={() => send("hi")}>{reply}</div>;
}
