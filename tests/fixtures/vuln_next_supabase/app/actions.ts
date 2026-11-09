"use server";
import { db } from "@/lib/db";

export async function deletePost(id: string) { // expect: AUTH001
  await db.post.delete({ where: { id } });
}
