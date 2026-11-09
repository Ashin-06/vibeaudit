import { cookies } from "next/headers";
import { jwtVerify } from "jose";

export async function auth() {
  const token = cookies().get("session")?.value;
  if (!token) return null;
  const secret = new TextEncoder().encode(process.env.SESSION_SECRET);
  const { payload } = await jwtVerify(token, secret, { algorithms: ["HS256"] });
  return payload;
}
