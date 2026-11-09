export async function auth() {
  return readSessionCookie();
}

function readSessionCookie(): { userId: string } | null {
  return null;
}
