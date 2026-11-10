export async function placeOrder(body: unknown) {
  return fetch("/api/orders", { method: "POST", body: JSON.stringify(body) });
}

export async function listOrders() {
  return fetch("/api/orders"); // expect: API002
}

export async function loadSettings() {
  return fetch("/api/settings"); // expect: API001
}
