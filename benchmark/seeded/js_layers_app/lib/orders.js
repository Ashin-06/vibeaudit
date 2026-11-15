import { exec } from "child_process";

export async function orderByRef(pool, ref) {
  return pool.query(`SELECT * FROM orders WHERE ref = '${ref}'`); // expect: BE001
}

export function exportOrders(format) {
  return run(format);
}

function run(format) {
  exec("export-orders --format " + format); // expect: BE002
}

export async function orderById(pool, id) {
  return pool.query("SELECT * FROM orders WHERE id = $1", [id]);
}
