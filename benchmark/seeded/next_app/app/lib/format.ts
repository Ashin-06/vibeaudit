export function formatDate(iso: string): string { // expect: QA011
  const d = new Date(iso);
  const day = d.toISOString().slice(0, 10);
  return day;
}
