export function formatDate(iso: string): string {
  const d = new Date(iso);
  const day = d.toISOString().slice(0, 10);
  return day;
}
