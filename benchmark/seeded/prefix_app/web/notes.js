export const list = () => fetch("/api/notes");
export const add = (n) => fetch("/api/notes", { method: "POST", body: JSON.stringify(n) });
export const remove = (id) => fetch(`/api/note/${id}`, { method: "DELETE" }); // expect: API001
