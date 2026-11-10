import { useState, useEffect } from "react";
import Link from "next/link";

export default function Home(props) {
  const [todos, setTodos] = useState([]);
  const [rows, setRows] = useState([]);
  const remove = (id) => setTodos(todos.filter((t) => t.id !== id));
  useEffect(() => { // expect: UI008
    const t = setInterval(tick, 1000);
  }, []);
  useEffect(() => { // expect: UI009
    fetch("/api/rows").then((r) => r.json()).then(setRows);
  }, []);
  return (
    <main>
      <img src="/hero.png" /> {/* expect: UI001 */}
      <input name="q" placeholder="Search" /> {/* expect: UI003 */}
      <button onClick={() => {}}>Save</button> {/* expect: UI004 */}
      {todos.map((t, i) => <li key={i}><input defaultValue={t.text} aria-label="todo" /></li>)} {/* expect: UI005 */}
      <button onClick={() => handleDelete(props.id)}>Delete</button> {/* expect: UI006 */}
      <p>Rendered at {new Date().toLocaleTimeString()}</p> {/* expect: UI007 */}
      <p>Lorem ipsum dolor sit amet</p> {/* expect: UI010 */}
      <Link href="/pricing">Pricing</Link> {/* expect: UI013 */}
      <p>{rows.length}</p>
    </main>
  );
}
