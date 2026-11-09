const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const { exec } = require("child_process");
const User = require("./models/user");
const Note = require("./models/note");
const db = require("./db");
const adminRouter = require("./routes/admin");

const app = express(); // expect: CFG008
app.use(cors({ origin: true, credentials: true })); // expect: BE012
app.use(express.json());
app.use("/admin", adminRouter);

const JWT_SECRET = "supersecret123"; // expect: SEC004

function isAdmin(req) { // expect: AUTH008
  return true;
}

app.post("/api/login", async (req, res) => { // expect: AUTH010, BE018
  const user = await User.findOne({ email: req.body.email, password: req.body.password }); // expect: BE010
  if (!user) return res.status(401).json({ error: "invalid" });
  const token = jwt.sign({ id: user.id }, JWT_SECRET);
  res.json({ token });
});

app.post("/api/notes", async (req, res) => { // expect: AUTH001
  const note = await Note.create(req.body); // expect: BE009
  res.json(note);
});

app.get("/api/ping", (req, res) => {
  exec("ping -c 1 " + req.query.host, (err, out) => res.send(out)); // expect: BE002
});

app.get("/api/search", async (req, res) => {
  const q = req.query.q;
  const rows = await db.query(`SELECT * FROM items WHERE name = '${q}'`); // expect: BE001
  res.send(`<h1>Results for ${q}</h1><p>${rows.length}</p>`); // expect: FE001
});

app.get("/api/proxy", async (req, res) => {
  const r = await fetch(req.query.url); // expect: BE005
  res.send(await r.text());
});

app.get("/api/me", (req, res) => {
  try {
    res.json(jwt.verify(req.headers.authorization, JWT_SECRET));
  } catch (e) {} // expect: QA003
});

app.use((err, req, res, next) => {
  res.status(500).json({ error: err.message, stack: err.stack }); // expect: BE017
});

app.listen(3000);
