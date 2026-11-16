const express = require("express");
const notes = require("./routes/notes");

const app = express();
app.use(express.json());
app.use("/api/notes", notes);
app.listen(3000);
