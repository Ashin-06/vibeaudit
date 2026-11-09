const express = require("express");
const User = require("../models/user");

const router = express.Router();

router.delete("/users/:id", async (req, res) => { // expect: AUTH002
  await User.findByIdAndDelete(req.params.id);
  res.json({ ok: true });
});

module.exports = router;
