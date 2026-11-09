const mongoose = require("mongoose");

module.exports = mongoose.model("Note", new mongoose.Schema({ title: String, owner: String }));
