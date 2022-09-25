const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  first_name: { type: String, default: null },
  last_name: { type: String, default: null },
  email: { type: String, unique: true },
  password: { type: String },
  token: { type: String },
  role: { type: String } //"0" - admin, "1" - normal user
});

module.exports = mongoose.model("user", userSchema);