require("dotenv").config();
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const User = require("./model/user");
require("./config/database").connect();

const auth = require("./middleware/auth");

const app = express();

app.use(express.json({ limit: "50mb" }));

app.post("/register", async (req, res) => {
  try {
    // Get user input
    const { first_name, last_name, role, email, password } = req.body;

    // Validate user input
    if (!(email && password && first_name && last_name && role)) {
      res.status(400).send("All input is required");
    }

    // check if user already exist
    // Validate if user exist in our database
    const oldUser = await User.findOne({ email: email });

    if (oldUser) {
      return res.status(409).send("User Already Exist. Please Login");
    }

    //Encrypt user password
    encryptedPassword = await bcrypt.hash(password, 10);

    // Create user in our database
    const user = await User.create({
      first_name,
      last_name,
      email: email.toLowerCase(), // sanitize: convert email to lowercase
      password: encryptedPassword,
      role: role
    });

    // Create token
    const token = jwt.sign(
      { user_id: user._id, email: email, role: role},
      process.env.TOKEN_KEY,
      {
        expiresIn: "2h",
      }
    );
    // save user token
    user.token = token;

    // return new user
    res.status(201).json(user);
  } catch (err) {
    console.log(err);
  }
});

// LOGIN
app.post("/login", async (req, res) => {

    try {

        const { email, password } = req.body;

        if (!(email && password)) {
            res.status(400).send("All input is required");
        }
        // Validate if user exist in our database
        const user = await User.findOne({ email: email });

        if (user && (bcrypt.compare(password, user.password))) {
            // Create token
            const token = jwt.sign(
            { user_id: user._id, email: email, role: user.role },
            process.env.TOKEN_KEY,
            {
                expiresIn: "2h",
            }
            );

            // save user token
            user.token = token;

            // user
            return res.status(200).json(user);
        }
        return res.status(400).send("Invalid Credentials");

    } catch (err) {
      console.log(err);
    }
})

app.get("/welcome", auth, (req, res) => {
  res.status(200).send("Welcome 🙌 ");
});

module.exports = app;