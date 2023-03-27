const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const mongoose = require("mongoose");
const passport = require("passport");
const User = require("./Models/User");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());

require("./passport");

const port = 3009;

genToken = (user) => {
  return jwt.sign(
    {
      iss: "Darshan",
      sub: user.id,
      iat: new Date().getTime(),
      exp: new Date().setDate(new Date().getDate() + 1),
    },
    process.env.SECRET,
    { expiresIn: "1d" }
  );
};

app.use(bodyParser.json());

if (process.env.NODE_ENV !== "production") {
  require("dotenv/config");
}

mongoose.connect(process.env.DB_CONNECTION, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});
const db = mongoose.connection;
db.on("error", console.error.bind(console, "connection error"));
db.once("open", () => {
  console.log("Database connected");
});

// ROUTES

app.post("/register", async function (req, res) {
  const { name, email, password } = req.body;

  //Check If User Exists
  let foundUser = await User.findOne({ email });
  if (foundUser) {
    return res.status(403).json({ error: "Email is already in use" });
  }

  const newUser = new User({ name, email, password });
  //   encrypt password
  newUser.password = await newUser.encryptPassword(password);

  await newUser.save();
  // Generate JWT token
  const token = genToken(newUser);
  res.status(200).json({ token, user: newUser });
});

app.post("/login", async function (req, res) {
  const { email, password } = req.body;

  //Check If User Exists
  let foundUser = await User.findOne({ email });
  if (!foundUser) {
    return res.status(403).json({ error: "Invalid Credentials" });
  }

  // Check if password is correct
  const isMatch = await foundUser.isValidPassword(password);
  if (!isMatch) {
    return res.status(403).json({ error: "Invalid Credentials" });
  }

  // Generate JWT token
  const token = genToken(foundUser);
  res.status(200).json({ token, user: foundUser });
});

// change password route
app.post("/changePassword", async function (req, res) {
  try {
    const { email, password, newPassword } = req.body;
    const user = await User.findOne({ email: email });
    if (user) {
      const isMatch = await user.isValidPassword(password);
      if (!isMatch) {
        return res.status(403).json({ error: "Invalid Credentials" });
      }
      user.password = await user.encryptPassword(newPassword);
      await user.save();
      const token = genToken(user);
      res
        .status(200)
        .json({ token, user: user, message: "Password changed successfully" });
    }
  } catch (err) {
    console.log("Error: ", err);
  }
});

app.get(
  "/secret",
  passport.authenticate("jwt", { session: false }),
  (req, res, next) => {
    res.json("Secret Data");
  }
);

app.post(
  "/updateUser",
  passport.authenticate("jwt", { session: false }),
  async function (req, res) {
    try {
      const { name, email, interests, followers } = req.body;
      const user = await User.findOne({ email: email });
      if (user) {
        user.name = name;
        user.interests = interests;
        user.followers = followers;
        await user.save();
        const token = genToken(user);
        res
          .status(200)
          .json({ token, user: user, message: "User details updated" });
      }
    } catch (err) {
      console.log("Error: ", err);
    }
  }
);

app.listen(port, () => console.log(`Example app listening on port ${port}!`));
