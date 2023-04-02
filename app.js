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
    process.env.SECRET
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
app.post(
  "/getUserDetails",
  passport.authenticate("jwt", { session: false }),
  async function (req, res) {
    const { email } = req.body;
    const user = await User.findOne({ email: email });
    if (user) {
      res.status(200).json({ user: user });
    } else {
      console.log("User not found");
      res.status(404).json({ user: user });
    }
  }
);

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

app.patch(
  "/updateUser",
  passport.authenticate("jwt", { session: false }),
  async function (req, res) {
    const {
      email,
      about,
      profilePic,
      socials,
      interests,
      highestEducation,
      occupation,
    } = req.body;
    const user = await User.findOne({ email: email });
    if (user) {
      if (about) user.about = about;
      if (profilePic) user.profilePic = profilePic;
      if (socials) user.socials = socials;
      if (interests) user.interests = interests;
      if (highestEducation) user.highestEducation = highestEducation;
      if (occupation) user.occupation = occupation;

      await user.save();
      res.status(200).json({ user: user });
    } else {
      console.log("User not found");
      res.status(404).json({ user: user });
    }
  }
);

// get all followers
app.get(
  "/getFollowers",
  passport.authenticate("jwt", { session: false }),
  async function (req, res) {
    try {
      const { email } = req.body;
      const user = User.findOne({ email: email });
      if (user) {
        const followers = user.followers;
        res.status(200).json({ followers: followers });
      }
    } catch (err) {
      console.log("Error: ", err);
    }
  }
);

app.listen(port, () => console.log(`Example app listening on port ${port}!`));
