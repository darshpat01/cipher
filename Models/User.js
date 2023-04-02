const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const UserSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
  },
  password: {
    type: String,
    required: true,
  },
  interests: {
    type: Array,
    Enum: [
      "app development",
      "web development",
      "game development",
      "data structures",
      "programming",
      "machine learning",
    ],
    required: false,
  },
  followers: {
    type: Array,
    required: false,
  },
  about: {
    type: String,
    required: false,
  },
  highestEducation: {
    type: String,
    required: false,
  },
  occupation: {
    type: String,
    required: false,
  },
  socials: {
    type: Object,
    required: false,
  },
  profilePicture: {
    type: String,
    required: false,
  },
});

UserSchema.methods.encryptPassword = async (password) => {
  const salt = await bcrypt.genSalt(10);
  const hash = bcrypt.hash(password, salt);
  return hash;
};

UserSchema.methods.isValidPassword = async function (password) {
  const user = this;
  const compare = await bcrypt.compare(password, user.password);
  return compare;
};

module.exports = mongoose.model("User", UserSchema);
