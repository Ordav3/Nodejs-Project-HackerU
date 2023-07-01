const mongoose = require("mongoose");
const minAllowEmpty = require("../../services/validatorAllowEmpty");

const userSchema = new mongoose.Schema({
  name: {
    first: {
      type: String,
      required: true,
      minlength: 2,
      maxlength: 256,
    },
    middle: {
      type: String,
      maxlength: 256,
      validate: {
        validator: minAllowEmpty(2),
        message: "should be empty or minimum",
      },
    },
    last: {
      type: String,
      required: true,
      minlength: 2,
      maxlength: 256,
    },
  },
  phone: {
    type: String,
    required: true,
    minlength: 9,
    maxlength: 14,
  },
  email: {
    type: String,
    required: true,
    minlength: 6,
    maxlength: 256,
    unique: true,
  },
  password: {
    type: String,
    required: true,
    minlength: 6,
    maxlength: 1024,
  },
  image: {
    url: {
      type: String,
      maxlength: 1024,
    },
    alt: { type: String, maxlength: 256 },
  },
  state: {
    type: String,
    maxlength: 256,
    validate: {
      validator: minAllowEmpty(2),
      message: "should be empty or minimum",
    },
  },
  address: {
    state: {
      type: String,
      required: true,
      maxlength: 256,
    },
    country: {
      type: String,
      required: true,
      minlength: 2,
      maxlength: 256,
    },
    city: {
      type: String,
      required: true,
      minlength: 2,
      maxlength: 256,
    },
    street: {
      type: String,
      required: true,
      minlength: 2,
      maxlength: 256,
    },
    houseNumber: {
      type: String,
      required: true,
      minlength: 1,
      maxlength: 256,
    },
    zip: {
      type: Number,
      maxlength: 99999999,
      validate: {
        validator: minAllowEmpty(1, "number"),
        message: "should be empty or minimum",
      },
    },
  },
  isBusiness: {
    type: Boolean,
    default: false,
    required: true,
  },
  createdAt: { type: Date, default: Date.now },
  isAdmin: { type: Boolean, default: false },
});

const User = mongoose.model("User", userSchema);

module.exports = User;
