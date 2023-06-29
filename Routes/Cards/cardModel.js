const mongoose = require("mongoose");
const minAllowEmpty = require("../../services/validatorAllowEmpty");

const cardSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
    minlength: 2,
    maxlength: 256,
  },
  subTitle: {
    type: String,
    required: true,
    minlength: 2,
    maxlength: 256,
  },
  description: {
    type: String,
    required: true,
    minlength: 2,
    maxlength: 1024,
  },
  state: {
    type: String,
    maxlength: 256,
    validate: {
      validator: minAllowEmpty(2),
      message: "should be empty or minimum",
    },
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
  zipCode: {
    type: Number,
    maxlength: 99999999,
    validate: {
      validator: minAllowEmpty(1, "number"),
      message: "should be empty or minimum",
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
  },
  web: {
    type: String,
    maxlength: 255,
    validate: {
      validator: minAllowEmpty(5, "string"),
      message: "should be empty or minimum",
    },
  },
  image: {
    url: {
      type: String,
      required: true,
      minlength: 6,
      maxlength: 1024,
    },
    alt: { type: String, required: true, minlength: 6, maxlength: 256 },
  },
  bizNumber: {
    type: String,
    minlength: 7,
    maxlength: 7,
    required: true,
  },
  likes: [String],
  createdAt: {
    type: Date,
    default: Date.now,
  },
  user_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
  },
});

const Card = mongoose.model("card", cardSchema);

exports.Card = Card;
