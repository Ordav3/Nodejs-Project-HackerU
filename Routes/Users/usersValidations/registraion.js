const Joi = require("joi");

function validateRegistration(user) {
  const schema = Joi.object({
    name: {
      first: Joi.string().min(2).max(256).required(),
      middle: Joi.string().min(2).max(256).allow(""),
      last: Joi.string().min(2).max(256).required(),
    },
    phone: Joi.string().min(9).max(14).required(),
    email: Joi.string()
      .min(6)
      .max(256)
      .required()
      .email({ tlds: { allow: false } }),
    password: Joi.string().min(6).max(1024).required(),
    image: {
      url: Joi.string().max(1024).allow(""),
      alt: Joi.string().max(256).allow(""),
    },
    address: {
      state: Joi.string().max(256).allow(""),
      country: Joi.string().min(2).max(256).required(),
      city: Joi.string().min(2).max(256).required(),
      street: Joi.string().min(2).max(256).required(),
      houseNumber: Joi.string().min(1).max(256).required(),
      zip: Joi.number().min(1).max(99999999).allow(null),
    },
    isBusiness: Joi.boolean(),
  });

  return schema.validate(user);
}

module.exports = validateRegistration;
