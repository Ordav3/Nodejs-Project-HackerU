const Joi = require("joi");

function validateEditIsBusiness(user) {
  const schema = Joi.object({
    isBusiness: Joi.boolean()
  });

  return schema.validate(user);
}

module.exports = validateEditIsBusiness;
