const jwt = require("jsonwebtoken");
const config = require("config");

function generateAuthToken(user) {
  const token = jwt.sign(
    { _id: user._id, biz: user.isBusiness, isAdmin: user.isAdmin },
    config.get("jwt")
  );
  return token;
}

function verifyToken(tokenFromUSer) {
  try {
    const userData = jwt.verify(tokenFromUSer, config.get("jwt"));

    return userData;
  } catch (error) {
    return null;
  }
}

module.exports = { generateAuthToken, verifyToken };
