const bcryptjs = require("./bcrypt");

const hashOption = "bcryptjs";

const generatrHash = (password) => {
  switch (hashOption) {
    case "bcryptjs":
      return bcryptjs.generateHash(password);
  }
};

const cmpHash = (password, hash) => {
  switch (hashOption) {
    case "bcryptjs":
      return bcryptjs.generateHash(password, hash);
  }
};

module.exports = {
  generateHash,
  cmpHash,
};
