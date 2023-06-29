const validateRegistration = require("./usersValidations/registraion");
const validateEditUser = require("./usersValidations/editUser");
const validateSignin = require("./usersValidations/signIn");
const {
  comparePassword,
  generateHashPassword,
} = require("../../services/bcrypt");
const { generateAuthToken } = require("../../services/token");
const _ = require("lodash");
const router = require("express").Router();
const User = require("./userModel");
const auth = require("../../middlewares/authorization");
const chalk = require("chalk");

router.post("/register", async (req, res) => {
  const { error } = validateRegistration(req.body);
  if (error) {
    console.log(chalk.redBright(error.details[0].message));
    return res.status(400).send(error.details[0].message);
  }

  let user = await User.findOne({ email: req.body.email });
  if (user) {
    console.log(chalk.redBright("Registration Error: User already registered"));
    return res.status(400).send("User already registered.");
  }
  user = new User({ ...req.body });
  // user = new User(
  //   _.pick(req.body, ["name", "email", "password", "biz", "cards"])
  // );

  user.password = generateHashPassword(user.password);
  await user.save();
  res.send(_.pick(user, ["_id", "name", "email"]));
});

router.post("/login", async (req, res) => {
  const { error } = validateSignin(req.body);
  if (error) {
    console.log(chalk.redBright(error.details[0].message));
    return res.status(400).send(error.details[0].message);
  }

  let user = await User.findOne({ email: req.body.email });
  if (!user) {
    console.log(chalk.redBright("Invalid email"));
    return res.status(400).send("Invalid email or password.");
  }

  const validPassword = comparePassword(req.body.password, user.password);
  if (!validPassword) {
    console.log(chalk.redBright("Invalid password"));
    return res.status(400).send("Invalid email or password.");
  }

  res.json({
    token: generateAuthToken(user),
  });
});

router.get("/getAllUsers", auth, async (req, res) => {
  try {
    console.log(req.user);
    if (!req.user || !req.user.isAdmin) {
      throw "you need to be admin!";
    }
    const users = await User.find().select(["-password", "-createdAt", "-__v"]);
    res.json({ users });
  } catch (err) {
    res.status(500).send(err);
  }
});

router.get("/userInfo", auth, (req, res) => {
  let user = req.user;

  User.findById(user._id)
    .select(["-password", "-createdAt", "-__v"])
    .then((user) => res.send(user))
    .catch((errorsFromMongoose) => res.status(500).send(errorsFromMongoose));
});

router.put("/userInfo", auth, async (req, res) => {
  try {
    const { error } = validateEditUser(req.body);
    if (error) {
      console.log(chalk.redBright(error.details[0].message));
      return res.status(400).send(error.details[0].message);
    }
    await User.findByIdAndUpdate(req.user._id, req.body);
    res.json({ msg: "Done" });
  } catch (err) {
    res.status(500).send(err);
  }
});

router.put("/userInfo/:id", auth, async (req, res) => {
  try {
    const { error } = validateEditUser(req.body);
    if (error) {
      console.log(chalk.redBright(error.details[0].message));
      return res.status(400).send(error.details[0].message);
    }
    if (!req.user || !req.user.isAdmin) {
      throw "you need to be admin!";
    }
    await User.findByIdAndUpdate(req.params.id, req.body);
    res.json({ msg: "Done" });
  } catch (err) {
    res.status(500).send(err);
  }
});

router.delete("/deleteUser/:id", auth, async (req, res) => {
  try {
    console.log(req.user);
    if (!req.user || !req.user.isAdmin) {
      throw "you need to be admin!";
    }
    await User.findByIdAndDelete(req.params.id);
    res.json({ msg: "Done" });
  } catch (err) {
    res.status(500).send(err);
  }
});

module.exports = router;
