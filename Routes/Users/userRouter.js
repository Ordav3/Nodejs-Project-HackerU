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

//--1-
router.post("", async (req, res) => {
  console.log(chalk.blue("Route: User Registration"));

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

  user.password = generateHashPassword(user.password);
  await user.save();
  res.send(_.pick(user, ["_id", "name", "email"]));
});

//--2--
router.post("/login", async (req, res) => {
  console.log(chalk.blue("Route: User Login"));

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

//--3--
router.get("", auth, async (req, res) => {
  console.log(chalk.blue("Route: Get All Users (Admin only)"));

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

//--4--
router.get("/:id", auth, (req, res) => {
  console.log(chalk.blue("Route: Get User by ID"));

  let user = req.user;
  User.findById(user._id)
    .select(["-password", "-createdAt", "-__v"])
    .then((user) => res.send(user))
    .catch((errorsFromMongoose) => res.status(500).send(errorsFromMongoose));
});

//--5--
router.put("/:id", auth, async (req, res) => {
  console.log(chalk.blue("Route: Update User by ID"));

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

//--6--
router.patch("/:id", auth, async (req, res) => {
  console.log(chalk.blue("Route: Partially Update User by ID"));

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

//--7--
router.delete("/:id", auth, async (req, res) => {
  console.log(chalk.blue("Route: Delete User by ID"));

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
