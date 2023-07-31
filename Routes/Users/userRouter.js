const validateRegistration = require("./usersValidations/registraion");
const validateEditUser = require("./usersValidations/editUser");
const validateEditIsBusiness = require("./usersValidations/ediIisBusiness");
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

const getUser = async (user_id)=>{
   let user = await User.findById(user_id);
   return user;
};


router.post("", async (req, res) => {
  const { error } = validateRegistration(req.body);
  if (error) {
    return res.status(400).send(error.details[0].message);
  }

  let user = await User.findOne({ email: req.body.email });
  if (user) {

    return res.status(409).send("User already exists.");
  }
  user = new User({ ...req.body });

  user.password = generateHashPassword(user.password);
  await user.save();
  res.send(_.pick(user, ["_id", "name", "email"]));
});


router.post("/login", async (req, res) => {
const { error } = validateSignin(req.body);
  if (error) {
    return res.status(400).send(error.details[0].message);
  }

  let user = await User.findOne({ email: req.body.email });
  
  if (!user) {
    return res.status(401).send("Invalid email or password.");
  }

  const validPassword = comparePassword(req.body.password, user.password);
  if (!validPassword) {
    return res.status(401).send("Invalid email or password.");
  }

  res.json({
    token: generateAuthToken(user),
  });
});


router.get("", auth, async (req, res) => {
 try {
    if (!req.user || !req.user.isAdmin) {
      throw "you need to be admin!";
    }
    const users = await User.find().select(["-password", "-createdAt", "-__v"]);
    res.json({ users });
  } catch (err) {
    res.status(500).send(err);
  }
});


router.get("/:id", auth, (req, res) => {
  let user = req.user;
  if(!(user._id.toString() == req.params.id || user.isAdmin)){
     res.status(404).send("Authorization Error");
    return;
  }

  User.findById(user._id)
    .select(["-password", "-createdAt", "-__v"])
    .then(
      (user) => {
      if(user){
        res.send(user);
      }else{
        res.status(404).send('User not found');
      }
    })
    .catch((errorsFromMongoose) => res.status(500).send(errorsFromMongoose));
});

router.put("/:id", auth, async (req, res) => {
 
  let user = req.user;
  if(user._id.toString() != req.params.id ){
      res.status(404).send("Authorization Error");
    return;
 }
  try {
    const { error } = validateEditUser(req.body);
    if (error) {
      return res.status(400).send(error.details[0].message);
    }
    await User.findByIdAndUpdate(req.user._id, req.body);
    res.json({ msg: "Done" });
  } catch (err) {
    res.status(500).send(err);
  }
});

router.patch("/:id", auth, async (req, res) => {
  
  let user = req.user;
  if(user._id.toString() != req.params.id ){
      res.status(404).send("Authorization Error");
    return;
 }

  try {
    const { error } = validateEditIsBusiness(req.body);
    if (error) {
      return res.status(400).send(error.details[0].message);
    }
    await User.findByIdAndUpdate(req.params.id, req.body);
    res.json({ msg: "Done" });
  } catch (err) {
    res.status(500).send(err);
  }
});

router.delete("/:id", auth, async (req, res) => {
  try {
    let user = await getUser(req.user._id);
    if(!user){
      res.status(404).send("Authorization Error"); //TODO replace the error msg
      return;
    }

    if(user._id.toString() != req.params.id ){
      if (!user.isAdmin) {
        res.status(404).send("Authorization Error");
        return;
      }
   }
   
    let delted_user = await User.findByIdAndDelete(req.params.id);
    if(!delted_user){
      res.status(404).send("User not found");
       return;
    }
    res.json({ msg: "Done" });
  } catch (err) {
    res.status(500).send(err);
  }
});

module.exports = router;
