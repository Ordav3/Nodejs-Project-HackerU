const { Card } = require("./cardModel");
const express = require("express");
const auth = require("../../middlewares/authorization");
const router = express.Router();
const chalk = require("chalk");
const { generateBizNum } = require("./services/generateBizNum");
const { validateCard } = require("./cardValidation");

/********** סעיף 7 **********/
router.get("/cards", async (req, res) => {
  try {
    const cards = await Card.find();
    return res.send(cards);
  } catch (error) {
    console.log(chalk.redBright(error.message));
    return res.status(500).send(error.message);
  }
});

/********** סעיף 8 **********/
router.get("/card/:id", async (req, res) => {
  try {
    const cardID = req.params.id;
    const card = await Card.findOne({ _id: cardID });
    return res.send(card);
  } catch (error) {
    console.log(chalk.redBright(error.message));
    return res.status(500).send(error.message);
  }
});

/********** סעיף 9 **********/
router.get("/my-cards", auth, async (req, res) => {
  try {
    console.log("my-cards request");
    let user = req.user;
    if (!user.biz) return res.status(403).json("Un authorize user!");
    const cards = await Card.find({ user_id: user._id });
    console.log("cards:", cards);
    return res.send(cards);
  } catch (error) {
    console.log(chalk.redBright(error.message));
    return res.status(500).send(error.message);
  }
});

router.get("/get-my-fav-cards", auth, async (req, res) => {
  try {
    let user = req.user;
    const cards = await Card.find({ likes: user._id });
    res.json(cards);
  } catch (err) {
    console.log(chalk.redBright(err));
    return res.status(500).send(err);
  }
});

/********** סעיף 10 **********/
router.post("/", auth, async (req, res) => {
  try {
    const user = req.user;
    console.log("caards/");
    if (!user.biz) {
      console.log(
        chalk.redBright("A non biz user attempted to create a card!")
      );
      return res.status(403).json("Un authorize user!");
    }

    let card = req.body;

    const { error } = validateCard(card);
    if (error) {
      console.log(chalk.redBright(error.details[0].message));
      return res.status(400).send(error.details[0].message);
    }

    card = new Card({
      title: card.title,
      subTitle: card.subTitle,
      description: card.description,
      state: card.state,
      country: card.country,
      city: card.city,
      street: card.street,
      houseNumber: card.houseNumber,
      zipCode: card.zipCode,
      email: card.email,
      web: card.web,
      phone: card.phone,
      image: {
        url: card.url
          ? card.url
          : "https://cdn.pixabay.com/photo/2015/10/05/22/37/blank-profile-picture-973460_960_720.png",
        alt: card.alt ? card.alt : "Pic Of Business Card",
      },
      bizNumber: await generateBizNum(),
      user_id: user._id,
    });
    // card = new Card({
    //   title: card.title,
    //   subTitle: card.subTitle,
    //   description: card.description,
    //   address: card.address,
    //   phone: card.phone,
    //   image: {
    //     url: card.url
    //       ? card.url
    //       : "https://cdn.pixabay.com/photo/2015/10/05/22/37/blank-profile-picture-973460_960_720.png",
    //     alt: card.alt ? card.alt : "Pic Of Business Card",
    //   },
    //   bizNumber: await generateBizNum(),
    //   user_id: user._id,
    // });

    card = await card.save();
    return res.send(card);
  } catch (error) {
    console.log(chalk.redBright(error.message));
    return res.status(500).send(error);
  }
});

/********** סעיף 11 **********/
router.put("/:id", auth, async (req, res) => {
  try {
    let user = req.user;
    console.log("user", user);
    if (!user.biz && !user.isAdmin) {
      console.log(
        chalk.redBright("A non-business user attempted to create a card!")
      );
      return res.status(403).json("You are not authorize to edit card!");
    }
    let card = req.body;
    delete card._id;
    const { error } = validateCard(card);
    if (error) {
      const errorMessage = error.details[0].message;
      console.log(chalk.redBright(errorMessage));
      return res.status(400).send(errorMessage);
    }

    // card = {
    //   title: card.title,
    //   subTitle: card.subTitle,
    //   description: card.description,
    //   address: card.address,
    //   phone: card.phone,
    //   image: {
    //     url: card.url,
    //     alt: card.alt,
    //   },
    // };
    card = {
      title: card.title,
      subTitle: card.subTitle,
      description: card.description,
      state: card.state,
      country: card.country,
      city: card.city,
      street: card.street,
      houseNumber: card.houseNumber,
      zipCode: card.zipCode,
      email: card.email,
      web: card.web,
      phone: card.phone,
      image: {
        url: card.url
          ? card.url
          : "https://cdn.pixabay.com/photo/2015/10/05/22/37/blank-profile-picture-973460_960_720.png",
        alt: card.alt ? card.alt : "Pic Of Business Card",
      },
    };

    const filter = {
      _id: req.params.id,
      userID: user._id,
    };
    if (user.isAdmin) {
      delete filter.userID;
    }

    card = await Card.findOneAndUpdate(filter, card);
    if (!card) {
      console.log(chalk.redBright("No card with this ID in the database!"));
      return res.status(404).send("No card with this ID in the database!");
    }
    card = await Card.findById(card._id);
    return res.send(card);
  } catch (error) {
    console.log(chalk.redBright(error.message));
    return res.status(500).send(error.message);
  }
});

router.patch("/bizNumber/:bizId", auth, async (req, res) => {
  try {
    let user = req.user;
    // if (!user.biz) {
    if (!user.isAdmin) {
      console.log(chalk.redBright("need to be admin"));
      return res.status(403).json("You are not authorize to edit card!");
    }
    // bizNumber: await generateBizNum(),
    const card = await Card.findByIdAndUpdate(req.params.bizId, {
      bizNumber: await generateBizNum(),
    });
    return res.send(card);
  } catch (error) {
    console.log(chalk.redBright(error.message));
    return res.status(500).send(error.message);
  }
});

/********** סעיף 12 **********/
router.delete("/:id", auth, async (req, res) => {
  try {
    let user = req.user;
    if (!user.biz && !user.isAdmin) {
      console.log(
        chalk.redBright("A non-business user attempted to create a card!")
      );
      return res.status(403).json("You are not authorize to delete this card!");
    }

    let card;

    if (user.isAdmin) {
      card = await Card.findOneAndRemove({
        _id: req.params.id,
      });
    } else if (user.biz) {
      card = await Card.findOneAndRemove({
        _id: req.params.id,
        user_id: user._id,
      });
    }

    // let card = await Card.findOneAndRemove({
    //   _id: req.params.id,
    //   user_id: user._id,
    // });

    if (!card) {
      console.log(chalk.redBright("Un authorized user!"));
      return res.status(403).send("You are noe authorize to delete cards");
    }

    return res.send(card);
  } catch (error) {
    console.log(chalk.redBright("Could not delet card:", error.message));
    return res.status(500).send(error.message);
  }
});
/********** סעיף 13 **********/

router.patch("/card-like/:id", auth, async (req, res) => {
  try {
    console.log(req.params.id);
    const user = req.user;
    let card = await Card.findOne({ _id: req.params.id });

    const cardLikes = card.likes.find((id) => id === user._id);

    if (!cardLikes) {
      card.likes.push(user._id);
      card = await card.save();
      return res.send(card);
    }

    const cardFiltered = card.likes.filter((id) => id !== user._id);
    card.likes = cardFiltered;
    card = await card.save();
    return res.send(card);
  } catch (error) {
    console.log(chalk.redBright("Could not edit like:", error.message));
    return res.status(500).send(error.message);
  }
});

module.exports = router;
