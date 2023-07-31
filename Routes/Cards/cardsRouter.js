const { Card } = require("./cardModel");
const express = require("express");
const auth = require("../../middlewares/authorization");
const router = express.Router();
const chalk = require("chalk");
const { validateCard } = require("./cardValidation");
const User = require("../Users/userModel");
const getUser = async (user_id)=>{
  let user = await User.findById(user_id);
  return user;
};

router.get("", async (req, res) => {
  try {
    const cards = await Card.find();
    return res.send(cards);
  } catch (error) {
    return res.status(500).send(error.message);
  }
});

router.get("/my-cards", auth, async (req, res) => {
  try {
    let user = req.user;
    const cards = await Card.find({ user_id: user._id });
    return res.send(cards);
  } catch (error) {
    return res.status(500).send(error.message);
  }
});

router.get("/:id", async (req, res) => {
  try {
    const cardID = req.params.id;
    const card = await Card.findOne({ _id: cardID });
    return res.send(card);
  } catch (error) {
    return res.status(500).send(error.message);
  }
});

router.post("", auth, async (req, res) => {
  try {
    const user = req.user;
    if (!user.biz) {
      return res.status(403).json("Un authorize user!");
    }

    let card = req.body;
    const { error } = validateCard(card);
    if (error) {
      return res.status(400).send(error.details[0].message);
    }
    card = new Card({
      title: card.title,
      subtitle: card.subtitle,
      description: card.description,
      email: card.email,
      web: card.web,
      phone: card.phone,
      image: {
        url: card.image.url
          ? card.image.url
          : "https://cdn.pixabay.com/photo/2015/10/05/22/37/blank-profile-picture-973460_960_720.png",
        alt: card.alt ? card.alt : "Pic Of Card",
      },
      address:{
        state: card.address.state,
        country: card.address.country,
        city: card.address.city,
        street: card.address.street,
        houseNumber: card.address.houseNumber,
        zip: card.address.zip
         },
       user_id: user._id,
    });
    card = await card.save();
    return res.send(card);
  } catch (error) {
    return res.status(500).send(error);
  }
});

router.put("/:id", auth, async (req, res) => {
  try {
    let user = req.user;
    if (!user.biz && !user.isAdmin) {
      return res.status(403).json("You are not authorize to edit card!");
    }
    let card = req.body;
    delete card._id;
    const { error } = validateCard(card);
    if (error) {
      const errorMessage = error.details[0].message;
      return res.status(400).send(errorMessage);
    }

    card = {
      title: card.title,
      subtitle: card.subtitle,
      description: card.description,
      email: card.email,
      web: card.web,
      phone: card.phone,
      image: {
        url: card.image.url
          ? card.image.url
          : "https://cdn.pixabay.com/photo/2015/10/05/22/37/blank-profile-picture-973460_960_720.png",
        alt: card.alt ? card.alt : "Pic Of Card",
      },
      address:{
        state: card.address.state,
        country: card.address.country,
        city: card.address.city,
        street: card.address.street,
        houseNumber: card.address.houseNumber,
        zip: card.address.zip
         }
    };

    const filter = {
      _id: req.params.id,
      userID: user._id,
    };

    card = await Card.findOneAndUpdate(filter, card);
    if (!card) {
      return res.status(404).send("No card with this ID in the database!");
    }
    card = await Card.findById(card._id);
    return res.send(card);
  } catch (error) {
    return res.status(500).send(error.message);
  }
});

router.patch("/:id", auth, async (req, res) => {
  try {
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
    return res.status(500).send(error.message);
  }
});

router.delete("/:id", auth, async (req, res) => {
  try {
    let user = await getUser(req.user._id);
   
    if(!user){
      return res.status(404).json("User are not exist");
    }

    let card;
    card = await Card.findById(req.params.id);

    if(!card){
      return res.status(404).json("Card not found"); 
    }

    if(user._id.toString() != card.user_id.toString()){
          if (!user.isAdmin) {
            return res.status(403).json("You are not authorize to delete this card!");
          }
      }

      card = await Card.findOneAndRemove({
        _id: req.params.id
      });
   
    if (!card) {
      return res.status(403).send("You are noe authorize to delete cards");
    }

    return res.send(card);
  } catch (error) {
    return res.status(500).send(error.message);
  }
});
module.exports = router;
