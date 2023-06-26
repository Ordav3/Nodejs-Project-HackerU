const usersService = require("../model/users/usersService");
const cardsService = require("../model/cards/cardsService");
const bcrypt = require("../config/bcrypt");
const normalizeUser = require("../model/users/helpers/normalizationUser");
const normalizeCard = require("../model/cards/helpers/normalizationCard");

const usersData = require("./users.json");
const cardsData = require("./cards.json");

const initialData = async () => {
  try {
    let cards = await cardsService.getAllCards();
    if (cards.length) {
      return;
    }
    let users = await usersService.getAllUsers();
    if (users.length) {
      return;
    }
    let user_id = "";
    for (let user of usersData) {
      user.password = await bcrypt.generateHash(user.password);
      user = normalizeUser(user);
      user_id = await usersService.registerUser(user);
    }
    user_id = user_id._id + "";
    for (let card of cardsData) {
      card = await normalizeCard(card, user_id);
      await cardsService.createCard(card);
    }
  } catch (err) {
    console.log("err from initial", err);
  }
};

// initialData();
module.exports = initialData;
