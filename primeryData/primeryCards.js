const { Card } = require("../Routes/Cards/cardModel");
const User = require("../Routes/Users/userModel");
const chalk = require("chalk");
const { generateHashPassword } = require("../services/bcrypt");

const data = {
  users: [
    {
      name: "user",
      email: "user@gmail.com",
      password: 123456,
      biz: false,
    },
    {
      name: "admin",
      email: "admin@gmail.com",
      password: 123456,
      biz: true,
      isAdmin: true,
    },
    {
      name: "business",
      email: "business@gmail.com",
      password: 123456,
      biz: true,
      isAdmin: false,
    },
  ],
  cards: [
    {
      title: "First Card",
      subTitle: "My First Card",
      description:
        "This is the description of this respectable business card. It is a successful business in some field with a very high demand for its products",
      address: "bla bla",
      phone: "0500000000",
      image: {
        url: "https://cdn.pixabay.com/photo/2022/02/09/17/22/cat-7003849_960_720.jpg",
        alt: "Cat Foot",
      },
      bizNumber: "1000000",
      likes: [],
      user_id: "621f3f27dde069e62aa3bcab",
    },
    {
      title: "Second Card",
      subTitle: "My Second Card",
      description:
        "This is the description of this respectable business card. It is a successful business in some field with a very high demand for its products",
      address: "bla bla",
      phone: "0500000000",
      image: {
        url: "https://cdn.pixabay.com/photo/2020/05/08/16/06/dog-5146351_960_720.jpg",
        alt: "dog pic",
      },
      bizNumber: "1000001",
      likes: [],
      user_id: "621f3f27dde069e62aa3bcab",
    },
    {
      title: "Third Card",
      subTitle: "My Third Card",
      description:
        "This is the description of this respectable business card. It is a successful business in some field with a very high demand for its products",
      address: "bla bla",
      phone: "0500000000",
      image: {
        url: "https://cdn.pixabay.com/photo/2022/01/07/07/08/seal-6921267_960_720.jpg",
        alt: "Seel",
      },
      bizNumber: "1000002",
      likes: [],
      user_id: "621f3f27dde069e62aa3bcab",
    },
  ],
};

async function primaryUsers(user) {
  try {
    user = new User(user);
    user.password = generateHashPassword(user.password);
    await user.save();
  } catch (error) {
    console.log(chalk.redBright(error.message));
  }
}

async function primaryCards(card) {
  try {
    card = new Card(card);
    await card.save();
  } catch (error) {
    console.log(chalk.redBright(error.message));
  }
}

const primaryData = () => {
  for (let i of data.users) {
    primaryUsers(i);
  }
  for (let i of data.cards) {
    primaryCards(i);
  }
};

module.exports = primaryData;
