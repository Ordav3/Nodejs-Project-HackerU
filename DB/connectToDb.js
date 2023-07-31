const mongoose = require("mongoose");
const config = require("config");
const chalk = require("chalk");

mongoose
  .connect(config.get("dbConfig.url"), {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log(chalk.magentaBright.bold("connected to MongoDb!")))
  .catch((error) =>
    console.log(chalk.redBright.bold(`could not connect to mongoDb: ${error}`))
  );
