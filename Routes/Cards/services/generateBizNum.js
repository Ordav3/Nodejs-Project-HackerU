const { Card } = require("../cardModel");
const lodash = require("lodash");

async function generateBizNum() {
  return lodash.random(1_000_000, 9_999_999);
}

// async function generateBizNum() {
//   let randomNum = lodash.random(1000, 999999);
//   let card = await Card.findOne({ number: randomNum });
//   if (!card) return String(randomNum);
//   generateBizNum();
// }

exports.generateBizNum = generateBizNum;
