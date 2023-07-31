const { Card } = require("../cardModel");
const lodash = require("lodash");

async function generateBizNum() {
  return lodash.random(1_000_000, 9_999_999);
}

exports.generateBizNum = generateBizNum;
