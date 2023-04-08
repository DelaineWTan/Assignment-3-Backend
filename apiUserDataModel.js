const mongoose = require('mongoose')

const apiUserDataSchema = new mongoose.Schema({
  userId: { type: String, required: false, default: null },
  timestamp: { type: Date, required: true },
  endpoint: { type: String, required: true },
  status: { type: Number, required: true },
});

module.exports = mongoose.model('ApiUserData', apiUserDataSchema) 