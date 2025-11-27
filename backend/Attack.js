//Attack.js

const mongoose = require('mongoose');

const AttackSchema = new mongoose.Schema({
  timestamp: {
    type: Date,
    required: true,
    index: true
  },
  event: {
    type: String,
    required: true
  },
  sessionId: String,
  username: String,
  password: String,
  ip: {
    type: String,
    index: true
  },
  command: String,
  
  // GeoIP data
  country: String,
  countryCode: String,
  city: String,
  latitude: Number,
  longitude: Number,
  timezone: String
}, {
  timestamps: true  // Adds createdAt, updatedAt automatically
});

module.exports = mongoose.model('Attack', AttackSchema);