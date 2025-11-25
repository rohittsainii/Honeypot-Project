require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const fs = require('fs');

const app = express();
app.use(cors());
app.use(express.json());

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/honeypot')
  .then(() => console.log('✅ Connected to MongoDB'))
  .catch(err => console.error('❌ MongoDB error:', err));

// Simple Attack Schema
const AttackSchema = new mongoose.Schema({
  timestamp: Date,
  event: String,
  username: String,
  password: String,
  ip: String,
  command: String,
  country: String
});

const Attack = mongoose.model('Attack', AttackSchema);

// API Routes
app.get('/api/stats', async (req, res) => {
  try {
    const total = await Attack.countDocuments();
    const authAttempts = await Attack.countDocuments({ event: 'auth' });
    
    res.json({
      totalAttacks: total,
      authAttempts: authAttempts
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/attacks/recent', async (req, res) => {
  try {
    const attacks = await Attack.find({ event: 'auth' })
      .sort({ timestamp: -1 })
      .limit(50);
    res.json(attacks);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/attacks/credentials', async (req, res) => {
  try {
    const credentials = await Attack.aggregate([
      { $match: { event: 'auth' } },
      { $group: { 
          _id: { username: '$username', password: '$password' },
          count: { $sum: 1 }
      }},
      { $sort: { count: -1 } },
      { $limit: 10 }
    ]);
    res.json(credentials);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/attacks/commands', async (req, res) => {
  try {
    const commands = await Attack.aggregate([
      { $match: { command: { $exists: true } } },
      { $group: { _id: '$command', count: { $sum: 1 } }},
      { $sort: { count: -1 } },
      { $limit: 10 }
    ]);
    res.json(commands);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Import logs from honeypot
app.post('/api/import-logs', async (req, res) => {
  try {
    const logPath = '../honeypot/logs/cowrie.log';
    const logs = fs.readFileSync(logPath, 'utf8').split('\n');
    
    let imported = 0;
    for (const line of logs) {
      if (!line.trim()) continue;
      
      try {
        const data = JSON.parse(line);
        const attack = new Attack({
          timestamp: new Date(data.timestamp),
          event: data.event,
          username: data.data?.username,
          password: data.data?.password,
          ip: data.data?.client_ip,
          command: data.data?.cmd
        });
        await attack.save();
        imported++;
      } catch (e) {
        // Skip invalid lines
      }
    }
    
    res.json({ message: `Imported ${imported} logs` });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Backend running on http://localhost:${PORT}`);
});