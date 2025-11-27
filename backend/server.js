//server.js

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const connectDB = require('./database');
const Attack = require('./Attack');
const importLogs = require('./importLogs');

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Connect to database
connectDB();

// ========== API ROUTES ==========

// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date(),
    message: 'Honeypot API is running' 
  });
});

// Get statistics
app.get('/api/stats', async (req, res) => {
  try {
    const [total, authAttempts, uniqueIps, sessions] = await Promise.all([
      Attack.countDocuments(),
      Attack.countDocuments({ event: 'auth' }),
      Attack.distinct('ip').then(ips => ips.filter(ip => ip).length),
      Attack.countDocuments({ event: 'session_start', username: { $ne: 'N/A' } })
    ]);

    res.json({
      totalAttacks: total,
      authAttempts: authAttempts,
      uniqueIps: uniqueIps,
      successfulSessions: sessions
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get recent attacks
app.get('/api/attacks/recent', async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 50;
    
    const attacks = await Attack.find({ event: 'auth' })
      .sort({ timestamp: -1 })
      .limit(limit)
      .select('timestamp ip username password country city');

    res.json(attacks);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get attacks by country
app.get('/api/attacks/by-country', async (req, res) => {
  try {
    const countries = await Attack.aggregate([
      { $match: { event: 'auth', country: { $ne: 'Unknown' } } },
      { $group: { _id: '$country', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 10 },
      { $project: { _id: 0, country: '$_id', count: 1 } }
    ]);

    res.json(countries);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get map data (for visualization)
app.get('/api/attacks/map', async (req, res) => {
  try {
    const mapData = await Attack.aggregate([
      { 
        $match: { 
          event: 'auth',
          latitude: { $ne: 0 },
          longitude: { $ne: 0 }
        } 
      },
      { 
        $group: {
          _id: { lat: '$latitude', lon: '$longitude', country: '$country' },
          count: { $sum: 1 },
          city: { $first: '$city' }
        }
      },
      {
        $project: {
          _id: 0,
          latitude: '$_id.lat',
          longitude: '$_id.lon',
          country: '$_id.country',
          city: '$city',
          count: 1
        }
      }
    ]);

    res.json(mapData);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get top credentials
app.get('/api/attacks/credentials', async (req, res) => {
  try {
    const credentials = await Attack.aggregate([
      { $match: { event: 'auth', username: { $exists: true } } },
      { 
        $group: { 
          _id: { username: '$username', password: '$password' },
          count: { $sum: 1 }
        }
      },
      { $sort: { count: -1 } },
      { $limit: 20 },
      {
        $project: {
          _id: 0,
          username: '$_id.username',
          password: '$_id.password',
          count: 1
        }
      }
    ]);

    res.json(credentials);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get top commands
app.get('/api/attacks/commands', async (req, res) => {
  try {
    const commands = await Attack.aggregate([
      { $match: { command: { $exists: true, $ne: null } } },
      { $group: { _id: '$command', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 20 },
      { $project: { _id: 0, command: '$_id', count: 1 } }
    ]);

    res.json(commands);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get attack timeline (last 7 days)
app.get('/api/attacks/timeline', async (req, res) => {
  try {
    const days = parseInt(req.query.days) || 7;
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days);

    const timeline = await Attack.aggregate([
      { $match: { timestamp: { $gte: startDate }, event: 'auth' } },
      {
        $group: {
          _id: { $dateToString: { format: '%Y-%m-%d', date: '$timestamp' } },
          count: { $sum: 1 }
        }
      },
      { $sort: { _id: 1 } },
      { $project: { _id: 0, date: '$_id', attacks: '$count' } }
    ]);

    res.json(timeline);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Import logs endpoint
app.post('/api/import-logs', async (req, res) => {
  try {
    console.log('Starting log import...');
    const result = await importLogs();
    
    res.json({
      success: true,
      message: `Imported ${result.imported} logs`,
      imported: result.imported,
      skipped: result.skipped
    });
  } catch (error) {
    res.status(500).json({ 
      success: false,
      error: error.message 
    });
  }
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`Health check: http://localhost:${PORT}/api/health`);
  console.log(`Stats: http://localhost:${PORT}/api/stats`);
});