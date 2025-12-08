// importLogs.js - Improved version with better error handling

require('dotenv').config();
const fs = require('fs');
const path = require('path');
const geoip = require('geoip-lite');
const connectDB = require('./database');
const Attack = require('./Attack');

// Function to get GeoIP data
function getGeoIP(ip) {
  if (!ip || ip === '127.0.0.1' || ip === 'localhost' || ip === '::1') {
    return {
      country: 'Local',
      countryCode: 'LO',
      city: 'Localhost',
      latitude: 0,
      longitude: 0,
      timezone: 'Local'
    };
  }

  const geo = geoip.lookup(ip);

  if (!geo) {
    return {
      country: 'Unknown',
      countryCode: 'XX',
      city: 'Unknown',
      latitude: 0,
      longitude: 0,
      timezone: 'Unknown'
    };
  }

  return {
    country: geo.country,
    countryCode: geo.country,
    city: geo.city || 'Unknown',
    latitude: geo.ll[0],
    longitude: geo.ll[1],
    timezone: geo.timezone || 'Unknown'
  };
}

// Function to extract IP from various log formats
function extractIP(data) {
  // Try different possible IP locations in the log data
  if (data.data?.client_ip) {
    return data.data.client_ip;
  }
  
  if (Array.isArray(data.data?.client)) {
    return data.data.client[0];
  }
  
  if (data.data?.ip) {
    return data.data.ip;
  }
  
  if (data.ip) {
    return data.ip;
  }
  
  return null;
}

// Function to parse a single log line
function parseLogLine(line) {
  const trimmed = line.trim();
  if (!trimmed) return null;

  try {
    // Method 1: Try direct JSON parse (if log is pure JSON)
    try {
      return JSON.parse(trimmed);
    } catch (e) {
      // Not pure JSON, continue to next method
    }

    // Method 2: Find JSON object in line (handles timestamp prefixes)
    const jsonStart = trimmed.indexOf('{');
    if (jsonStart === -1) {
      return null; // No JSON found
    }

    const jsonPart = trimmed.slice(jsonStart);
    return JSON.parse(jsonPart);
    
  } catch (error) {
    // Silently skip malformed lines
    return null;
  }
}

// Function to process and import logs
async function importLogs() {
  try {
    console.log('🔍 Starting log import process...\n');

    // Get log path from environment
    const logPath = process.env.HONEYPOT_LOG_PATH || '../honeypot/logs/cowrie.log';
    const resolvedPath = path.resolve(logPath);

    console.log(`📂 Log file path: ${resolvedPath}`);

    // Check if log file exists
    if (!fs.existsSync(resolvedPath)) {
      console.error(`❌ Error: Log file not found at: ${resolvedPath}`);
      console.log('\n💡 To fix this:');
      console.log('   1. Make sure your honeypot is running and generating logs');
      console.log('   2. Check your .env file has correct HONEYPOT_LOG_PATH');
      console.log('   3. Current path setting: ' + logPath);
      return { imported: 0, skipped: 0, error: 'Log file not found' };
    }

    // Check file size
    const stats = fs.statSync(resolvedPath);
    console.log(`📊 Log file size: ${(stats.size / 1024).toFixed(2)} KB`);

    if (stats.size === 0) {
      console.log('⚠️  Warning: Log file is empty');
      console.log('   Run the honeypot and try to connect to it to generate logs');
      return { imported: 0, skipped: 0, error: 'Log file is empty' };
    }

    // Read log file
    console.log('📖 Reading log file...');
    const logContent = fs.readFileSync(resolvedPath, 'utf8');
    const lines = logContent.split('\n').filter(line => line.trim());

    console.log(`📝 Found ${lines.length} log lines\n`);
    console.log('⚙️  Processing logs...\n');

    let imported = 0;
    let skipped = 0;
    let duplicates = 0;
    const errors = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      // Parse log line
      const data = parseLogLine(line);
      
      if (!data) {
        skipped++;
        continue;
      }

      try {
        // Extract required fields
        const timestamp = data.timestamp ? new Date(data.timestamp) : new Date();
        const event = data.event || 'unknown';
        
        // Skip if not an interesting event
        if (!['auth', 'session_start', 'session_event'].includes(event)) {
          skipped++;
          continue;
        }

        // Extract IP
        const ip = extractIP(data);
        
        // Get GeoIP data
        const geoData = ip ? getGeoIP(ip) : {
          country: 'Unknown',
          countryCode: 'XX',
          city: 'Unknown',
          latitude: 0,
          longitude: 0,
          timezone: 'Unknown'
        };

        // Create attack document
        const attackData = {
          timestamp: timestamp,
          event: event,
          sessionId: data.data?.session_id || data.sessionId,
          username: data.data?.username || data.username,
          password: data.data?.password || data.password,
          ip: ip,
          command: data.data?.cmd || data.command,
          country: geoData.country,
          countryCode: geoData.countryCode,
          city: geoData.city,
          latitude: geoData.latitude,
          longitude: geoData.longitude,
          timezone: geoData.timezone
        };

        // Check for duplicates (optional - comment out if you want to allow duplicates)
        const existingAttack = await Attack.findOne({
          timestamp: attackData.timestamp,
          event: attackData.event,
          ip: attackData.ip,
          username: attackData.username
        });

        if (existingAttack) {
          duplicates++;
          continue;
        }

        // Save to database
        const attack = new Attack(attackData);
        await attack.save();
        
        imported++;

        // Progress indicator
        if (imported % 50 === 0) {
          const progress = ((i + 1) / lines.length * 100).toFixed(1);
          console.log(`   ✓ Imported ${imported} entries (${progress}% complete)...`);
        }

      } catch (error) {
        skipped++;
        if (errors.length < 5) { // Only store first 5 errors
          errors.push({
            line: i + 1,
            message: error.message,
            data: line.substring(0, 100)
          });
        }
      }
    }

    // Final report
    console.log('\n' + '='.repeat(60));
    console.log('📊 IMPORT COMPLETE');
    console.log('='.repeat(60));
    console.log(`✅ Successfully imported: ${imported} entries`);
    console.log(`⏭️  Skipped: ${skipped} entries`);
    if (duplicates > 0) {
      console.log(`🔄 Duplicates avoided: ${duplicates} entries`);
    }
    console.log(`📈 Total processed: ${lines.length} lines`);
    console.log('='.repeat(60));

    // Show errors if any
    if (errors.length > 0) {
      console.log('\n⚠️  Sample errors encountered:');
      errors.forEach(err => {
        console.log(`   Line ${err.line}: ${err.message}`);
        console.log(`   Data: ${err.data}...`);
      });
    }

    // Verify data in database
    const totalInDB = await Attack.countDocuments();
    console.log(`\n💾 Total entries now in database: ${totalInDB}`);

    // Show sample entry
    const sampleEntry = await Attack.findOne().sort({ timestamp: -1 });
    if (sampleEntry) {
      console.log('\n📋 Latest entry in database:');
      console.log(`   Event: ${sampleEntry.event}`);
      console.log(`   IP: ${sampleEntry.ip}`);
      console.log(`   Country: ${sampleEntry.country}`);
      console.log(`   Timestamp: ${sampleEntry.timestamp}`);
    }

    console.log('\n✨ Import process finished successfully!\n');

    return { imported, skipped, duplicates, totalInDB };

  } catch (error) {
    console.error('\n❌ Import Error:', error.message);
    console.error('Stack trace:', error.stack);
    throw error;
  }
}

// Run if executed directly
if (require.main === module) {
  console.log('🍯 Honeypot Log Importer\n');
  
  connectDB()
    .then(async () => {
      await importLogs();
      process.exit(0);
    })
    .catch(err => {
      console.error('Failed to connect to database:', err.message);
      process.exit(1);
    });
}

module.exports = importLogs;