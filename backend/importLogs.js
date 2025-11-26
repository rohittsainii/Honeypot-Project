// importLogs.js

require('dotenv').config();
const fs = require('fs');
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

// Function to process and import logs
async function importLogs() {
  try {
    const logPath = process.env.HONEYPOT_LOG_PATH;

    if (!fs.existsSync(logPath)) {
      console.error('❌ Log file not found:', logPath);
      return { imported: 0, skipped: 0 };
    }

    console.log('📖 Reading logs from:', logPath);

    const logs = fs.readFileSync(logPath, 'utf8').split('\n');

    let imported = 0;
    let skipped = 0;

    for (const line of logs) {
      const trimmed = line.trim();
      if (!trimmed) continue;

      try {
        // Find JSON start — cowrie logs prefix timestamps before JSON
        const jsonStart = trimmed.indexOf('{');
        if (jsonStart === -1) {
          skipped++;
          continue; // No JSON → skip the line
        }

        const jsonPart = trimmed.slice(jsonStart);
        const data = JSON.parse(jsonPart); // Parse the actual JSON object

        // Extract IP
        let ip = null;
        if (data.data?.client_ip) {
          ip = data.data.client_ip;
        } else if (Array.isArray(data.data?.client)) {
          ip = data.data.client[0]; // IPv6 or IPv4 stored here
        }

        const geoData = getGeoIP(ip);

        // Create attack document
        const attack = new Attack({
          timestamp: new Date(data.timestamp),
          event: data.event,
          sessionId: data.data?.session_id,
          username: data.data?.username,
          password: data.data?.password,
          ip: ip,
          command: data.data?.cmd,
          country: geoData.country,
          countryCode: geoData.countryCode,
          city: geoData.city,
          latitude: geoData.latitude,
          longitude: geoData.longitude,
          timezone: geoData.timezone
        });

        await attack.save();
        imported++;

        if (imported % 100 === 0) {
          console.log(`✅ Imported ${imported} entries...`);
        }
      } catch (e) {
        skipped++;
        // Uncomment below if you want debugging info
        // console.error('❌ Error:', e.message, '\nLine:', trimmed);
      }
    }

    console.log('\n🎯 Import Complete!');
    console.log(`   Imported: ${imported}`);
    console.log(`   Skipped: ${skipped}`);

    return { imported, skipped };

  } catch (error) {
    console.error('❌ Import Error:', error.message);
    throw error;
  }
}

// Run if executed directly
if (require.main === module) {
  connectDB().then(async () => {
    await importLogs();
    process.exit(0);
  });
}

module.exports = importLogs;
