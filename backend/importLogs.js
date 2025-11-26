require('dotenv').config();
const fs = require('fs');
const geoip = require('geoip-lite');
const connectDB = require('./database');
const Attack = require('./Attack');

// Function to get GeoIP data
function getGeoIP(ip) {
  if (!ip || ip === '127.0.0.1' || ip === 'localhost') {
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
    timezone: geo.timezone
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
      if (!line.trim()) continue;
      
      try {
        const data = JSON.parse(line);
        
        // Extract IP
        let ip = null;
        if (data.data?.client_ip) {
          ip = data.data.client_ip;
        } else if (Array.isArray(data.data?.client)) {
          ip = data.data.client[0];
        }

        // Get GeoIP data
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

        // Show progress every 100 entries
        if (imported % 100 === 0) {
          console.log(`✅ Imported ${imported} entries...`);
        }
      } catch (e) {
        skipped++;
      }
    }

    console.log(`\n✅ Import Complete!`);
    console.log(`   Imported: ${imported}`);
    console.log(`   Skipped: ${skipped}`);
    
    return { imported, skipped };
  } catch (error) {
    console.error('❌ Import Error:', error.message);
    throw error;
  }
}

// Run if called directly
if (require.main === module) {
  connectDB().then(async () => {
    await importLogs();
    process.exit(0);
  });
}

module.exports = importLogs;