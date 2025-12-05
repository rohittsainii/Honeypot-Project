import json
import geoip2.database
from pymongo import MongoClient

class LogParser:
    def __init__(self, db_uri, geoip_db_path):
        self.db = MongoClient(db_uri).honeypot
        self.geoip = geoip2.database.Reader(geoip_db_path)
        
    
    def enrich_and_store(self, log_line):
        data = json.loads(log_line)
        
        # GeoIP enrichment
        if 'client_ip' in data.get('data', {}):
            ip = data['data']['client_ip']
            try:
                geo = self.geoip.city(ip)
                data['data']['country'] = geo.country.name
                data['data']['city'] = geo.city.name
                data['data']['latitude'] = geo.location.latitude
                data['data']['longitude'] = geo.location.longitude
            except:
                pass
        
        self.db.events.insert_one(data)