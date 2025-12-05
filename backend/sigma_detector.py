from datetime import datetime, timedelta
from pymongo import MongoClient

class SigmaDetector:
    def __init__(self, mongodb_uri='mongodb://localhost:27017/honeypot'):
        self.db = MongoClient(mongodb_uri).honeypot
    
    def detect_ssh_bruteforce(self, minutes=5, threshold=10):
        """Detect SSH brute force attacks"""
        time_threshold = datetime.utcnow() - timedelta(minutes=minutes)
        
        pipeline = [
            {
                '$match': {
                    'event': 'auth',
                    'timestamp': {'$gte': time_threshold}
                }
            },
            {
                '$group': {
                    '_id': '$ip',
                    'attempts': {'$sum': 1},
                    'usernames': {'$addToSet': '$username'}
                }
            },
            {
                '$match': {
                    'attempts': {'$gte': threshold}
                }
            }
        ]
        
        return list(self.db.Attack.aggregate(pipeline))
    
    def detect_default_credentials(self):
        """Detect usage of default credentials"""
        default_creds = [
            ('root', 'root'),
            ('admin', 'admin'),
            ('root', 'password'),
            ('admin', 'password'),
            ('root', '123456'),
            ('test', 'test')
        ]
        
        results = []
        for username, password in default_creds:
            count = self.db.Attack.count_documents({
                'event': 'auth',
                'username': username,
                'password': password
            })
            if count > 0:
                results.append({
                    'username': username,
                    'password': password,
                    'attempts': count
                })
        
        return results
    
    def detect_malicious_commands(self):
        """Detect malicious command patterns"""
        malicious_patterns = [
            'wget',
            'curl',
            'chmod +x',
            '/dev/tcp/',
            'nc -e',
            'python -c',
            'perl -e'
        ]
        
        results = []
        for pattern in malicious_patterns:
            matches = self.db.Attack.find({
                'command': {'$regex': pattern, '$options': 'i'}
            }).limit(10)
            
            results.extend([{
                'pattern': pattern,
                'command': doc.get('command'),
                'ip': doc.get('ip'),
                'timestamp': doc.get('timestamp')
            } for doc in matches])
        
        return results
    
    def detect_crypto_miners(self):
        """Detect cryptocurrency mining activity"""
        miner_keywords = ['xmrig', 'minerd', 'cpuminer', 'stratum+tcp', 'monero']
        
        return list(self.db.Attack.find({
            'command': {
                '$regex': '|'.join(miner_keywords),
                '$options': 'i'
            }
        }))
    
    def generate_alert_report(self):
        """Generate comprehensive alert report"""
        report = {
            'timestamp': datetime.utcnow(),
            'alerts': {
                'brute_force': self.detect_ssh_bruteforce(),
                'default_credentials': self.detect_default_credentials(),
                'malicious_commands': self.detect_malicious_commands(),
                'crypto_miners': self.detect_crypto_miners()
            }
        }
        
        return report

# Usage example
if __name__ == '__main__':
    detector = SigmaDetector()
    
    # Generate report
    report = detector.generate_alert_report()
    
    print("=== Security Alert Report ===")
    print(f"Generated: {report['timestamp']}")
    print(f"\nBrute Force Attacks: {len(report['alerts']['brute_force'])}")
    print(f"Default Credential Attempts: {len(report['alerts']['default_credentials'])}")
    print(f"Malicious Commands: {len(report['alerts']['malicious_commands'])}")
    print(f"Crypto Miners: {len(report['alerts']['crypto_miners'])}")