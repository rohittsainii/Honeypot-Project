import yara
import os

class YaraScanner:
    def __init__(self, rules_path='../rules/yara/honeypot_detection.yar'):
        self.rules = yara.compile(filepath=rules_path)
    
    def scan_file(self, filepath):
        """Scan a file and return matches"""
        matches = self.rules.match(filepath)
        return [
            {
                'rule': match.rule,
                'tags': match.tags,
                'meta': match.meta,
                'strings': [(s[0], s[1], s[2]) for s in match.strings]
            }
            for match in matches
        ]
    
    def scan_directory(self, directory):
        """Scan all files in a directory"""
        results = {}
        for root, dirs, files in os.walk(directory):
            for file in files:
                filepath = os.path.join(root, file)
                matches = self.scan_file(filepath)
                if matches:
                    results[filepath] = matches
        return results

# Usage example
if __name__ == '__main__':
    scanner = YaraScanner()
    
    # Scan captured malware samples
    results = scanner.scan_directory('../honeypot/downloads/')
    
    for filepath, matches in results.items():
        print(f"\n[!] Matches found in: {filepath}")
        for match in matches:
            print(f"  - Rule: {match['rule']}")
            print(f"    Severity: {match['meta'].get('severity', 'N/A')}")
            print(f"    MITRE ATT&CK: {match['meta'].get('mitre_attack', 'N/A')}")