/*
   YARA Rules for Honeypot-Based Threat Intelligence
   Project: Decoy Defense
   Description: Rules to detect malicious files, scripts, and payloads captured by the honeypot
*/

// Rule 1: Detect common Linux malware downloaders
rule Linux_Malware_Downloader {
    meta:
        description = "Detects common wget/curl download commands used by attackers"
        author = "Decoy Defense Team"
        date = "2025-01-01"
        severity = "high"
        mitre_attack = "T1105" // Ingress Tool Transfer
    
    strings:
        $wget1 = "wget http" nocase
        $wget2 = "wget https" nocase
        $curl1 = "curl -O" nocase
        $curl2 = "curl http" nocase
        $chmod = "chmod +x" nocase
        $bash_exec = "/bin/bash" nocase
        
    condition:
        (any of ($wget*, $curl*)) and ($chmod or $bash_exec)
}

// Rule 2: Detect cryptocurrency miners
rule Crypto_Miner_Detection {
    meta:
        description = "Detects cryptocurrency mining software and commands"
        author = "Decoy Defense Team"
        date = "2025-01-01"
        severity = "critical"
        mitre_attack = "T1496" // Resource Hijacking
    
    strings:
        $xmrig1 = "xmrig" nocase
        $xmrig2 = "monero" nocase
        $pool1 = "pool.minergate.com" nocase
        $pool2 = "pool.supportxmr.com" nocase
        $pool3 = "xmr-" nocase
        $stratum = "stratum+tcp://" nocase
        $algo = "--algo=" nocase
        $donate = "--donate-level" nocase
        
    condition:
        2 of them
}

// Rule 3: Detect reverse shell patterns
rule Reverse_Shell_Pattern {
    meta:
        description = "Detects common reverse shell commands"
        author = "Decoy Defense Team"
        date = "2025-01-01"
        severity = "critical"
        mitre_attack = "T1059.004" // Unix Shell
    
    strings:
        $nc_reverse = /nc\s+-[a-z]*e\s+\/bin\/(ba)?sh/ nocase
        $bash_tcp = "/dev/tcp/" nocase
        $perl_shell = "perl -e" nocase
        $python_shell = "python -c" nocase
        $socket = "socket.socket" nocase
        $subprocess = "subprocess.call" nocase
        $exec_bin = "exec(\"/bin" nocase
        
    condition:
        any of them
}

// Rule 4: Detect SSH brute force scripts
rule SSH_Bruteforce_Script {
    meta:
        description = "Detects SSH brute force automation scripts"
        author = "Decoy Defense Team"
        date = "2025-01-01"
        severity = "high"
        mitre_attack = "T1110.001" // Brute Force: Password Guessing
    
    strings:
        $ssh_scan1 = "masscan" nocase
        $ssh_scan2 = "hydra" nocase
        $ssh_scan3 = "medusa" nocase
        $ssh_scan4 = "ncrack" nocase
        $wordlist = "wordlist" nocase
        $password_file = "passwords.txt" nocase
        $user_file = "users.txt" nocase
        $port_22 = ":22" nocase
        
    condition:
        any of ($ssh_scan*) or (2 of ($wordlist, $password_file, $user_file) and $port_22)
}

// Rule 5: Detect backdoor installation
rule Backdoor_Installation {
    meta:
        description = "Detects commands used to install persistent backdoors"
        author = "Decoy Defense Team"
        date = "2025-01-01"
        severity = "critical"
        mitre_attack = "T1053.003" // Scheduled Task/Job: Cron
    
    strings:
        $cron1 = "* * * * *" nocase
        $crontab = "crontab -" nocase
        $rc_local = "/etc/rc.local" nocase
        $systemd = "/etc/systemd/system/" nocase
        $bashrc = ".bashrc" nocase
        $profile = ".profile" nocase
        $ssh_key = "authorized_keys" nocase
        $wget_cron = "wget" nocase
        $curl_cron = "curl" nocase
        
    condition:
        ($cron1 or $crontab) and (any of ($wget_cron, $curl_cron)) or
        (any of ($rc_local, $systemd, $bashrc, $profile)) and $ssh_key
}
