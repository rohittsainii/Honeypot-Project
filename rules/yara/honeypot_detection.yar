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

// Rule 6: Detect DDoS bot signatures
rule DDoS_Bot_Signature {
    meta:
        description = "Detects DDoS bot malware signatures"
        author = "Decoy Defense Team"
        date = "2025-01-01"
        severity = "critical"
        mitre_attack = "T1498" // Network Denial of Service
    
    strings:
        $mirai1 = "mirai" nocase
        $gafgyt = "gafgyt" nocase
        $qbot = "qbot" nocase
        $ddos_cmd1 = "hping3" nocase
        $ddos_cmd2 = "slowloris" nocase
        $flood1 = "syn flood" nocase
        $flood2 = "udp flood" nocase
        $attack_target = "target=" nocase
        
    condition:
        any of ($mirai1, $gafgyt, $qbot) or
        (any of ($ddos_cmd*, $flood*) and $attack_target)
}

// Rule 7: Detect reconnaissance tools
rule Reconnaissance_Tools {
    meta:
        description = "Detects network reconnaissance and scanning tools"
        author = "Decoy Defense Team"
        date = "2025-01-01"
        severity = "medium"
        mitre_attack = "T1046" // Network Service Discovery
    
    strings:
        $nmap = "nmap" nocase
        $masscan = "masscan" nocase
        $zmap = "zmap" nocase
        $netcat = "nc -" nocase
        $telnet = "telnet" nocase
        $ping_sweep = /ping\s+-c\s+\d+/ nocase
        $port_scan = /:\d{1,5}\s/ nocase
        
    condition:
        2 of them
}

// Rule 8: Detect file exfiltration attempts
rule Data_Exfiltration {
    meta:
        description = "Detects data exfiltration commands"
        author = "Decoy Defense Team"
        date = "2025-01-01"
        severity = "high"
        mitre_attack = "T1041" // Exfiltration Over C2 Channel
    
    strings:
        $tar_gz = "tar -czf" nocase
        $zip = "zip -r" nocase
        $scp = "scp " nocase
        $base64 = "base64 " nocase
        $etc_passwd = "/etc/passwd" nocase
        $etc_shadow = "/etc/shadow" nocase
        $ssh_keys = "id_rsa" nocase
        $history = ".bash_history" nocase
        
    condition:
        (any of ($tar_gz, $zip, $scp, $base64)) and
        (any of ($etc_passwd, $etc_shadow, $ssh_keys, $history))
}

// Rule 9: Detect privilege escalation attempts
rule Privilege_Escalation {
    meta:
        description = "Detects common privilege escalation commands"
        author = "Decoy Defense Team"
        date = "2025-01-01"
        severity = "critical"
        mitre_attack = "T1068" // Exploitation for Privilege Escalation
    
    strings:
        $sudo = "sudo " nocase
        $su = "su -" nocase
        $setuid = "chmod 4755" nocase
        $setuid2 = "chmod u+s" nocase
        $passwd_edit = "vi /etc/passwd" nocase
        $shadow_edit = "vi /etc/shadow" nocase
        $sudoers = "/etc/sudoers" nocase
        $exploit = "exploit" nocase
        
    condition:
        2 of them
}

// Rule 10: Detect web shell patterns
rule Web_Shell_Pattern {
    meta:
        description = "Detects common web shell code patterns"
        author = "Decoy Defense Team"
        date = "2025-01-01"
        severity = "critical"
        mitre_attack = "T1505.003" // Server Software Component: Web Shell
    
    strings:
        $php_exec = "<?php" nocase
        $system = "system(" nocase
        $shell_exec = "shell_exec(" nocase
        $passthru = "passthru(" nocase
        $eval = "eval(" nocase
        $base64_decode = "base64_decode(" nocase
        $post = "$_POST" nocase
        $get = "$_GET" nocase
        $request = "$_REQUEST" nocase
        
    condition:
        $php_exec and (any of ($system, $shell_exec, $passthru, $eval)) and
        (any of ($post, $get, $request))
}