import threading
import time
import logging
from scapy.all import sniff, Raw
import re
from modules.utils import setup_logging

class DeepPacketInspector(threading.Thread):
    def __init__(self, config, alert_callback):
        super().__init__()
        self.config = config.get("dpi", {})
        self.alert_callback = alert_callback
        self._stop_event = threading.Event()
        self.enabled = self.config.get("enabled", True)

        # Configure logging based on log_level from config
        log_level = self.config.get("log_level", "INFO")
        self.logger = setup_logging(log_level)
        self.logger.name = "DPI"

        # Precompile suspicious keywords regex for better performance
        self.suspicious_keywords = [
            "virus", "worm", "trojan", "spyware", "adware", "ransomware", "rootkit",
            "botnet", "phishing", "backdoor", "ddos", "xss", "sql injection", "mitm",
            "keylogger", "exploit", "payload", "malware", "dropper", "command and control",
            "c2 server", "credential stuffing", "brute force", "zero-day", "obfuscation",
            "shellcode", "remote access", "unauthorized access", "data exfiltration",
            "privilege escalation", "session hijacking", "drive-by download", "spybot",
            "keystroke logger", "packet sniffer", "dns poisoning", "arp spoofing",
            "session fixation", "clickjacking", "buffer overflow", "heap spraying",
            "format string attack", "directory traversal", "code injection", "csrf",
            "dll injection", "man-in-the-middle", "ping of death", "smurf attack",
            "teardrop attack", "land attack", "fraggle attack", "ip spoofing",
            "mac spoofing", "tcp reset attack", "icmp flood", "syn flood", "udp flood",
            "slowloris", "nmap", "metasploit", "beef", "sqlmap", "hydra", "john the ripper",
            "aircrack-ng", "wireshark", "ettercap", "malicious", "attack", "compromise",
            "breach", "unauthorized", "hack", "exploit", "vulnerability", "threat",
            "infected", "reverse shell", "bind shell", "remote code execution",
            "denial of service", "distributed denial of service", "cross-site scripting",
            "command injection", "evil twin", "rogue access point", "zip bomb",
            "email bomb", "fork bomb", "logic bomb", "scareware", "fileless malware",
            "polymorphic malware", "metamorphic malware", "watering hole attack",
            "dns spoofing", "bios attack", "uefi attack", "bluejacking", "bluesnarfing",
            "war driving", "supply chain attack", "advanced persistent threat"
        ]
        self.suspicious_keywords_re = re.compile(r"\b(" + "|".join(map(re.escape, self.suspicious_keywords)) + r")\b", re.IGNORECASE)

    def run(self):
        if not self.enabled:
            self.logger.info("DPI module is disabled in config. Skipping packet inspection.")
            return
        self.logger.info("DPI module started. Listening for packets...")
        sniff(prn=self.inspect_packet, store=False, stop_filter=self.should_stop)

    def inspect_packet(self, packet):
        if packet.haslayer(Raw):
            try:
                payload = packet[Raw].load.decode(errors="ignore")
                matched_keyword = self.contains_malicious_signature(payload)
                if matched_keyword:
                    self.logger.info(f"Suspicious keyword detected: {matched_keyword}")
                    self.alert_callback({
                        "module": "DPI",
                        "event": "suspicious_packet_detected",
                        "keyword": matched_keyword,
                        "payload": payload[:100],  # limit payload log to first 100 chars
                        "src_ip": packet[0][1].src,
                        "dst_ip": packet[0][1].dst,
                        "protocol": packet[0][1].proto
                    })
            except Exception as e:
                self.logger.warning(f"Error decoding packet payload: {e}")

    def contains_malicious_signature(self, data):
        if self.suspicious_keywords_re.search(data):
            return self.suspicious_keywords_re.search(data).group(0)
        return None

    def should_stop(self, packet):
        return self._stop_event.is_set()

    def stop(self):
        self._stop_event.set()
        self.logger.info("DPI module stopping.")
        time.sleep(1)  # Allow time to finish processing the last few packets

