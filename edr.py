import logging
import psutil
import time
import os
import fnmatch
import threading
from modules.utils import setup_logging
from modules.utils import is_path_trusted

class LinuxEDR(threading.Thread):
    def __init__(self, config, alert_callback):
        super().__init__()
        self.config = config
        self.alert_callback = alert_callback
        self._stop_event = threading.Event()

        # Extract configuration values for EDR
        edr_config = config.get("edr", {})
        self.cpu_threshold = edr_config.get("cpu_threshold", 50.0)
        self.mem_threshold = edr_config.get("memory_threshold", 200 * 1024 * 1024)

        self.trusted_apps = [app.lower() for app in edr_config.get("trusted_applications", [])]
        self.trusted_paths = [path.lower() for path in edr_config.get("trusted_paths", [])]

        # Set up logging based on the log level from config.yaml
        log_level = edr_config.get("log_level", "INFO")
        self.logger = setup_logging(log_level)
        self.logger.name = "EDR"

    def run(self):
        while not self._stop_event.is_set():
            self.logger.debug("Scanning for endpoint anomalies...")
            self.detect_anomalies()
            time.sleep(3)  # Delay between checks

    def detect_anomalies(self):
        suspicious_keywords = ["mimikatz", "keylogger", "powersploit", "metasploit", "dump", "shadow", "rundll32"]
        trusted_paths = self.config.get("trusted_paths", [])

        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info', 'cmdline', 'ppid', 'exe']):
            try:
                name = proc.info['name']
                exe_path = (proc.info.get('exe') or "").lower()
                cpu = proc.cpu_percent(interval=0.1)  # Short delay to get CPU percentage

                # Safely get memory_info, set default to 0 if not available
                memory_info = proc.info.get('memory_info', None)
                mem = memory_info.rss if memory_info else 0  # Use 0 if memory_info is None

                cmdline = ' '.join(proc.info.get('cmdline') or []).lower()
                ppid = proc.info['ppid']
                parent = psutil.Process(ppid).name().lower() if psutil.pid_exists(ppid) else "N/A"

                if self.is_whitelisted(name, exe_path):
                    continue  # Skip trusted apps

                # Check for high CPU usage
                if cpu > self.cpu_threshold:
                    self.alert("high_cpu_usage", name, f"{cpu}%")

                # Check for high memory usage
                if mem > self.mem_threshold:
                    self.alert("high_memory_usage", name, f"{mem} bytes")

                # Check for suspicious commands
                if any(kw in cmdline for kw in suspicious_keywords):
                    self.alert("suspicious_command", name, cmdline)

                # Check for unusual parent-child process relationship (e.g., PowerShell from Word or Excel)
                if "powershell" in name.lower() and parent in ["winword.exe", "excel.exe"]:
                    self.alert("unusual_parent", name, f"{parent} -> {name}")

            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                self.logger.error(f"Error processing {name}: {e}")
                continue

    def is_whitelisted(self, process_name, exe_path):
        process_name = process_name.lower()
        exe_path = exe_path.lower()

        # Check trusted applications
        if process_name in self.trusted_apps:
            return True

        # Check trusted paths with wildcard support
        for trusted_path in self.trusted_paths:
            if "*" in trusted_path:
                base = trusted_path.replace("\\", "/").lower()
                exe_path_norm = exe_path.replace("\\", "/").lower()
                if fnmatch.fnmatch(exe_path_norm, base):
                    return True
            else:
                if exe_path.startswith(trusted_path):
                    return True
        return False

    def alert(self, anomaly_type, proc_name, details):
        self.logger.warning(f"[{anomaly_type}] Detected in process: {proc_name} - Details: {details}")
        self.alert_callback({
            "module": "EDR",
            "event": "process_anomaly_detected",
            "type": anomaly_type,
            "process": proc_name,
            "details": str(details)
        })

    def stop(self):
        self._stop_event.set()
        self.logger.info("EDR module stopping.")

