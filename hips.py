import threading
import logging
import psutil
import os
import shutil
import time
import hashlib
import fnmatch
from modules.utils import setup_logging
from modules.utils import is_path_trusted


def is_trusted_path(path, trusted_paths):
    path = os.path.normcase(os.path.normpath(path))  # normalize and lowercase
    for trusted in trusted_paths:
        normalized_trusted = os.path.normcase(os.path.normpath(trusted.replace('*', '')))
        if '*' in trusted:
            if fnmatch.fnmatch(path, os.path.normcase(trusted)):
                return True
        elif path.startswith(normalized_trusted):
            return True
    return False


class HIPS(threading.Thread):
    def __init__(self, config, alert_callback):
        super().__init__()
        self.config = config
        self.alert_callback = alert_callback
        self._stop_event = threading.Event()

        # Extract HIPS and EDR configuration
        hips_config = config.get("hips", {})
        self.log_enabled = hips_config.get("logging_enabled", True)
        self.blocking_enabled = hips_config.get("blocking_enabled", True)
        self.quarantine_enabled = hips_config.get("quarantine_enabled", True)
        self.quarantine_dir = hips_config.get("quarantine_directory", "quarantined")
        self.packet_threshold = hips_config.get("packet_threshold", 1024)

        edr_config = config.get("edr", {})
        self.trusted_apps = [app.lower() for app in edr_config.get("trusted_applications", [])]
        self.trusted_paths = [path.lower() for path in edr_config.get("trusted_paths", [])]

        # Configure logger based on config file's log_level
        log_level = hips_config.get("log_level", "INFO")
        self.logger = setup_logging(log_level)
        self.logger.name = "HIPS"

        # Ensure quarantine directory exists
        if self.quarantine_enabled:
            os.makedirs(self.quarantine_dir, exist_ok=True)

    def run(self):
        while not self._stop_event.is_set():
            self.logger.debug("Checking for suspicious system calls...")

            if self.is_suspicious():
                self.logger.warning("Suspicious system call detected!")
                self.alert_callback({
                    "module": "HIPS",
                    "event": "unauthorized_syscall_detected"
                })

                if self.blocking_enabled:
                    self.logger.info("Blocking suspicious activity...")
                    self.block_suspicious_activity()

                if self.quarantine_enabled:
                    self.logger.info("Quarantining suspicious files/processes...")
                    self.quarantine_files()

            time.sleep(2)

    def is_suspicious(self):
        suspicious_keywords = ["mimikatz", "keylogger", "meterpreter", "powersploit", "metasploit", "ransom"]
        suspicious_dirs = ["temp", "appdata", "downloads"]

        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
            try:
                name = proc.info.get('name', '').lower()
                cmdline_list = proc.info.get('cmdline') or []
                cmdline = ' '.join(cmdline_list).lower()
                exe = proc.info.get('exe', '')

                if exe and isinstance(exe, str):
                    exe = exe.lower()
                else:
                    exe = ""

                if self.is_whitelisted(name, exe):
                    self.logger.debug(f"Skipping whitelisted process: {name} at {exe}")
                    continue

                if any(kw in cmdline for kw in suspicious_keywords):
                    self.logger.warning(f"Suspicious command detected: {cmdline}")
                    self._suspicious_proc = proc
                    return True

                if any(sdir in exe for sdir in suspicious_dirs):
                    self.logger.warning(f"Process running from suspicious location: {exe}")
                    self._suspicious_proc = proc
                    return True

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return False

    def is_whitelisted(self, process_name, exe_path):
        """Check if the process or executable is whitelisted."""
        if process_name in self.trusted_apps:
            return True

        if is_path_trusted(exe_path, self.trusted_paths):
            return True

        return False

    def block_suspicious_activity(self):
        """Terminate suspicious process if found."""
        try:
            proc = getattr(self, "_suspicious_proc", None)
            if proc:
                proc.kill()
                self.logger.info(f"Terminated suspicious process: {proc.pid}")
        except Exception as e:
            self.logger.error(f"Failed to block suspicious process: {str(e)}")

    def quarantine_files(self):
        """Quarantine suspicious files."""
        try:
            proc = getattr(self, "_suspicious_proc", None)
            if proc and proc.exe():
                filename = os.path.basename(proc.exe())
                quarantine_path = os.path.join(self.quarantine_dir, filename)

                # Handle locked files or permission issues when copying
                if os.path.exists(proc.exe()):
                    shutil.copy(proc.exe(), quarantine_path)
                    self.logger.info(f"Copied file to quarantine: {quarantine_path}")
                else:
                    self.logger.warning(f"File not found for quarantine: {proc.exe()}")
        except Exception as e:
            self.logger.error(f"Failed to quarantine file: {str(e)}")

    def get_file_hash(self, file_path):
        """Get the SHA-256 hash of a file."""
        hash_sha256 = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                while chunk := f.read(8192):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception:
            return None

    def stop(self):
        """Stop the HIPS thread and associated processes."""
        self._stop_event.set()
        self.logger.info("HIPS module stopping.")
