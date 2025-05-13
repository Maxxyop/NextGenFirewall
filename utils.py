import os
import logging
import yaml
import fnmatch
import os

def is_path_trusted(process_path, trusted_paths):
    process_path = os.path.normpath(process_path).lower()
    for trusted in trusted_paths:
        trusted = os.path.normpath(trusted).lower()
        if fnmatch.fnmatch(process_path, trusted):
            return True
    return False


def check_privileges():
    """Check if the script is run with administrative/root privileges."""
    try:
        is_admin = os.getuid() == 0
    except AttributeError:
        # Windows fallback
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    if not is_admin:
        print("[ERROR] This script must be run as root or administrator.")
    return is_admin

def setup_logging(level=logging.INFO, log_file=None):
    """
    Sets up logging configuration.

    Args:
        level (int or str): Logging level, either a numeric value or string like 'INFO'.
        log_file (str, optional): Path to log file. If None, logs only to console.

    Returns:
        logger: Configured logger object.
    """
    if isinstance(level, str):
        level = getattr(logging, level.upper(), logging.INFO)
    elif not isinstance(level, int):
        raise ValueError(f"Level not an integer or a valid string: {level}")

    logger = logging.getLogger()
    logger.setLevel(level)

    # Avoid adding duplicate handlers
    if not logger.handlers:
        formatter = logging.Formatter(
            '[%(asctime)s] [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S'
        )

        console = logging.StreamHandler()
        console.setFormatter(formatter)
        logger.addHandler(console)

        if log_file:
            try:
                file_handler = logging.FileHandler(log_file)
                file_handler.setFormatter(formatter)
                logger.addHandler(file_handler)
            except Exception as e:
                logger.error(f"Error setting up file logging: {e}")

    return logger


def load_config(path):
    """Load YAML configuration file."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"Config file not found: {path}")
    
    try:
        with open(path, 'r') as f:
            return yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise ValueError(f"Error parsing YAML file: {e}")
