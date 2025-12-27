# modules/logging/logger.py

import logging
from logging.handlers import RotatingFileHandler
import os

# ----------------------------------------------------------
# Log file path
# ----------------------------------------------------------
LOG_DIR = "logs"

if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

LOG_FILE = os.path.join(LOG_DIR, "application.log")

# ----------------------------------------------------------
# Configure logger
# ----------------------------------------------------------
logger = logging.getLogger("secure_logger")
logger.setLevel(logging.INFO)

# Prevent duplicate handlers when imported multiple times
if not logger.handlers:

    handler = RotatingFileHandler(
        LOG_FILE,
        maxBytes=1000000,  # 1 MB
        backupCount=5
    )

    formatter = logging.Formatter(
        fmt="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    handler.setFormatter(formatter)
    logger.addHandler(handler)


# ----------------------------------------------------------
# Safe log functions
# ----------------------------------------------------------

def log_info(message: str):
    """Info messages (no sensitive info allowed)"""
    logger.info(message)


def log_warning(message: str):
    logger.warning(message)


def log_error(message: str):
    logger.error(message)


def log_security_event(message: str):
    """
    Used for security-relevant events:
    - login success/failure
    - lockout
    - suspicious input
    - encryption usage
    """
    logger.info(f"[SECURITY] {message}")
