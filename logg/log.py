import logging
import datetime
import os
from logging.handlers import TimedRotatingFileHandler
import time

def setup():
    if not os.path.exists("logs"):
        os.makedirs("logs")
    log_file = os.path.join("logs", "current.log")

    log_rotation_handler = TimedRotatingFileHandler(
        log_file,
        when="midnight",
        interval=1,
        backupCount=7
    )
    logging.Formatter.converter = time.gmtime
    log_formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    log_rotation_handler.setLevel(logging.DEBUG)
    log_rotation_handler.setFormatter(log_formatter)
    logging.basicConfig(
        level=logging.DEBUG,
        handlers=[
            log_rotation_handler
        ]
    )

def log(logger_name, method, message):
    logger = logging.getLogger(logger_name)

    if hasattr(logger, method) and callable(getattr(logger, method)):
        log_method = getattr(logger, method)
        log_method(message)
    else:
        logger.error(f"Invalid logging method provided: {method}")