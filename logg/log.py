import logging
import datetime
import os

def setup():
    today = datetime.datetime.today()
    if not os.path.exists("logs"):
        os.makedirs("logs")
    filename = f"{today.month:02d}-{today.day:02d}-{today.year}"
    
    logging.basicConfig(
        level=logging.DEBUG,
        handlers=[
            logging.FileHandler(filename)
        ]
    )

def log(logger_name, method, message):
    logger = logging.getLogger(logger_name)

    if hasattr(logger, method) and callable(getattr(logger, method)):
        log_method = getattr(logger, method)
        log_method(message)
    else:
        logger.error(f"Invalid logging method provided: {method}")