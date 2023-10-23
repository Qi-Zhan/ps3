import logging

def get_logger(name):
    logger = logging.getLogger(name)
    if not logger.handlers:
        # Prevent logging from propagating to the root logger
        logger.propagate = 0
        console = logging.StreamHandler()
        logger.addHandler(console)
        formatter = logging.Formatter('%(levelname)s [%(filename)s:%(lineno)d] %(message)s')
        console.setFormatter(formatter)
    return logger

INFO = logging.INFO
DEBUG = logging.DEBUG
ERROR = logging.ERROR
FATAL = logging.FATAL
