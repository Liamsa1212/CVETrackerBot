"""Structured logging setup using Loguru with standard library logging interception."""

import logging
import sys
from loguru import logger
from cve_tracker.core.config import Settings


class InterceptHandler(logging.Handler):
    """Intercept standard logging messages and redirect them to loguru."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            level = logger.level(record.levelname).name
        except ValueError:
            level = record.levelno

        frame, depth = logging.currentframe(), 2
        while frame and frame.f_code.co_filename == logging.__file__:
            frame = frame.f_back
            depth += 1

        logger.opt(depth=depth, exception=record.exc_info).log(
            level, record.getMessage()
        )


def setup_logging(settings: Settings) -> None:
    """Configure Loguru and redirect standard library loggers."""
    logger.remove()

    if settings.log_json:
        logger.add(
            sys.stdout,
            level=settings.log_level.upper(),
            serialize=True,
        )
    else:
        log_format = (
            "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{name}</cyan>:<cyan>{line}</cyan> - "
            "<level>{message}</level>"
        )
        logger.add(
            sys.stdout,
            level=settings.log_level.upper(),
            format=log_format,
            colorize=True,
        )

    # Intercept root logger and common noisy libraries
    logging.basicConfig(handlers=[InterceptHandler()], level=0, force=True)
    for lib in ("httpx", "httpcore", "telegram", "sqlalchemy.engine", "asyncio"):
        logging.getLogger(lib).handlers = [InterceptHandler()]
        logging.getLogger(lib).propagate = False
