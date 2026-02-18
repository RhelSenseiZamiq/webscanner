"""Tests for structured logging setup."""

import logging

from webscanner.core.logging import setup_logging


class TestSetupLogging:
    def test_default_level(self) -> None:
        logger = setup_logging(verbose=False)
        assert logger.level == logging.INFO

    def test_verbose_level(self) -> None:
        logger = setup_logging(verbose=True)
        assert logger.level == logging.DEBUG

    def test_has_handler(self) -> None:
        logger = setup_logging()
        assert len(logger.handlers) >= 1

    def test_idempotent(self) -> None:
        logger1 = setup_logging()
        handler_count = len(logger1.handlers)
        logger2 = setup_logging()
        assert len(logger2.handlers) == handler_count
