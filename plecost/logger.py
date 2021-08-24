from plecost.interfaces import Singleton

import logging

class _Logger(metaclass=Singleton):

    def __init__(self):
        self._logger = logging.getLogger("plecost")

    def debug(self, message: str):
        self._logger.debug(message)

    def info(self, message: str):
        self._logger.info(message)

    def warning(self, message: str):
        self._logger.warning(message)

    def error(self, message: str):
        self._logger.error(message)

    def critical(self, message: str):
        self._logger.critical(message)

    def config_from_cli(self, level: int):
        _level = level * 10

        if _level >= 50:
            _level = 40

        if _level < 0:
            _level = 0

        self._logger.setLevel(abs(50 - _level))

        # create console handler and set level to debug
        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG)

        # create formatter
        # formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        formatter = logging.Formatter('[ %(asctime)s ] %(levelname)s - %(message)s')

        # add formatter to ch
        ch.setFormatter(formatter)

        # add ch to logger
        self._logger.addHandler(ch)


Logger = _Logger()
