import pytest


def pytest_configure(config):
    config.addinivalue_line("markers", "functional: mark test as functional (requires real WordPress)")
