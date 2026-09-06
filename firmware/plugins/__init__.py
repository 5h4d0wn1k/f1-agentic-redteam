"""Built-in campaign plugins (offline echo demos + external-tool adapters)."""

from .base import PhasePlugin
from .registry import all_plugins, get_plugin, register


def discover():
    from . import demo, external  # noqa: F401


discover()

__all__ = ["PhasePlugin", "register", "get_plugin", "all_plugins"]