"""Moved. Provider selection is `uai.connect` and `uai.from_env`; this module keeps `create_provider` working.

`create_provider(environ)` reads UAI2_PROVIDER and UAI2_MODEL (or UAI_PROVIDER and UAI_MODEL) and the selected
provider's key, exactly as `uai.from_env` does, and returns the provider behind the typed contract. It holds no
provider code of its own.
"""

from uai import from_env

__all__ = ["create_provider"]


def create_provider(environ=None):
    """Build the configured provider behind the common typed interface."""
    return from_env(environ).model_provider()
