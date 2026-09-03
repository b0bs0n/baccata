"""Baccata — a KNX project editor and commissioning tool."""
try:
    from importlib.metadata import version as _pkg_version
    __version__ = _pkg_version('baccata')
except Exception:
    __version__ = 'dev'
