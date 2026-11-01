"""Errors raised while fetching from a source."""

from __future__ import annotations


class FetchError(RuntimeError):
    pass


class EgressBlocked(FetchError):
    pass
