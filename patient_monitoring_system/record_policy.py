"""Canonical patient-record sensitivity and restriction policy helpers."""
from __future__ import annotations

import re
from collections.abc import Mapping


CANONICAL_SENSITIVITIES = ('Low', 'Medium', 'High', 'Critical')
_SENSITIVITY_BY_KEY = {value.lower(): value for value in CANONICAL_SENSITIVITIES}

# These categories carry an inherently restricted healthcare classification.
# Authorization remains a separate role/category decision.
RESTRICTED_CATEGORY_KEYS = frozenset({
    'confidential',
    'hiv-related',
    'psychiatric',
})


def normalize_sensitivity(value, *, required=True):
    """Return the project's canonical sensitivity label or reject the value."""
    raw = str(value or '').strip()
    if not raw:
        if required:
            raise ValueError('Sensitivity is required.')
        return None
    canonical = _SENSITIVITY_BY_KEY.get(raw.casefold())
    if canonical is None:
        supported = ', '.join(CANONICAL_SENSITIVITIES)
        raise ValueError(f'Unsupported sensitivity. Choose one of: {supported}.')
    return canonical


def sensitivity_key(value):
    """Return a stable lowercase key for styling and comparisons."""
    try:
        canonical = normalize_sensitivity(value, required=False)
    except ValueError:
        return 'unknown'
    return canonical.lower() if canonical else 'unknown'


def sensitivity_display(value):
    """Return the canonical English display label without changing meaning."""
    try:
        canonical = normalize_sensitivity(value, required=False)
    except ValueError:
        canonical = None
    return canonical or str(value or '').strip() or 'Unknown'


def normalize_category(value):
    """Normalize category spelling for policy comparisons only."""
    normalized = str(value or '').strip().casefold().replace('_', '-').replace('–', '-')
    normalized = re.sub(r'[\s-]+', '-', normalized)
    return normalized.strip('-')


def _record_value(record, key):
    if record is None:
        return None
    if isinstance(record, Mapping):
        return record.get(key)
    try:
        return record[key]
    except (KeyError, IndexError, TypeError):
        return getattr(record, key, None)


def _as_explicit_boolean(value):
    if value is None:
        return None
    if isinstance(value, str):
        key = value.strip().casefold()
        if key in {'1', 'true', 'yes', 'restricted'}:
            return True
        if key in {'0', 'false', 'no', 'standard', 'unrestricted'}:
            return False
    return bool(value)


def is_restricted_record(record):
    """Classify a record independently from the current user's authorization."""
    for field in ('is_restricted', 'restricted'):
        explicit = _as_explicit_boolean(_record_value(record, field))
        if explicit is not None:
            return explicit
    classification = _record_value(record, 'access_classification')
    if classification is not None:
        return normalize_category(classification) == 'restricted'
    category = record if isinstance(record, str) else _record_value(record, 'record_category')
    return normalize_category(category) in RESTRICTED_CATEGORY_KEYS
