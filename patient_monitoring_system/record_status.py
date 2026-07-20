"""Canonical patient-record lifecycle values and transition rules."""
from __future__ import annotations


RECORD_STATUSES = (
    'active',
    'archived',
    'entered_in_error',
    'deactivated',
    'voided',
)

RECORD_STATUS_LABELS = {
    'active': 'Active',
    'archived': 'Archived',
    'entered_in_error': 'Entered in Error',
    'deactivated': 'Deactivated',
    'voided': 'Voided',
}

RECORD_STATUS_REASON_CODES = {
    'active': 'record_reactivated',
    'archived': 'record_archived',
    'entered_in_error': 'record_entered_in_error',
    'deactivated': 'record_deactivated',
    'voided': 'record_voided',
}

# Error and void states are intentionally terminal in the normal application.
# Restoring either needs a future, separately approved correction workflow.
_ALLOWED_TRANSITIONS = {
    'active': frozenset({'archived', 'entered_in_error', 'deactivated', 'voided'}),
    'archived': frozenset({'active'}),
    'deactivated': frozenset({'active'}),
    'entered_in_error': frozenset(),
    'voided': frozenset(),
}


def normalize_record_status(value, *, default=None):
    """Return a canonical status, rejecting unrecognised lifecycle values."""
    if value is None or not str(value).strip():
        if default is not None:
            return normalize_record_status(default)
        raise ValueError('A patient-record status is required.')
    key = str(value).strip().casefold().replace('-', '_').replace(' ', '_')
    if key not in RECORD_STATUSES:
        raise ValueError('Invalid patient-record status.')
    return key


def record_status_label(value):
    """Return the safe English display label for a canonical status."""
    status = normalize_record_status(value, default='active')
    return RECORD_STATUS_LABELS[status]


def available_record_status_transitions(current_status):
    """Return valid target statuses in the stable display order."""
    current = normalize_record_status(current_status, default='active')
    allowed = _ALLOWED_TRANSITIONS[current]
    return tuple(status for status in RECORD_STATUSES if status in allowed)


def validate_record_status_transition(current_status, new_status):
    """Validate a lifecycle transition and return its canonical values."""
    current = normalize_record_status(current_status, default='active')
    target = normalize_record_status(new_status)
    if current == target:
        raise ValueError('The record is already in the selected status.')
    if target not in _ALLOWED_TRANSITIONS[current]:
        raise ValueError(
            f'A record cannot move from {record_status_label(current)} '
            f'to {record_status_label(target)} through the normal application.'
        )
    return current, target
