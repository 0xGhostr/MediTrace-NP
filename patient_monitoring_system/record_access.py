"""Central patient-record authorization policy.

This module is deliberately independent from Flask and the database layer so
the same allowlist is used by forms, SQL queries, direct routes, and tests.
Record sensitivity is intentionally not part of the authorization decision.
"""
from __future__ import annotations

import re
from collections.abc import Mapping

from config import Config
from record_policy import RESTRICTED_CATEGORY_KEYS, normalize_category


ROLE_DEPARTMENT_MATRIX = {
    'Doctor': ('General Medicine', 'Emergency', 'Psychiatry', 'Infectious Disease'),
    'Nurse': ('General Medicine', 'Emergency', 'Psychiatry', 'Infectious Disease'),
    'Laboratory Staff': ('Laboratory',),
    'Billing Staff': ('Billing',),
    'Receptionist': ('Reception',),
    'Admin': ('Administration',),
    'Super Admin': ('Administration',),
}

PRIVILEGED_ROLES = frozenset({'Admin', 'Super Admin'})
CLINICAL_ROLES = frozenset({'Doctor', 'Nurse'})
RECEPTION_CATEGORY_KEYS = frozenset({
    'reception', 'registration', 'appointment', 'referral-administration',
})
SERVICE_ROLES = frozenset({'Laboratory Staff', 'Billing Staff', 'Receptionist'})
CLINICAL_DETAIL_FIELDS = (
    'primary_condition', 'clinical_notes', 'medication_or_treatment',
    'relevant_observations', 'heart_rate', 'blood_pressure', 'temperature',
    'oxygen_saturation', 'attending_doctor',
)


def _key(value):
    value = str(value or '').strip().casefold().replace('_', ' ')
    value = re.sub(r'[\s-]+', ' ', value)
    return value


_ROLE_ALIASES = {
    'doctor': 'Doctor',
    'nurse': 'Nurse',
    'receptionist': 'Receptionist',
    'billing staff': 'Billing Staff',
    'laboratory staff': 'Laboratory Staff',
    'admin': 'Admin',
    'super admin': 'Super Admin',
    'superadmin': 'Super Admin',
}
_DEPARTMENT_ALIASES = {
    _key(department): department for department in Config.DEPARTMENTS
}


def normalize_role(value):
    """Return a canonical known role, or ``None`` for an unknown value."""
    return _ROLE_ALIASES.get(_key(value))


def normalize_department(value):
    """Return a canonical known department, or ``None`` for an unknown value."""
    return _DEPARTMENT_ALIASES.get(_key(value))


def normalize_record_category(value):
    """Return the stable explicit category key used by policy comparisons."""
    return normalize_category(value)


def departments_for_role(role, *, public_only=False):
    """Return valid canonical departments for a known role."""
    canonical_role = normalize_role(role)
    if public_only and canonical_role not in Config.STAFF_REGISTER_ROLES:
        return ()
    return ROLE_DEPARTMENT_MATRIX.get(canonical_role, ())


def validate_role_department(role, department, *, public_only=False):
    """Validate an exact role/department pairing against the central matrix."""
    canonical_role = normalize_role(role)
    canonical_department = normalize_department(department)
    if not canonical_role or not canonical_department:
        return False
    if public_only and canonical_role not in Config.STAFF_REGISTER_ROLES:
        return False
    return canonical_department in ROLE_DEPARTMENT_MATRIX.get(canonical_role, ())


def _value(subject, name, default=None):
    if subject is None:
        return default
    if isinstance(subject, Mapping):
        return subject.get(name, default)
    return getattr(subject, name, default)


def _account_is_authorized(user):
    approved = str(_value(user, 'approval_status', '') or '').strip().casefold() == 'approved'
    active = bool(_value(user, 'is_active_account', _value(user, 'is_active', False)))
    deleted = bool(_value(user, 'is_deleted', False))
    return approved and active and not deleted


def _view_decision(user, record):
    role = normalize_role(_value(user, 'role'))
    department = normalize_department(_value(user, 'department'))
    if not _account_is_authorized(user):
        return False, 'account_not_authorized'
    if not validate_role_department(role, department):
        return False, 'invalid_role_department_assignment'
    if record is None:
        return False, 'record_not_found'
    if role in PRIVILEGED_ROLES:
        reason = 'privileged_superadmin_view' if role == 'Super Admin' else 'privileged_admin_view'
        return True, reason

    record_status = str(_value(record, 'record_status', '') or '').strip().casefold()
    if not record_status:
        record_status = 'active' if bool(_value(record, 'is_active', True)) else 'deactivated'
    if record_status != 'active':
        return False, 'record_not_active'

    record_department = normalize_department(_value(record, 'department'))
    category = normalize_record_category(_value(record, 'record_category'))
    if role in CLINICAL_ROLES:
        if department != record_department:
            return False, 'clinical_department_mismatch'
        if category in RESTRICTED_CATEGORY_KEYS:
            specialized_category = {
                'Psychiatry': 'psychiatric',
                'Infectious Disease': 'hiv-related',
            }.get(department)
            restricted_allowed = (
                category == specialized_category
                or (role == 'Doctor' and category == 'confidential')
            )
            if not restricted_allowed:
                return False, 'restricted_record_denied'
        return True, 'clinical_department_match'
    if role == 'Laboratory Staff':
        return (
            (True, 'laboratory_category_access') if category == 'laboratory'
            else (False, 'laboratory_scope_denied')
        )
    if role == 'Billing Staff':
        return (
            (True, 'billing_category_access') if category == 'billing'
            else (False, 'billing_scope_denied')
        )
    if role == 'Receptionist':
        if record_department == 'Reception' or category in RECEPTION_CATEGORY_KEYS:
            return True, 'reception_scope_access'
        return False, 'reception_scope_denied'
    return False, 'role_not_authorized'


def get_access_policy_reason(user, record, action='view'):
    """Return a safe reason code for an allowed or denied record action."""
    view_allowed, view_reason = _view_decision(user, record)
    if action == 'delete':
        return 'permanent_delete_not_permitted'
    if action == 'view' or not view_allowed:
        return view_reason
    role = normalize_role(_value(user, 'role'))
    category = normalize_record_category(_value(record, 'record_category'))
    if action == 'export':
        if role in PRIVILEGED_ROLES:
            return view_reason
        existing_export_categories = Config.ROLE_ACCESS.get(role) or ()
        existing_keys = {normalize_record_category(item) for item in existing_export_categories}
        if role == 'Receptionist' or category not in existing_keys:
            return 'export_not_permitted'
        return view_reason
    if action == 'edit':
        return view_reason if role in PRIVILEGED_ROLES else 'edit_not_permitted'
    if action == 'status':
        return view_reason if role in PRIVILEGED_ROLES else 'unauthorized_record_status_attempt'
    return 'action_not_permitted'


def can_view_record(user, record):
    return _view_decision(user, record)[0]


def can_export_record(user, record):
    return get_access_policy_reason(user, record, 'export') != 'export_not_permitted' and can_view_record(user, record)


def can_edit_record(user, record):
    return can_view_record(user, record) and normalize_role(_value(user, 'role')) in PRIVILEGED_ROLES


def can_delete_record(user, record):
    """Permanent patient-record deletion is unavailable to every role."""
    return False


def can_change_record_status(user, record):
    """Only approved Admin/Super Admin accounts may use lifecycle actions."""
    return can_view_record(user, record) and normalize_role(_value(user, 'role')) in PRIVILEGED_ROLES


def record_for_display(user, record):
    """Return a safe projection for non-clinical service roles.

    The prototype has no separate service payload columns, so the service
    record's content remains available while unrelated structured clinical
    narrative and vital signs are withheld.
    """
    result = dict(record)
    if normalize_role(_value(user, 'role')) in SERVICE_ROLES:
        for field in CLINICAL_DETAIL_FIELDS:
            if field in result:
                result[field] = None
        result['service_scope_limited'] = True
    else:
        result['service_scope_limited'] = False
    return result


def authorized_record_predicate(user, table_alias=None):
    """Return an SQL predicate and parameters for the user's view scope."""
    prefix = f'{table_alias}.' if table_alias else ''
    if not _account_is_authorized(user) or not validate_role_department(
            _value(user, 'role'), _value(user, 'department')):
        return '1 = 0', []

    role = normalize_role(_value(user, 'role'))
    department = normalize_department(_value(user, 'department'))
    if role in PRIVILEGED_ROLES:
        return '1 = 1', []

    department_expr = (
        f"LOWER(REPLACE(REPLACE(TRIM({prefix}department), '_', '-'), ' ', '-'))"
    )
    category_expr = (
        f"LOWER(REPLACE(REPLACE(TRIM({prefix}record_category), '_', '-'), ' ', '-'))"
    )
    if role in CLINICAL_ROLES:
        allowed_restricted = []
        specialized_category = {
            'Psychiatry': 'psychiatric',
            'Infectious Disease': 'hiv-related',
        }.get(department)
        if specialized_category:
            allowed_restricted.append(specialized_category)
        if role == 'Doctor':
            allowed_restricted.append('confidential')
        restricted_keys = sorted(RESTRICTED_CATEGORY_KEYS)
        restricted_placeholders = ','.join('?' for _ in restricted_keys)
        if allowed_restricted:
            allowed_placeholders = ','.join('?' for _ in allowed_restricted)
            restricted_sql = (
                f'({category_expr} NOT IN ({restricted_placeholders}) '
                f'OR {category_expr} IN ({allowed_placeholders}))'
            )
        else:
            restricted_sql = f'{category_expr} NOT IN ({restricted_placeholders})'
        return (
            f'({department_expr} = ? AND {restricted_sql})',
            [normalize_category(department), *restricted_keys, *allowed_restricted],
        )
    if role == 'Laboratory Staff':
        return f'{category_expr} = ?', ['laboratory']
    if role == 'Billing Staff':
        return f'{category_expr} = ?', ['billing']
    if role == 'Receptionist':
        keys = sorted(RECEPTION_CATEGORY_KEYS)
        placeholders = ','.join('?' for _ in keys)
        return (
            f'({department_expr} = ? OR {category_expr} IN ({placeholders}))',
            [normalize_category('Reception'), *keys],
        )
    return '1 = 0', []


def role_department_choices(*, public_only=False):
    roles = Config.STAFF_REGISTER_ROLES if public_only else Config.ROLES
    return {role: list(departments_for_role(role, public_only=public_only)) for role in roles}
