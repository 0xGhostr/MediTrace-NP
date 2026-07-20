"""Secure public recovery intake and administrator credential workflows.

Public requests are support tickets only: this module never changes credentials
from public input. Credential mutations require an authenticated administrator,
an authorized target, and (for request-based changes) a verified-identity state.
"""
import re
import secrets
from datetime import datetime, timedelta

from werkzeug.security import generate_password_hash

from config import Config
from database import get_db
from record_access import normalize_department, normalize_role, validate_role_department


REQUEST_TYPES = {
    'forgot_username': 'Forgot username',
    'forgot_password': 'Forgot password',
    'forgot_both': 'Forgot both username and password',
}
DESTINATIONS = {
    'administrator': 'Administrator Support',
    'super_administrator': 'Super Administrator Support',
}
RECOVERY_STATUSES = ('pending', 'in_review', 'identity_verified', 'completed', 'rejected')
OPEN_STATUSES = ('pending', 'in_review', 'identity_verified')
VERIFICATION_METHODS = {
    'in_person': 'In-person institutional identification',
    'hr_record': 'Human Resources record verification',
    'supervisor_confirmation': 'Department supervisor confirmation',
    'institutional_email': 'Approved institutional email process',
    'other_approved': 'Other institution-approved method',
}
RESOLUTION_TYPES = {
    'username_recovered': 'Existing username recovered',
    'username_updated': 'Username updated',
    'password_reset': 'Password reset with temporary password',
    'both_recovered': 'Existing username recovered and password reset',
    'both_updated': 'Username updated and password reset',
}
ALLOWED_RESOLUTIONS = {
    'forgot_username': {'username_recovered', 'username_updated'},
    'forgot_password': {'password_reset'},
    'forgot_both': {'both_recovered', 'both_updated'},
}

USERNAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{2,49}$')
TIME_RE = re.compile(r'^(?:[01]\d|2[0-3]):[0-5]\d$')


def _actor_dict(actor):
    return getattr(actor, '_raw', actor) or {}


def _single_line(value, max_length):
    return ' '.join(str(value or '').strip().split())[:max_length]


def _message(value, max_length):
    text = str(value or '').replace('\r\n', '\n').replace('\r', '\n').strip()
    return text[:max_length]


def normalize_staff_id(value):
    return _single_line(value, 20).upper()


def normalize_username(value):
    return _single_line(value, 50)


def validate_username(value):
    username = normalize_username(value)
    if not USERNAME_RE.fullmatch(username):
        return None, (
            'Username must be 3–50 characters and use only letters, numbers, '
            'periods, underscores, or hyphens.'
        )
    return username, None


def validate_password_policy(password):
    value = str(password or '')
    minimum = Config.TEMPORARY_PASSWORD_MIN_LENGTH
    if len(value) < minimum or len(value) > 128:
        return False, f'Password must be between {minimum} and 128 characters.'
    checks = (
        any(ch.islower() for ch in value),
        any(ch.isupper() for ch in value),
        any(ch.isdigit() for ch in value),
        any(not ch.isalnum() for ch in value),
    )
    if not all(checks):
        return False, (
            'Password must contain an uppercase letter, lowercase letter, '
            'number, and special character.'
        )
    return True, None


def _new_reference(conn, now):
    for _ in range(10):
        reference = f"AR-{now.strftime('%Y%m%d')}-{secrets.token_hex(5).upper()}"
        exists = conn.execute(
            'SELECT 1 FROM account_recovery_requests WHERE public_reference = ?',
            (reference,),
        ).fetchone()
        if not exists:
            return reference
    raise RuntimeError('Could not create a unique recovery reference.')


def submit_recovery_request(data, request_ip, request_user_agent):
    """Store an eligible public support request without changing any account."""
    now = datetime.utcnow()
    created_at = now.isoformat()
    window_start = (
        now - timedelta(minutes=Config.RECOVERY_REQUEST_WINDOW_MINUTES)
    ).isoformat()
    staff_id = normalize_staff_id(data.get('staff_id'))
    request_type = str(data.get('request_type') or '')
    request_ip = _single_line(request_ip, 64) or 'unknown'
    user_agent = _single_line(request_user_agent, 500)

    conn = get_db()
    try:
        conn.execute('BEGIN IMMEDIATE')
        ip_count = conn.execute(
            '''
            SELECT COUNT(*) AS count FROM account_recovery_requests
            WHERE request_ip = ? AND created_at >= ?
            ''',
            (request_ip, window_start),
        ).fetchone()['count']
        staff_count = conn.execute(
            '''
            SELECT COUNT(*) AS count FROM account_recovery_requests
            WHERE submitted_staff_id = ? AND created_at >= ?
            ''',
            (staff_id, window_start),
        ).fetchone()['count']
        duplicate = conn.execute(
            '''
            SELECT 1 FROM account_recovery_requests
            WHERE submitted_staff_id = ? AND request_type = ?
              AND status IN ('pending', 'in_review', 'identity_verified')
            LIMIT 1
            ''',
            (staff_id, request_type),
        ).fetchone()

        suppressed_reason = None
        if ip_count >= Config.RECOVERY_MAX_REQUESTS_PER_IP:
            suppressed_reason = 'ip_rate_limited'
        elif staff_count >= Config.RECOVERY_MAX_REQUESTS_PER_STAFF_ID:
            suppressed_reason = 'staff_rate_limited'
        elif duplicate:
            suppressed_reason = 'duplicate_open_request'

        if suppressed_reason:
            conn.rollback()
            return {'stored': False, 'reason': suppressed_reason}

        matched = conn.execute(
            '''
            SELECT id FROM users
            WHERE UPPER(TRIM(staff_id)) = ? AND COALESCE(is_deleted, 0) = 0
            LIMIT 1
            ''',
            (staff_id,),
        ).fetchone()
        reference = _new_reference(conn, now)
        conn.execute(
            '''
            INSERT INTO account_recovery_requests (
                public_reference, request_type, submitted_staff_id,
                submitted_name, submitted_email, submitted_department,
                submitted_role, requested_destination, message, status,
                matched_user_id, created_at, request_ip, request_user_agent
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?)
            ''',
            (
                reference, request_type, staff_id,
                _single_line(data.get('full_name'), 100),
                _single_line(data.get('email'), 254).lower(),
                _single_line(data.get('department'), 100),
                _single_line(data.get('role'), 100),
                str(data.get('requested_destination') or ''),
                _message(data.get('message'), Config.RECOVERY_MESSAGE_MAX_LENGTH),
                matched['id'] if matched else None, created_at,
                request_ip, user_agent,
            ),
        )
        conn.commit()
        return {'stored': True, 'reference': reference}
    finally:
        conn.close()


def _visibility(actor, alias='r'):
    actor = _actor_dict(actor)
    if actor.get('role') == 'Super Admin':
        return '1=1', []
    if actor.get('role') == 'Admin':
        return (
            f"{alias}.requested_destination = 'administrator' AND ("
            f"{alias}.matched_user_id IS NULL OR NOT EXISTS ("
            f"SELECT 1 FROM users scoped_user WHERE scoped_user.id = {alias}.matched_user_id "
            f"AND scoped_user.role IN ('Admin', 'Super Admin')))"
        ), []
    return '1=0', []


def get_recovery_request_count(actor, open_only=True):
    where, params = _visibility(actor)
    status_sql = " AND r.status IN ('pending', 'in_review', 'identity_verified')" if open_only else ''
    conn = get_db()
    count = conn.execute(
        f'SELECT COUNT(*) AS count FROM account_recovery_requests r WHERE {where}{status_sql}',
        params,
    ).fetchone()['count']
    conn.close()
    return count


def get_recovery_requests(actor, filters=None):
    filters = filters or {}
    where, params = _visibility(actor)
    clauses = [where]
    if filters.get('status') in RECOVERY_STATUSES:
        clauses.append('r.status = ?')
        params.append(filters['status'])
    if filters.get('request_type') in REQUEST_TYPES:
        clauses.append('r.request_type = ?')
        params.append(filters['request_type'])
    if filters.get('requested_destination') in DESTINATIONS:
        clauses.append('r.requested_destination = ?')
        params.append(filters['requested_destination'])
    search = _single_line(filters.get('search'), 100)
    if search:
        clauses.append('''(
            r.public_reference LIKE ? OR r.submitted_staff_id LIKE ?
            OR r.submitted_name LIKE ?
        )''')
        params.extend([f'%{search}%'] * 3)
    conn = get_db()
    rows = conn.execute(
        f'''
        SELECT r.*, matched.full_name AS matched_name,
               matched.username AS matched_username,
               assigned.full_name AS assigned_admin_name
        FROM account_recovery_requests r
        LEFT JOIN users matched ON matched.id = r.matched_user_id
        LEFT JOIN users assigned ON assigned.id = r.assigned_admin_id
        WHERE {' AND '.join(clauses)}
        ORDER BY CASE r.status
            WHEN 'identity_verified' THEN 1 WHEN 'in_review' THEN 2
            WHEN 'pending' THEN 3 WHEN 'completed' THEN 4 ELSE 5 END,
            r.created_at DESC, r.id DESC
        ''',
        params,
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_recovery_request(request_id, actor=None):
    clauses = ['r.id = ?']
    params = [request_id]
    if actor is not None:
        where, visibility_params = _visibility(actor)
        clauses.append(where)
        params.extend(visibility_params)
    conn = get_db()
    row = conn.execute(
        f'''
        SELECT r.*, matched.full_name AS matched_name,
               matched.username AS matched_username,
               matched.staff_id AS matched_staff_id,
               matched.email AS matched_email,
               matched.role AS matched_role,
               matched.department AS matched_department,
               matched.approval_status AS matched_account_status,
               assigned.full_name AS assigned_admin_name,
               verifier.full_name AS verified_by_name,
               completer.full_name AS completed_by_name
        FROM account_recovery_requests r
        LEFT JOIN users matched ON matched.id = r.matched_user_id
        LEFT JOIN users assigned ON assigned.id = r.assigned_admin_id
        LEFT JOIN users verifier ON verifier.id = r.identity_verified_by_id
        LEFT JOIN users completer ON completer.id = r.completed_by_id
        WHERE {' AND '.join(clauses)}
        ''',
        params,
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def can_manage_user(actor, target):
    actor = _actor_dict(actor)
    target = target or {}
    if actor.get('role') not in Config.ADMIN_PANEL_ROLES:
        return False
    if not target or target.get('role') == 'Super Admin':
        return False
    if target.get('role') == 'Admin':
        return actor.get('role') == 'Super Admin'
    return True


def get_manageable_users(actor):
    actor = _actor_dict(actor)
    conn = get_db()
    if actor.get('role') == 'Super Admin':
        rows = conn.execute(
            '''
            SELECT * FROM users WHERE role != 'Super Admin'
              AND COALESCE(is_deleted, 0) = 0 ORDER BY full_name
            '''
        ).fetchall()
    elif actor.get('role') == 'Admin':
        rows = conn.execute(
            '''
            SELECT * FROM users WHERE role NOT IN ('Admin', 'Super Admin')
              AND COALESCE(is_deleted, 0) = 0 ORDER BY full_name
            '''
        ).fetchall()
    else:
        rows = []
    conn.close()
    return [dict(row) for row in rows]


def _load_action_context(
    conn, request_id, actor, require_assigned=True, enforce_target_scope=True,
):
    actor = _actor_dict(actor)
    request_row = conn.execute(
        'SELECT * FROM account_recovery_requests WHERE id = ?',
        (request_id,),
    ).fetchone()
    if not request_row:
        raise LookupError('Recovery request not found.')
    recovery = dict(request_row)
    if actor.get('role') == 'Admin' and recovery['requested_destination'] != 'administrator':
        raise PermissionError('This request is reserved for Super Administrator Support.')
    if actor.get('role') not in Config.ADMIN_PANEL_ROLES:
        raise PermissionError('Administrator access is required.')
    if (
        require_assigned and recovery.get('assigned_admin_id')
        and recovery['assigned_admin_id'] != actor.get('id')
        and actor.get('role') != 'Super Admin'
    ):
        raise PermissionError('This request is assigned to another administrator.')
    target = None
    if recovery.get('matched_user_id'):
        row = conn.execute(
            'SELECT * FROM users WHERE id = ? AND COALESCE(is_deleted, 0) = 0',
            (recovery['matched_user_id'],),
        ).fetchone()
        target = dict(row) if row else None
        if enforce_target_scope and target and not can_manage_user(actor, target):
            raise PermissionError('You are not authorized to manage the matched account.')
    return recovery, target


def start_recovery_review(request_id, actor, matched_user_id, review_notes=''):
    actor = _actor_dict(actor)
    conn = get_db()
    try:
        conn.execute('BEGIN IMMEDIATE')
        recovery, _ = _load_action_context(conn, request_id, actor, require_assigned=True)
        if recovery['status'] not in ('pending', 'in_review'):
            raise ValueError('Only pending or in-review requests can be assigned.')
        target_row = conn.execute(
            'SELECT * FROM users WHERE id = ? AND COALESCE(is_deleted, 0) = 0',
            (matched_user_id,),
        ).fetchone()
        target = dict(target_row) if target_row else None
        if not can_manage_user(actor, target):
            raise PermissionError('You are not authorized to manage that account.')
        now = datetime.utcnow().isoformat()
        conn.execute(
            '''
            UPDATE account_recovery_requests
            SET status = 'in_review', matched_user_id = ?, assigned_admin_id = ?,
                review_started_at = COALESCE(review_started_at, ?), review_notes = ?
            WHERE id = ?
            ''',
            (
                matched_user_id, actor['id'], now,
                _message(review_notes, Config.RECOVERY_REVIEW_NOTES_MAX_LENGTH),
                request_id,
            ),
        )
        conn.commit()
        return target
    finally:
        conn.close()


def verify_recovery_identity(request_id, actor, method, notes):
    actor = _actor_dict(actor)
    if method not in VERIFICATION_METHODS:
        raise ValueError('Select an approved identity-verification method.')
    notes = _message(notes, Config.RECOVERY_REVIEW_NOTES_MAX_LENGTH)
    if len(notes) < 10:
        raise ValueError('Identity-verification notes must contain at least 10 characters.')
    conn = get_db()
    try:
        conn.execute('BEGIN IMMEDIATE')
        recovery, target = _load_action_context(conn, request_id, actor)
        if recovery['status'] != 'in_review' or not target:
            raise ValueError('Start review and match an account before verifying identity.')
        now = datetime.utcnow().isoformat()
        conn.execute(
            '''
            UPDATE account_recovery_requests
            SET status = 'identity_verified', identity_verification_method = ?,
                identity_verification_notes = ?, identity_verified_by_id = ?,
                identity_verified_at = ? WHERE id = ?
            ''',
            (method, notes, actor['id'], now, request_id),
        )
        conn.commit()
        return target
    finally:
        conn.close()


def reject_recovery_request(request_id, actor, notes):
    actor = _actor_dict(actor)
    notes = _message(notes, Config.RECOVERY_REVIEW_NOTES_MAX_LENGTH)
    if len(notes) < 5:
        raise ValueError('Provide a concise rejection reason for the audit record.')
    conn = get_db()
    try:
        conn.execute('BEGIN IMMEDIATE')
        recovery, target = _load_action_context(
            conn, request_id, actor, enforce_target_scope=False,
        )
        if recovery['status'] not in OPEN_STATUSES:
            raise ValueError('This request has already reached a terminal state.')
        now = datetime.utcnow().isoformat()
        conn.execute(
            '''
            UPDATE account_recovery_requests
            SET status = 'rejected', review_notes = ?, rejected_at = ?,
                completed_by_id = ?, assigned_admin_id = COALESCE(assigned_admin_id, ?)
            WHERE id = ?
            ''',
            (notes, now, actor['id'], actor['id'], request_id),
        )
        conn.commit()
        return target
    finally:
        conn.close()


def _unique_value(conn, column, value, exclude_user_id):
    return conn.execute(
        f'SELECT id FROM users WHERE {column} = ? COLLATE NOCASE AND id != ?',
        (value, exclude_user_id),
    ).fetchone() is None


def resolve_recovery_request(
    request_id, actor, resolution_type, new_username=None, temporary_password=None,
):
    actor = _actor_dict(actor)
    if resolution_type not in RESOLUTION_TYPES:
        raise ValueError('Select a valid resolution type.')
    conn = get_db()
    try:
        conn.execute('BEGIN IMMEDIATE')
        recovery, target = _load_action_context(conn, request_id, actor)
        if recovery['status'] != 'identity_verified' or not target:
            raise ValueError('Identity must be verified before resolving credentials.')
        if resolution_type not in ALLOWED_RESOLUTIONS.get(recovery['request_type'], set()):
            raise ValueError('The selected resolution does not match the submitted request type.')

        username_change = resolution_type in ('username_updated', 'both_updated')
        password_change = resolution_type in ('password_reset', 'both_recovered', 'both_updated')
        username = target['username']
        if username_change:
            username, error = validate_username(new_username)
            if error:
                raise ValueError(error)
            if not _unique_value(conn, 'username', username, target['id']):
                raise ValueError('That username is already in use.')
        if password_change:
            valid, error = validate_password_policy(temporary_password)
            if not valid:
                raise ValueError(error)

        updates = ['username = ?']
        params = [username]
        if password_change:
            updates.extend(['password_hash = ?', 'must_change_password = 1'])
            params.append(generate_password_hash(temporary_password))
        credential_changed = username_change or password_change
        if credential_changed:
            updates.extend([
                'credential_version = COALESCE(credential_version, 0) + 1',
                'credentials_changed_at = ?', 'credentials_changed_by = ?',
            ])
            params.extend([datetime.utcnow().isoformat(), actor['id']])
        params.append(target['id'])
        conn.execute(
            f"UPDATE users SET {', '.join(updates)} WHERE id = ?",
            params,
        )
        now = datetime.utcnow().isoformat()
        conn.execute(
            '''
            UPDATE account_recovery_requests
            SET status = 'completed', resolution_type = ?, completed_at = ?,
                completed_by_id = ? WHERE id = ?
            ''',
            (resolution_type, now, actor['id'], request_id),
        )
        conn.commit()
        target['username'] = username
        return {
            'target': target,
            'credential_changed': credential_changed,
            'username_changed': username_change,
            'password_reset': password_change,
            'resolution_type': resolution_type,
        }
    finally:
        conn.close()


def edit_account(actor, target_user_id, data, temporary_password=None):
    """Direct administrator edit that preserves approval and suspension state."""
    actor = _actor_dict(actor)
    conn = get_db()
    try:
        conn.execute('BEGIN IMMEDIATE')
        row = conn.execute(
            'SELECT * FROM users WHERE id = ? AND COALESCE(is_deleted, 0) = 0',
            (target_user_id,),
        ).fetchone()
        target = dict(row) if row else None
        if not can_manage_user(actor, target):
            raise PermissionError('You are not authorized to edit this account.')

        full_name = _single_line(data.get('full_name'), 100)
        staff_id = normalize_staff_id(data.get('staff_id'))
        email = _single_line(data.get('email'), 254).lower()
        username, username_error = validate_username(data.get('username'))
        role = _single_line(data.get('role'), 100)
        department = _single_line(data.get('department'), 100)
        work_start = _single_line(data.get('work_start'), 5)
        work_end = _single_line(data.get('work_end'), 5)
        if not full_name or not staff_id or not email or '@' not in email:
            raise ValueError('Full name, Staff ID, and a valid email are required.')
        if username_error:
            raise ValueError(username_error)
        if department not in Config.DEPARTMENTS:
            raise ValueError('Select a valid department.')
        if not TIME_RE.fullmatch(work_start) or not TIME_RE.fullmatch(work_end):
            raise ValueError('Work times must use the HH:MM 24-hour format.')
        if target['role'] == 'Admin':
            if role != 'Admin':
                raise ValueError('Administrator role changes must use Manage Admins.')
        elif role not in Config.STAFF_REGISTER_ROLES:
            raise ValueError('Select a valid staff role.')
        if not validate_role_department(
                role, department,
                public_only=target['role'] not in Config.ADMIN_PANEL_ROLES):
            raise ValueError('Select a valid department for the selected role.')
        role = normalize_role(role)
        department = normalize_department(department)
        for column, value, label in (
            ('username', username, 'Username'),
            ('staff_id', staff_id, 'Staff ID'),
            ('email', email, 'Email'),
        ):
            if not _unique_value(conn, column, value, target_user_id):
                raise ValueError(f'{label} is already in use.')

        password_change = bool(temporary_password)
        if password_change:
            valid, error = validate_password_policy(temporary_password)
            if not valid:
                raise ValueError(error)
        username_change = username != target['username']
        updates = [
            'full_name = ?', 'staff_id = ?', 'email = ?', 'username = ?',
            'role = ?', 'department = ?', 'work_start = ?', 'work_end = ?',
        ]
        params = [
            full_name, staff_id, email, username, role, department,
            work_start, work_end,
        ]
        if password_change:
            updates.extend(['password_hash = ?', 'must_change_password = 1'])
            params.append(generate_password_hash(temporary_password))
        credential_changed = username_change or password_change
        if credential_changed:
            updates.extend([
                'credential_version = COALESCE(credential_version, 0) + 1',
                'credentials_changed_at = ?', 'credentials_changed_by = ?',
            ])
            params.extend([datetime.utcnow().isoformat(), actor['id']])
        params.append(target_user_id)
        conn.execute(
            f"UPDATE users SET {', '.join(updates)} WHERE id = ?",
            params,
        )
        conn.commit()
        return {
            'username_changed': username_change,
            'password_reset': password_change,
            'credential_changed': credential_changed,
            'approval_status_preserved': target['approval_status'],
            'previous_role': target['role'],
            'new_role': role,
            'previous_department': target['department'],
            'new_department': department,
        }
    finally:
        conn.close()
