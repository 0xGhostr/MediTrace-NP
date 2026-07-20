"""Database query helpers and access control utilities."""
import json
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from werkzeug.security import generate_password_hash, check_password_hash

from config import Config
from database import get_db, write_connection
from record_policy import (
    RESTRICTED_CATEGORY_KEYS,
    is_restricted_record,
    normalize_category,
    normalize_sensitivity,
)
from record_access import (
    authorized_record_predicate,
    can_export_record,
    normalize_department,
    normalize_role,
    validate_role_department,
)


def row_to_dict(row):
    """Convert sqlite3.Row to dictionary."""
    if row is None:
        return None
    return dict(row)


def get_user_by_id(user_id):
    conn = get_db()
    user = conn.execute(
        'SELECT * FROM users WHERE id = ? AND COALESCE(is_deleted, 0) = 0',
        (user_id,),
    ).fetchone()
    conn.close()
    return row_to_dict(user)


def get_user_by_username(username):
    conn = get_db()
    user = conn.execute(
        'SELECT * FROM users WHERE username = ? AND COALESCE(is_deleted, 0) = 0',
        (username,),
    ).fetchone()
    conn.close()
    return row_to_dict(user)


def get_user_by_staff_id(staff_id):
    conn = get_db()
    user = conn.execute(
        'SELECT * FROM users WHERE staff_id = ? AND COALESCE(is_deleted, 0) = 0',
        (staff_id,),
    ).fetchone()
    conn.close()
    return row_to_dict(user)


def get_user_by_email(email):
    conn = get_db()
    user = conn.execute(
        'SELECT * FROM users WHERE email = ? AND COALESCE(is_deleted, 0) = 0',
        (email,),
    ).fetchone()
    conn.close()
    return row_to_dict(user)


def create_user(data):
    """Insert a new user with hashed password."""
    if not validate_role_department(
            data.get('role'), data.get('department'), public_only=True):
        raise ValueError('Select a valid department for the selected role.')
    data = dict(data)
    data['role'] = normalize_role(data['role'])
    data['department'] = normalize_department(data['department'])
    password_hash = generate_password_hash(data['password'])
    now = datetime.utcnow().isoformat()
    with write_connection() as conn:
        cursor = conn.execute('''
            INSERT INTO users (full_name, staff_id, email, username, password_hash,
                role, department, work_start, work_end, approval_status, is_active, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            data['full_name'], data['staff_id'], data['email'], data['username'],
            password_hash, data['role'], data['department'], data['work_start'],
            data['work_end'], data.get('approval_status', 'pending'),
            data.get('is_active', 0), now
        ))
        return cursor.lastrowid


def verify_password(user, password):
    return check_password_hash(user['password_hash'], password)


def update_user_login(user_id):
    now = datetime.utcnow().isoformat()
    with write_connection() as conn:
        conn.execute('UPDATE users SET last_login = ? WHERE id = ?', (now, user_id))


def update_user_language(user_id, locale):
    """Persist a validated UI preference without touching account/domain state."""
    if locale not in ('en', 'ne'):
        raise ValueError('Unsupported language.')
    with write_connection() as conn:
        conn.execute(
            'UPDATE users SET preferred_language = ? WHERE id = ?',
            (locale, user_id),
        )


def log_login_attempt(username, user_id, success, failure_reason=None, ip_address=None):
    now = datetime.utcnow().isoformat()
    with write_connection() as conn:
        conn.execute('''
            INSERT INTO login_history (user_id, username, timestamp, success, failure_reason, ip_address)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (user_id, username, now, 1 if success else 0, failure_reason, ip_address))


def log_admin_action(admin_id, action_type, target_user_id=None, details=None):
    now = datetime.utcnow().isoformat()
    with write_connection() as conn:
        conn.execute('''
            INSERT INTO admin_actions (admin_id, action_type, target_user_id, details, timestamp)
            VALUES (?, ?, ?, ?, ?)
        ''', (admin_id, action_type, target_user_id, details, now))


def role_can_access_category(role, category):
    """Check if role is allowed to view record category."""
    if role not in Config.ROLE_ACCESS:
        return False
    allowed = Config.ROLE_ACCESS.get(role)
    if allowed is None:
        return True
    category_key = normalize_category(category)
    return any(normalize_category(item) == category_key for item in allowed)


def category_mismatch(role, category):
    """True if role should not normally access this category."""
    return not role_can_access_category(role, category)


def get_patient_record(record_id):
    conn = get_db()
    record = conn.execute(
        'SELECT * FROM patient_records WHERE id = ? AND COALESCE(is_active, 1) = 1',
        (record_id,),
    ).fetchone()
    conn.close()
    return row_to_dict(record)


def get_all_patient_records(category_filter=None, search=None):
    conn = get_db()
    query = 'SELECT * FROM patient_records WHERE COALESCE(is_active, 1) = 1'
    params = []
    if category_filter:
        placeholders = ','.join('?' * len(category_filter))
        query += f' AND record_category IN ({placeholders})'
        params.extend(category_filter)
    if search:
        search_value = f'%{search.strip()}%'
        query += (
            ' AND (patient_code LIKE ? OR record_title LIKE ? '
            'OR department LIKE ?)'
        )
        params.extend([search_value, search_value, search_value])
    # Newly created records should be immediately visible at the top. The id
    # tie-breaker keeps deterministic ordering for seeded rows sharing a date.
    query += ' ORDER BY created_at DESC, id DESC'
    records = conn.execute(query, params).fetchall()
    conn.close()
    return [row_to_dict(r) for r in records]


def _record_query_user(user_or_role, is_admin_panel=None):
    """Accept current user objects while retaining old test/helper compatibility."""
    if not isinstance(user_or_role, str):
        return user_or_role
    role = normalize_role(user_or_role) or user_or_role
    default_departments = {
        'Super Admin': 'Administration', 'Admin': 'Administration',
        'Doctor': 'General Medicine', 'Nurse': 'General Medicine',
        'Laboratory Staff': 'Laboratory', 'Billing Staff': 'Billing',
        'Receptionist': 'Reception',
    }
    return {
        'role': role,
        'department': default_departments.get(role),
        'approval_status': 'approved', 'is_active': 1, 'is_deleted': 0,
    }


def get_authorized_patient_records(user, search=None):
    """Return all active rows in the centralized view scope for dashboards."""
    scope_sql, scope_params = authorized_record_predicate(user)
    conditions = ['COALESCE(is_active, 1) = 1', scope_sql]
    params = list(scope_params)
    if search:
        search_value = f'%{str(search).strip()}%'
        conditions.append(
            '(patient_code LIKE ? OR record_title LIKE ? OR department LIKE ?)'
        )
        params.extend([search_value, search_value, search_value])
    conn = get_db()
    rows = conn.execute(
        f'''SELECT * FROM patient_records
            WHERE {' AND '.join(conditions)}
            ORDER BY created_at DESC, id DESC''',
        params,
    ).fetchall()
    conn.close()
    records = [row_to_dict(row) for row in rows]
    for record in records:
        record['allowed'] = True
        record['is_restricted'] = is_restricted_record(record)
        record['can_export'] = can_export_record(user, record)
    return records


def get_patient_records_page(user_or_role, is_admin_panel=None, filters=None, page=1, per_page=15):
    """Return one authorized, server-filtered page plus count metadata."""
    user = _record_query_user(user_or_role, is_admin_panel)
    filters = filters or {}
    try:
        page = max(int(page), 1)
    except (TypeError, ValueError):
        page = 1
    per_page = max(int(per_page), 1)

    category_expr = (
        "LOWER(REPLACE(REPLACE(TRIM(record_category), '_', '-'), ' ', '-'))"
    )
    conditions = ['COALESCE(is_active, 1) = 1']
    params = []

    # Authorization is the first SQL predicate, before filtering, counting, and
    # pagination, so unauthorized rows and totals never reach the caller.
    scope_sql, scope_params = authorized_record_predicate(user)
    conditions.append(scope_sql)
    params.extend(scope_params)

    search = str(filters.get('search') or '').strip()
    if search:
        search_value = f'%{search}%'
        conditions.append(
            '(patient_code LIKE ? OR record_title LIKE ? OR department LIKE ?)'
        )
        params.extend([search_value, search_value, search_value])

    category = str(filters.get('category') or '').strip()
    if category:
        conditions.append(f'{category_expr} = ?')
        params.append(normalize_category(category))

    department = str(filters.get('department') or '').strip()
    if department:
        conditions.append('LOWER(TRIM(department)) = LOWER(?)')
        params.append(department)

    sensitivity = filters.get('sensitivity')
    if sensitivity:
        canonical_sensitivity = normalize_sensitivity(sensitivity)
        conditions.append('LOWER(TRIM(sensitivity_level)) = LOWER(?)')
        params.append(canonical_sensitivity)

    restricted = str(filters.get('restricted') or '').strip().casefold()
    if restricted in {'restricted', 'standard'}:
        restricted_keys = sorted(RESTRICTED_CATEGORY_KEYS)
        placeholders = ','.join('?' * len(restricted_keys))
        operator = 'IN' if restricted == 'restricted' else 'NOT IN'
        conditions.append(f'{category_expr} {operator} ({placeholders})')
        params.extend(restricted_keys)

    where_clause = ' AND '.join(conditions)
    conn = get_db()
    total = conn.execute(
        f'SELECT COUNT(*) FROM patient_records WHERE {where_clause}', params
    ).fetchone()[0]
    total_pages = (total + per_page - 1) // per_page if total else 0
    if total_pages and page > total_pages:
        page = total_pages
    elif not total_pages:
        page = 1

    offset = (page - 1) * per_page
    rows = conn.execute(
        f'''SELECT * FROM patient_records
            WHERE {where_clause}
            ORDER BY created_at DESC, id DESC
            LIMIT ? OFFSET ?''',
        [*params, per_page, offset],
    ).fetchall()
    conn.close()

    records = [row_to_dict(row) for row in rows]
    for record in records:
        record['allowed'] = True
        record['is_restricted'] = is_restricted_record(record)
        record['can_export'] = can_export_record(user, record)

    start = offset + 1 if total else 0
    end = min(offset + len(records), total) if total else 0
    return records, {
        'page': page,
        'per_page': per_page,
        'total': total,
        'total_pages': total_pages,
        'start': start,
        'end': end,
        'has_previous': page > 1,
        'has_next': bool(total_pages and page < total_pages),
        'previous_page': page - 1 if page > 1 else None,
        'next_page': page + 1 if total_pages and page < total_pages else None,
    }


def is_after_hours(user, timestamp=None):
    """Check if access is outside work hours."""
    ts = timestamp or datetime.utcnow()
    if isinstance(ts, str):
        ts = datetime.fromisoformat(ts.replace('Z', ''))
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    ts = ts.astimezone(ZoneInfo(Config.LOCAL_TIMEZONE))
    start_parts = user['work_start'].split(':')
    end_parts = user['work_end'].split(':')
    current_time = ts.time()
    from datetime import time as dt_time
    start_t = dt_time(int(start_parts[0]), int(start_parts[1]))
    end_t = dt_time(int(end_parts[0]), int(end_parts[1]))
    within_schedule = (
        start_t <= current_time <= end_t
        if start_t <= end_t
        else current_time >= start_t or current_time <= end_t
    )
    return not within_schedule


def is_sensitive_record(sensitivity_level):
    try:
        return normalize_sensitivity(sensitivity_level) in ('High', 'Critical')
    except ValueError:
        return False


def build_access_context(user_id, record=None, timestamp=None, computer_name=None):
    """Build pre-event behavioural context; the current event is excluded."""
    ts = timestamp or datetime.utcnow()
    if isinstance(ts, str):
        ts = datetime.fromisoformat(ts.replace('Z', ''))

    conn = get_db()
    ten_min_ago = (ts - timedelta(minutes=10)).isoformat()
    thirty_min_ago = (ts - timedelta(minutes=30)).isoformat()
    utc_ts = ts.replace(tzinfo=timezone.utc) if ts.tzinfo is None else ts.astimezone(timezone.utc)
    local_ts = utc_ts.astimezone(ZoneInfo(Config.LOCAL_TIMEZONE))
    today_start = local_ts.replace(
        hour=0, minute=0, second=0, microsecond=0,
    ).astimezone(timezone.utc).replace(tzinfo=None).isoformat()

    records_last_10_min = conn.execute('''
        SELECT COUNT(*) as cnt FROM access_events
        WHERE user_id = ? AND action_type = 'view' AND timestamp >= ? AND timestamp < ?
    ''', (user_id, ten_min_ago, ts.isoformat())).fetchone()['cnt']

    high_critical_last_30_min = conn.execute('''
        SELECT COUNT(*) as cnt FROM access_events
        WHERE user_id = ? AND action_type = 'view' AND timestamp >= ? AND timestamp < ?
        AND sensitivity_level IN ('High', 'Critical')
    ''', (user_id, thirty_min_ago, ts.isoformat())).fetchone()['cnt']

    records_today = conn.execute('''
        SELECT COUNT(*) as cnt FROM access_events
        WHERE user_id = ? AND timestamp >= ? AND timestamp < ?
        AND action_type != 'usb_monitor'
    ''', (user_id, today_start, ts.isoformat())).fetchone()['cnt']

    sensitive_today = conn.execute('''
        SELECT COUNT(*) as cnt FROM access_events
        WHERE user_id = ? AND timestamp >= ? AND timestamp < ?
        AND sensitivity_level IN ('High', 'Critical')
        AND action_type != 'usb_monitor'
    ''', (user_id, today_start, ts.isoformat())).fetchone()['cnt']

    repeated_record_30m = 0
    if record:
        repeated_record_30m = conn.execute('''
            SELECT COUNT(*) as cnt FROM access_events
            WHERE user_id = ? AND record_id = ? AND timestamp >= ? AND timestamp < ?
        ''', (user_id, record['id'], thirty_min_ago, ts.isoformat())).fetchone()['cnt']

    previous = conn.execute('''
        SELECT timestamp FROM access_events
        WHERE user_id = ? AND timestamp < ? AND action_type != 'usb_monitor'
        ORDER BY timestamp DESC, id DESC LIMIT 1
    ''', (user_id, ts.isoformat())).fetchone()
    time_since_previous = 1440.0
    if previous:
        previous_ts = datetime.fromisoformat(previous['timestamp'].replace('Z', ''))
        time_since_previous = max((ts - previous_ts).total_seconds() / 60.0, 0)

    device_familiarity = 0
    if computer_name:
        device_familiarity = 1 if conn.execute('''
            SELECT 1 FROM access_events
            WHERE user_id = ? AND computer_name = ? AND timestamp < ? LIMIT 1
        ''', (user_id, computer_name, ts.isoformat())).fetchone() else 0

    conn.close()

    department_match = 1
    if record and user_id:
        user = get_user_by_id(user_id)
        if user and record:
            department_match = 1 if user['department'] == record['department'] else 0

    return {
        'records_last_10_min': records_last_10_min,
        'high_critical_last_30_min': high_critical_last_30_min,
        'records_accessed_today': records_today,
        'sensitive_accesses_today': sensitive_today,
        'repeated_record_30m': repeated_record_30m,
        'time_since_previous_minutes': time_since_previous,
        'device_familiarity': device_familiarity,
        'computer_name': computer_name or 'Web session',
        'department_match': department_match,
        'timestamp': ts,
    }


def insert_access_event(event_data):
    """Insert access event and return event id."""
    conn = get_db()
    columns = (
        'user_id', 'username', 'staff_id', 'role', 'department', 'record_id',
        'record_category', 'sensitivity_level', 'action_type', 'timestamp',
        'ip_address', 'computer_name', 'is_after_hours', 'is_sensitive',
        'department_match', 'rule_result', 'ml_score', 'rule_score',
        'anomaly_score', 'hybrid_score', 'baseline_source', 'anomaly_method',
        'model_version', 'model_raw_score', 'model_confidence',
        'minimum_risk_override', 'human_review_required', 'explanation_json',
        'browser_info', 'final_risk_level', 'alert_created',
    )
    values = (
        event_data['user_id'], event_data['username'], event_data['staff_id'],
        event_data['role'], event_data['department'], event_data.get('record_id'),
        event_data.get('record_category'), event_data.get('sensitivity_level'),
        event_data['action_type'], event_data['timestamp'], event_data.get('ip_address'),
        event_data.get('computer_name'), event_data.get('is_after_hours', 0),
        event_data.get('is_sensitive', 0), event_data.get('department_match', 0),
        event_data.get('rule_result'), event_data.get('ml_score', 0),
        event_data.get('rule_score'), event_data.get('anomaly_score'),
        event_data.get('hybrid_score'), event_data.get('baseline_source'),
        event_data.get('anomaly_method'), event_data.get('model_version'),
        event_data.get('model_raw_score'), event_data.get('model_confidence'),
        event_data.get('minimum_risk_override'),
        event_data.get('human_review_required', 0), event_data.get('explanation_json'),
        event_data.get('browser_info'), event_data.get('final_risk_level', 'Normal'),
        event_data.get('alert_created', 0),
    )
    placeholders = ','.join('?' for _ in columns)
    cursor = conn.execute(
        f"INSERT INTO access_events ({','.join(columns)}) VALUES ({placeholders})",
        values,
    )
    event_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return event_id


def insert_alert(alert_data):
    conn = get_db()
    columns = (
        'event_id', 'user_id', 'username', 'role', 'department', 'record_id',
        'severity', 'reason', 'triggered_rules', 'ml_score', 'rule_score',
        'anomaly_score', 'hybrid_score', 'baseline_source', 'anomaly_method',
        'model_version', 'model_confidence', 'minimum_risk_override',
        'human_review_required', 'explanation_json', 'status', 'created_at',
    )
    values = (
        alert_data['event_id'], alert_data['user_id'], alert_data['username'],
        alert_data['role'], alert_data['department'], alert_data.get('record_id'),
        alert_data['severity'], alert_data['reason'], alert_data.get('triggered_rules'),
        alert_data.get('ml_score', 0), alert_data.get('rule_score'),
        alert_data.get('anomaly_score'), alert_data.get('hybrid_score'),
        alert_data.get('baseline_source'), alert_data.get('anomaly_method'),
        alert_data.get('model_version'), alert_data.get('model_confidence'),
        alert_data.get('minimum_risk_override'),
        alert_data.get('human_review_required', 1), alert_data.get('explanation_json'),
        'open', alert_data['created_at'],
    )
    placeholders = ','.join('?' for _ in columns)
    cursor = conn.execute(
        f"INSERT INTO alerts ({','.join(columns)}) VALUES ({placeholders})",
        values,
    )
    alert_id = cursor.lastrowid
    if str(alert_data.get('severity', '')).strip().lower() == 'critical':
        conn.execute(
            '''
            INSERT OR IGNORE INTO messages (
                sender_id, receiver_id, title, body, is_read, is_urgent,
                created_at, notification_type, related_alert_id
            )
            SELECT ?, u.id, 'Critical Security Alert',
                   'A new critical patient-record access alert has been generated and requires review.',
                   0, 1, ?, 'critical_alert', ?
            FROM users u
            WHERE LOWER(TRIM(u.role)) IN ('admin', 'super admin')
              AND LOWER(TRIM(u.approval_status)) = 'approved'
              AND COALESCE(u.is_active, 0) = 1
              AND COALESCE(u.is_deleted, 0) = 0
            ''',
            (alert_data['user_id'], alert_data['created_at'], alert_id),
        )
    conn.commit()
    conn.close()
    return alert_id


def get_pending_users():
    conn = get_db()
    users = conn.execute(
        "SELECT * FROM users WHERE approval_status = 'pending' AND COALESCE(is_deleted, 0) = 0 ORDER BY created_at DESC"
    ).fetchall()
    conn.close()
    return [row_to_dict(u) for u in users]


def get_pending_registration_count():
    """Count only current, non-deleted pending staff registrations."""
    conn = get_db()
    count = conn.execute('''
        SELECT COUNT(*) AS count
        FROM users
        WHERE LOWER(TRIM(approval_status)) = 'pending'
          AND COALESCE(is_deleted, 0) = 0
    ''').fetchone()['count']
    conn.close()
    return int(count or 0)


def get_all_users(status_filter=None):
    conn = get_db()
    if status_filter:
        users = conn.execute(
            'SELECT * FROM users WHERE approval_status = ? AND COALESCE(is_deleted, 0) = 0 ORDER BY created_at DESC',
            (status_filter,)
        ).fetchall()
    else:
        users = conn.execute(
            'SELECT * FROM users WHERE COALESCE(is_deleted, 0) = 0 ORDER BY created_at DESC'
        ).fetchall()
    conn.close()
    return [row_to_dict(u) for u in users]


def approve_user(user_id, admin_id, role=None, department=None):
    conn = get_db()
    now = datetime.utcnow().isoformat()
    user = get_user_by_id(user_id)
    if role is None:
        role = user['role']
    if department is None:
        department = user['department']
    if not validate_role_department(role, department, public_only=True):
        raise ValueError('Select a valid department for the selected role.')
    role = normalize_role(role)
    department = normalize_department(department)
    conn.execute('''
        UPDATE users SET approval_status = 'approved', role = ?, department = ?,
            approved_by = ?, approved_at = ?, is_active = 1
        WHERE id = ?
    ''', (role, department, admin_id, now, user_id))
    conn.commit()
    conn.close()


def reject_user(user_id, reason=None):
    conn = get_db()
    conn.execute('''
        UPDATE users SET approval_status = 'rejected', rejection_reason = ?, is_active = 0
        WHERE id = ?
    ''', (reason, user_id))
    conn.commit()
    conn.close()


def suspend_user(user_id):
    conn = get_db()
    conn.execute("UPDATE users SET approval_status = 'suspended', is_active = 0 WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()


def reactivate_user(user_id):
    conn = get_db()
    conn.execute("UPDATE users SET approval_status = 'approved', is_active = 1 WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()


def soft_delete_user(user_id):
    conn = get_db()
    conn.execute(
        "UPDATE users SET is_deleted = 1, is_active = 0, approval_status = 'deleted' WHERE id = ?",
        (user_id,),
    )
    conn.commit()
    conn.close()


def update_user_details(user_id, **kwargs):
    current = get_user_by_id(user_id)
    if not current:
        raise ValueError('User account was not found.')
    role = kwargs.get('role', current['role'])
    department = kwargs.get('department', current['department'])
    public_only = normalize_role(current['role']) not in Config.ADMIN_PANEL_ROLES
    if not validate_role_department(role, department, public_only=public_only):
        raise ValueError('Select a valid department for the selected role.')
    kwargs['role'] = normalize_role(role)
    kwargs['department'] = normalize_department(department)
    conn = get_db()
    allowed = ['role', 'department', 'work_start', 'work_end', 'full_name']
    for key, value in kwargs.items():
        if key in allowed and value is not None:
            conn.execute(f'UPDATE users SET {key} = ? WHERE id = ?', (value, user_id))
    conn.commit()
    conn.close()


def get_access_events(filters=None, limit=500):
    """Query access events with optional filters."""
    conn = get_db()
    query = 'SELECT * FROM access_events WHERE 1=1'
    params = []
    filters = filters or {}

    if filters.get('username'):
        query += ' AND username LIKE ?'
        params.append(f"%{filters['username']}%")
    if filters.get('staff_id'):
        query += ' AND staff_id LIKE ?'
        params.append(f"%{filters['staff_id']}%")
    if filters.get('record_id'):
        query += ' AND record_id = ?'
        params.append(filters['record_id'])
    if filters.get('date_from'):
        query += ' AND timestamp >= ?'
        params.append(filters['date_from'])
    if filters.get('date_to'):
        query += ' AND timestamp <= ?'
        params.append(filters['date_to'] + 'T23:59:59')
    if filters.get('role'):
        query += ' AND role = ?'
        params.append(filters['role'])
    if filters.get('department'):
        query += ' AND department = ?'
        params.append(filters['department'])
    if filters.get('risk_level'):
        query += ' AND final_risk_level = ?'
        params.append(filters['risk_level'])

    query += ' ORDER BY timestamp DESC LIMIT ?'
    params.append(limit)
    events = conn.execute(query, params).fetchall()
    conn.close()
    return [_enrich_explainability(row_to_dict(event)) for event in events]


def _alert_filter_sql(filters=None):
    """Build parameterized filtering shared by alert list and count queries."""
    filters = filters or {}
    clauses = ['1=1']
    params = []

    if filters.get('severity'):
        clauses.append('a.severity = ?')
        params.append(filters['severity'])
    if filters.get('status'):
        clauses.append('a.status = ?')
        params.append(filters['status'])
    if filters.get('search'):
        search_value = f"%{filters['search']}%"
        clauses.append('''
            (
                CAST(a.id AS TEXT) LIKE ? OR
                a.username LIKE ? OR
                COALESCE(u.full_name, '') LIKE ? OR
                COALESCE(e.staff_id, '') LIKE ? OR
                a.role LIKE ? OR
                CAST(COALESCE(a.record_id, '') AS TEXT) LIKE ? OR
                a.department LIKE ? OR
                COALESCE(a.triggered_rules, '') LIKE ? OR
                a.reason LIKE ? OR
                COALESCE(e.ip_address, '') LIKE ? OR
                COALESCE(e.computer_name, '') LIKE ? OR
                COALESCE(e.action_type, '') LIKE ?
            )
        ''')
        params.extend([search_value] * 12)

    return ' AND '.join(clauses), params


def _parse_triggered_rule_list(raw_value):
    """Parse the stored JSON rule list without splitting descriptive text."""
    if not raw_value:
        return []
    try:
        parsed = json.loads(raw_value)
    except (TypeError, ValueError, json.JSONDecodeError):
        return [str(raw_value)]
    if isinstance(parsed, list):
        return [str(rule) for rule in parsed if rule]
    return [str(parsed)] if parsed else []


def _enrich_explainability(item):
    """Parse persisted explainability JSON for templates and reports."""
    if not item:
        return item
    raw = item.get('explanation_json')
    try:
        explanation = json.loads(raw) if raw else {}
    except (TypeError, ValueError, json.JSONDecodeError):
        explanation = {'scoring_method': 'unavailable', 'summary': 'Explanation data is invalid.'}
    item['explanation'] = explanation if isinstance(explanation, dict) else {}
    item['rule_contributions'] = item['explanation'].get('rule_contributions', [])
    item['behavioural_deviations'] = item['explanation'].get('behavioural_deviations', [])
    return item


def get_alerts(filters=None, limit=200, offset=0):
    conn = get_db()
    where_sql, params = _alert_filter_sql(filters)
    query = f'''
        SELECT
            a.*,
            u.full_name AS user_full_name,
            e.staff_id AS event_staff_id,
            e.ip_address AS event_ip_address,
            e.computer_name AS event_computer_name,
            e.action_type AS event_action_type,
            e.record_category AS event_record_category,
            e.sensitivity_level AS event_sensitivity_level,
            resolver.full_name AS resolved_by_name
        FROM alerts a
        LEFT JOIN users u ON u.id = a.user_id
        LEFT JOIN access_events e ON e.id = a.event_id
        LEFT JOIN users resolver ON resolver.id = a.resolved_by
        WHERE {where_sql}
        ORDER BY a.created_at DESC, a.id DESC
        LIMIT ? OFFSET ?
    '''
    params.extend([limit, offset])
    alerts = conn.execute(query, params).fetchall()
    conn.close()
    output = []
    for row in alerts:
        alert = row_to_dict(row)
        alert['triggered_rule_list'] = _parse_triggered_rule_list(
            alert.get('triggered_rules')
        )
        output.append(_enrich_explainability(alert))
    return output


def get_alert_count(filters=None):
    conn = get_db()
    where_sql, params = _alert_filter_sql(filters)
    total = conn.execute(
        f'''
            SELECT COUNT(*) AS count
            FROM alerts a
            LEFT JOIN users u ON u.id = a.user_id
            LEFT JOIN access_events e ON e.id = a.event_id
            WHERE {where_sql}
        ''',
        params,
    ).fetchone()['count']
    conn.close()
    return total


def get_alert_summary():
    conn = get_db()
    row = conn.execute('''
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) AS open_count,
            SUM(CASE WHEN severity = 'Critical' THEN 1 ELSE 0 END) AS critical_count,
            SUM(CASE WHEN severity = 'High' THEN 1 ELSE 0 END) AS high_count,
            SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END) AS resolved_count,
            MAX(created_at) AS last_updated
        FROM alerts
    ''').fetchone()
    conn.close()
    summary = row_to_dict(row)
    for key in ('total', 'open_count', 'critical_count', 'high_count', 'resolved_count'):
        summary[key] = summary.get(key) or 0
    return summary


def get_alert_filter_options():
    conn = get_db()
    severities = conn.execute('''
        SELECT DISTINCT severity FROM alerts
        WHERE severity IS NOT NULL AND severity != ''
        ORDER BY CASE severity
            WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3
            WHEN 'Low' THEN 4 WHEN 'Normal' THEN 5 ELSE 6 END
    ''').fetchall()
    statuses = conn.execute('''
        SELECT DISTINCT status FROM alerts
        WHERE status IS NOT NULL AND status != ''
        ORDER BY CASE status WHEN 'open' THEN 1 WHEN 'resolved' THEN 2 ELSE 3 END, status
    ''').fetchall()
    conn.close()
    return {
        'severities': [row['severity'] for row in severities],
        'statuses': [row['status'] for row in statuses],
    }


def get_nepal_day_utc_bounds(now=None):
    """Return the current Nepal calendar day's half-open UTC boundaries."""
    instant = now or datetime.now(timezone.utc)
    if instant.tzinfo is None:
        instant = instant.replace(tzinfo=timezone.utc)
    else:
        instant = instant.astimezone(timezone.utc)
    local_now = instant.astimezone(ZoneInfo(Config.LOCAL_TIMEZONE))
    local_start = local_now.replace(hour=0, minute=0, second=0, microsecond=0)
    local_end = local_start + timedelta(days=1)
    return (
        local_start.astimezone(timezone.utc).replace(tzinfo=None).isoformat(),
        local_end.astimezone(timezone.utc).replace(tzinfo=None).isoformat(),
    )


def get_alert_summary_today(conn=None, now=None):
    """Count each canonical alert severity once for the current Nepal day."""
    own_connection = conn is None
    conn = conn or get_db()
    start_utc, end_utc = get_nepal_day_utc_bounds(now)
    rows = conn.execute(
        '''
        SELECT LOWER(TRIM(severity)) AS severity_key, COUNT(DISTINCT id) AS cnt
        FROM alerts
        WHERE created_at >= ? AND created_at < ?
          AND LOWER(TRIM(severity)) IN ('medium', 'high', 'critical')
        GROUP BY LOWER(TRIM(severity))
        ''',
        (start_utc, end_utc),
    ).fetchall()
    if own_connection:
        conn.close()

    counts = {'medium': 0, 'high': 0, 'critical': 0}
    for row in rows:
        counts[row['severity_key']] = int(row['cnt'] or 0)
    counts['total'] = counts['medium'] + counts['high'] + counts['critical']
    return counts


def resolve_alert(alert_id, admin_id, notes=None):
    conn = get_db()
    now = datetime.utcnow().isoformat()
    conn.execute('''
        UPDATE alerts SET status = 'resolved', resolved_by = ?, resolved_at = ?, notes = ?
        WHERE id = ?
    ''', (admin_id, now, notes, alert_id))
    conn.commit()
    conn.close()


def get_dashboard_stats():
    """Return statistics for admin dashboard."""
    conn = get_db()
    today = datetime.utcnow().strftime('%Y-%m-%d')

    total_today = conn.execute(
        "SELECT COUNT(*) as cnt FROM access_events WHERE timestamp LIKE ?",
        (f'{today}%',)
    ).fetchone()['cnt']

    alert_summary_today = get_alert_summary_today(conn=conn)

    risk_counts = {}
    for level in Config.RISK_LEVELS:
        risk_counts[level] = conn.execute(
            "SELECT COUNT(*) as cnt FROM access_events WHERE final_risk_level = ? AND timestamp LIKE ?",
            (level, f'{today}%')
        ).fetchone()['cnt']

    recent_events = conn.execute(
        'SELECT * FROM access_events ORDER BY timestamp DESC LIMIT 10'
    ).fetchall()

    recent_alerts = conn.execute(
        'SELECT * FROM alerts ORDER BY created_at DESC LIMIT 10'
    ).fetchall()

    top_risky = conn.execute('''
        SELECT username, staff_id, role, department,
               COUNT(*) as event_count,
               SUM(CASE WHEN final_risk_level IN ('High','Critical') THEN 1 ELSE 0 END) as risky_count
        FROM access_events
        WHERE timestamp LIKE ?
        GROUP BY user_id
        ORDER BY risky_count DESC, event_count DESC
        LIMIT 5
    ''', (f'{today}%',)).fetchall()

    usb_events_today = conn.execute(
        "SELECT COUNT(*) as cnt FROM usb_events WHERE timestamp LIKE ?",
        (f'{today}%',),
    ).fetchone()['cnt']

    unknown_usb_alerts_today = conn.execute(
        """
        SELECT COUNT(*) as cnt FROM usb_events
        WHERE timestamp LIKE ? AND is_whitelisted = 0 AND alert_created = 1
        """,
        (f'{today}%',),
    ).fetchone()['cnt']

    whitelisted_usb_count = conn.execute(
        "SELECT COUNT(*) as cnt FROM usb_devices WHERE is_whitelisted = 1"
    ).fetchone()['cnt']

    usb_critical_alerts = conn.execute(
        """
        SELECT COUNT(*) as cnt FROM usb_events
        WHERE risk_level = 'Critical' AND timestamp LIKE ?
        """,
        (f'{today}%',),
    ).fetchone()['cnt']

    recent_usb_events = conn.execute(
        'SELECT * FROM usb_events ORDER BY timestamp DESC LIMIT 10'
    ).fetchall()

    conn.close()

    return {
        'total_access_today': total_today,
        'total_alerts_today': alert_summary_today['total'],
        'critical_alerts': alert_summary_today['critical'],
        'high_alerts': alert_summary_today['high'],
        'medium_alerts': alert_summary_today['medium'],
        'alert_summary_today': alert_summary_today,
        'risk_counts': risk_counts,
        'recent_events': [row_to_dict(e) for e in recent_events],
        'recent_alerts': [row_to_dict(a) for a in recent_alerts],
        'top_risky_users': [row_to_dict(u) for u in top_risky],
        'usb_events_today': usb_events_today,
        'unknown_usb_alerts_today': unknown_usb_alerts_today,
        'whitelisted_usb_count': whitelisted_usb_count,
        'usb_critical_alerts': usb_critical_alerts,
        'recent_usb_events': [row_to_dict(e) for e in recent_usb_events],
    }


def get_chart_access_timeline(days=7):
    conn = get_db()
    labels = []
    data = []
    start = (datetime.utcnow() - timedelta(days=days - 1)).strftime('%Y-%m-%d')
    grouped = conn.execute(
        """
        SELECT substr(timestamp, 1, 10) AS day_key, COUNT(*) AS cnt
        FROM access_events
        WHERE substr(timestamp, 1, 10) >= ?
        GROUP BY day_key
        """,
        (start,),
    ).fetchall()
    grouped_map = {row['day_key']: row['cnt'] for row in grouped}
    for i in range(days - 1, -1, -1):
        day = (datetime.utcnow() - timedelta(days=i)).strftime('%Y-%m-%d')
        labels.append(day)
        data.append(grouped_map.get(day, 0))
    conn.close()
    return {'labels': labels, 'data': data}


def get_chart_alerts_by_severity(alert_summary_today=None):
    """Build chart-safe values from the shared current Nepal-day summary."""
    summary = alert_summary_today or get_alert_summary_today()
    items = [
        {'key': key, 'label': key.title(), 'count': int(summary[key])}
        for key in ('medium', 'high', 'critical')
    ]
    return {'items': items, 'total': int(summary['total'])}


def get_user_activity_summary(user_id):
    conn = get_db()
    today = datetime.utcnow().strftime('%Y-%m-%d')
    user = conn.execute(
        "SELECT * FROM users WHERE id = ? AND COALESCE(is_deleted, 0) = 0",
        (user_id,),
    ).fetchone()
    if not user:
        conn.close()
        return None
    totals = conn.execute(
        "SELECT COUNT(*) AS cnt FROM access_events WHERE user_id = ?",
        (user_id,),
    ).fetchone()['cnt']
    today_count = conn.execute(
        "SELECT COUNT(*) AS cnt FROM access_events WHERE user_id = ? AND timestamp LIKE ?",
        (user_id, f'{today}%'),
    ).fetchone()['cnt']
    alerts_total = conn.execute(
        "SELECT COUNT(*) AS cnt FROM alerts WHERE user_id = ?",
        (user_id,),
    ).fetchone()['cnt']
    sev_rows = conn.execute(
        "SELECT severity, COUNT(*) AS cnt FROM alerts WHERE user_id = ? GROUP BY severity",
        (user_id,),
    ).fetchall()
    sev_map = {r['severity']: r['cnt'] for r in sev_rows}
    last_access = conn.execute(
        "SELECT MAX(timestamp) AS ts FROM access_events WHERE user_id = ?",
        (user_id,),
    ).fetchone()['ts']
    recent_events = conn.execute(
        "SELECT * FROM access_events WHERE user_id = ? ORDER BY timestamp DESC LIMIT 10",
        (user_id,),
    ).fetchall()
    recent_alerts = conn.execute(
        "SELECT * FROM alerts WHERE user_id = ? ORDER BY created_at DESC LIMIT 10",
        (user_id,),
    ).fetchall()
    conn.close()
    return {
        'user': row_to_dict(user),
        'total_records_accessed': totals,
        'records_accessed_today': today_count,
        'alerts_generated': alerts_total,
        'critical_alerts': sev_map.get('Critical', 0),
        'high_alerts': sev_map.get('High', 0),
        'medium_alerts': sev_map.get('Medium', 0),
        'last_login': user['last_login'],
        'last_access_time': last_access,
        'recent_events': [row_to_dict(r) for r in recent_events],
        'recent_alerts': [row_to_dict(r) for r in recent_alerts],
    }


def create_patient_record(data):
    now = datetime.utcnow().isoformat()
    sensitivity = normalize_sensitivity(data.get('sensitivity_level'))
    with write_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO patient_records (
                patient_code, record_title, record_category, department,
                sensitivity_level, content, patient_identifier, patient_name,
                patient_age, patient_gender, ward, admission_date, attending_doctor,
                primary_condition, clinical_notes, medication_or_treatment,
                relevant_observations, heart_rate, blood_pressure, temperature,
                oxygen_saturation, created_at, is_active
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
            """,
            (
                data['patient_code'],
                data['record_title'],
                data['record_category'],
                data['department'],
                sensitivity,
                data['content'],
                data.get('patient_identifier'),
                data.get('patient_name'),
                data.get('patient_age'),
                data.get('patient_gender'),
                data.get('ward'),
                data.get('admission_date'),
                data.get('attending_doctor'),
                data.get('primary_condition'),
                data.get('clinical_notes'),
                data.get('medication_or_treatment'),
                data.get('relevant_observations'),
                data.get('heart_rate'),
                data.get('blood_pressure'),
                data.get('temperature'),
                data.get('oxygen_saturation'),
                now,
            ),
        )
        return cursor.lastrowid


def update_patient_record(record_id, data):
    sensitivity = normalize_sensitivity(data.get('sensitivity_level'))
    with write_connection() as conn:
        conn.execute(
            """
            UPDATE patient_records
            SET patient_code = ?, record_title = ?, record_category = ?, department = ?,
                sensitivity_level = ?, content = ?, patient_identifier = ?, patient_name = ?,
                patient_age = ?, patient_gender = ?, ward = ?, admission_date = ?,
                attending_doctor = ?, primary_condition = ?, clinical_notes = ?,
                medication_or_treatment = ?, relevant_observations = ?, heart_rate = ?,
                blood_pressure = ?, temperature = ?, oxygen_saturation = ?
            WHERE id = ?
            """,
            (
                data['patient_code'],
                data['record_title'],
                data['record_category'],
                data['department'],
                sensitivity,
                data['content'],
                data.get('patient_identifier'),
                data.get('patient_name'),
                data.get('patient_age'),
                data.get('patient_gender'),
                data.get('ward'),
                data.get('admission_date'),
                data.get('attending_doctor'),
                data.get('primary_condition'),
                data.get('clinical_notes'),
                data.get('medication_or_treatment'),
                data.get('relevant_observations'),
                data.get('heart_rate'),
                data.get('blood_pressure'),
                data.get('temperature'),
                data.get('oxygen_saturation'),
                record_id,
            ),
        )


def deactivate_patient_record(record_id):
    with write_connection() as conn:
        conn.execute(
            "UPDATE patient_records SET is_active = 0 WHERE id = ?",
            (record_id,),
        )


def get_message(message_id):
    conn = get_db()
    msg = conn.execute("SELECT * FROM messages WHERE id = ?", (message_id,)).fetchone()
    conn.close()
    return row_to_dict(msg)


def send_message(sender_id, receiver_id, title, body, is_urgent=False):
    conn = get_db()
    now = datetime.utcnow().isoformat()
    conn.execute(
        """
        INSERT INTO messages (sender_id, receiver_id, title, body, is_read, is_urgent, created_at)
        VALUES (?, ?, ?, ?, 0, ?, ?)
        """,
        (sender_id, receiver_id, title, body, 1 if is_urgent else 0, now),
    )
    conn.commit()
    conn.close()


def get_messages_for_user(user_id):
    conn = get_db()
    rows = conn.execute(
        """
        SELECT m.*, u.username AS sender_username
        FROM messages m
        JOIN users u ON u.id = m.sender_id
        WHERE m.receiver_id = ? AND m.notification_type IS NULL
        ORDER BY m.created_at DESC
        """,
        (user_id,),
    ).fetchall()
    conn.close()
    return [row_to_dict(r) for r in rows]


def get_sent_messages(admin_id):
    conn = get_db()
    rows = conn.execute(
        """
        SELECT m.*, u.username AS receiver_username
        FROM messages m
        JOIN users u ON u.id = m.receiver_id
        WHERE m.sender_id = ? AND m.notification_type IS NULL
        ORDER BY m.created_at DESC
        """,
        (admin_id,),
    ).fetchall()
    conn.close()
    return [row_to_dict(r) for r in rows]


def get_unread_messages_for_user(user_id):
    conn = get_db()
    rows = conn.execute(
        """
        SELECT m.*, u.username AS sender_username
        FROM messages m
        JOIN users u ON u.id = m.sender_id
        WHERE m.receiver_id = ? AND m.is_read = 0
          AND m.notification_type IS NULL
        ORDER BY m.created_at DESC
        """,
        (user_id,),
    ).fetchall()
    conn.close()
    return [row_to_dict(r) for r in rows]


def mark_message_read(message_id, user_id):
    conn = get_db()
    now = datetime.utcnow().isoformat()
    conn.execute(
        "UPDATE messages SET is_read = 1, read_at = ? WHERE id = ? AND receiver_id = ?",
        (now, message_id, user_id),
    )
    conn.commit()
    conn.close()


def get_chart_user_registrations():
    """User registrations: last 7 days (daily) and last 30 days (daily) from users.created_at."""
    conn = get_db()
    labels_7d = []
    data_7d = []
    start_7 = (datetime.utcnow() - timedelta(days=6)).strftime('%Y-%m-%d')
    grouped_7 = conn.execute(
        """
        SELECT substr(created_at, 1, 10) AS day_key, COUNT(*) AS cnt
        FROM users
        WHERE COALESCE(is_deleted, 0) = 0
          AND substr(created_at, 1, 10) >= ?
        GROUP BY day_key
        """,
        (start_7,),
    ).fetchall()
    map_7 = {r['day_key']: r['cnt'] for r in grouped_7}
    for i in range(6, -1, -1):
        day = (datetime.utcnow() - timedelta(days=i)).strftime('%Y-%m-%d')
        labels_7d.append(day)
        data_7d.append(map_7.get(day, 0))

    labels_30d = []
    data_30d = []
    start_30 = (datetime.utcnow() - timedelta(days=29)).strftime('%Y-%m-%d')
    grouped_30 = conn.execute(
        """
        SELECT substr(created_at, 1, 10) AS day_key, COUNT(*) AS cnt
        FROM users
        WHERE COALESCE(is_deleted, 0) = 0
          AND substr(created_at, 1, 10) >= ?
        GROUP BY day_key
        """,
        (start_30,),
    ).fetchall()
    map_30 = {r['day_key']: r['cnt'] for r in grouped_30}
    for i in range(29, -1, -1):
        day = (datetime.utcnow() - timedelta(days=i)).strftime('%Y-%m-%d')
        labels_30d.append(day)
        data_30d.append(map_30.get(day, 0))

    month_start = datetime.utcnow().replace(day=1).strftime('%Y-%m-%d')
    month_total = conn.execute(
        """
        SELECT COUNT(*) AS cnt FROM users
        WHERE COALESCE(is_deleted, 0) = 0 AND substr(created_at, 1, 10) >= ?
        """,
        (month_start,),
    ).fetchone()['cnt']
    conn.close()
    return {
        'labels_7d': labels_7d,
        'data_7d': data_7d,
        'labels_30d': labels_30d,
        'data_30d': data_30d,
        'month_total': month_total,
    }


def get_admin_users():
    conn = get_db()
    rows = conn.execute(
        """
        SELECT * FROM users
        WHERE role = 'Admin' AND COALESCE(is_deleted, 0) = 0
        ORDER BY created_at DESC
        """
    ).fetchall()
    conn.close()
    return [row_to_dict(r) for r in rows]


def create_admin_user(data, created_by_id):
    """Create an Admin account (Super Admin only)."""
    if not validate_role_department('Admin', data.get('department')):
        raise ValueError('Select a valid department for the selected role.')
    data = dict(data)
    data['department'] = normalize_department(data['department'])
    conn = get_db()
    password_hash = generate_password_hash(data['password'])
    now = datetime.utcnow().isoformat()
    cursor = conn.execute(
        """
        INSERT INTO users (
            full_name, staff_id, email, username, password_hash,
            role, department, work_start, work_end,
            approval_status, is_active, approved_by, approved_at,
            must_change_password, created_at
        ) VALUES (?, ?, ?, ?, ?, 'Admin', ?, ?, ?, 'approved', 1, ?, ?, ?, ?)
        """,
        (
            data['full_name'], data['staff_id'], data['email'], data['username'],
            password_hash, data['department'], data['work_start'], data['work_end'],
            created_by_id, now, 1 if data.get('must_change_password') else 0, now,
        ),
    )
    uid = cursor.lastrowid
    conn.commit()
    conn.close()
    return uid


def update_admin_user(user_id, **kwargs):
    if kwargs.get('department') is not None and not validate_role_department(
            'Admin', kwargs.get('department')):
        raise ValueError('Select a valid department for the selected role.')
    conn = get_db()
    changed_by = kwargs.pop('changed_by', None)
    allowed = ['full_name', 'staff_id', 'email', 'username', 'department', 'work_start', 'work_end']
    username_changed = False
    for key, value in kwargs.items():
        if key in allowed and value is not None:
            if key == 'username':
                current = conn.execute(
                    "SELECT username FROM users WHERE id = ? AND role = 'Admin'",
                    (user_id,),
                ).fetchone()
                username_changed = bool(current and current['username'] != value)
            conn.execute(f'UPDATE users SET {key} = ? WHERE id = ? AND role = ?', (value, user_id, 'Admin'))
    if username_changed:
        conn.execute(
            '''
            UPDATE users SET credential_version = COALESCE(credential_version, 0) + 1,
                credentials_changed_at = ?, credentials_changed_by = ?
            WHERE id = ? AND role = 'Admin'
            ''',
            (datetime.utcnow().isoformat(), changed_by, user_id),
        )
    conn.commit()
    conn.close()


def get_unread_critical_notifications(user_id, limit=10):
    """Return safe popup metadata for one authorized recipient."""
    conn = get_db()
    rows = conn.execute(
        '''
        SELECT m.id AS notification_id, m.related_alert_id AS alert_id,
               a.username, a.department, a.created_at,
               e.action_type
        FROM messages m
        JOIN alerts a ON a.id = m.related_alert_id
        LEFT JOIN access_events e ON e.id = a.event_id
        WHERE m.receiver_id = ? AND m.is_read = 0
          AND m.notification_type = 'critical_alert'
          AND LOWER(TRIM(a.severity)) = 'critical'
        ORDER BY a.created_at DESC, a.id DESC
        LIMIT ?
        ''',
        (user_id, max(1, min(int(limit), 50))),
    ).fetchall()
    conn.close()
    return [row_to_dict(row) for row in rows]


def mark_critical_notification_seen(notification_id, user_id):
    """Mark only the current recipient's Critical notification as seen."""
    now = datetime.utcnow().isoformat()
    with write_connection() as conn:
        row = conn.execute(
            '''
            SELECT related_alert_id
            FROM messages
            WHERE id = ? AND receiver_id = ?
              AND notification_type = 'critical_alert'
            ''',
            (notification_id, user_id),
        ).fetchone()
        if not row:
            return None
        conn.execute(
            '''
            UPDATE messages SET is_read = 1, read_at = ?
            WHERE id = ? AND receiver_id = ?
              AND notification_type = 'critical_alert'
            ''',
            (now, notification_id, user_id),
        )
        return row['related_alert_id']


def set_user_password(user_id, new_password, must_change=False, changed_by=None):
    """Set a password hash, invalidate sessions, and optionally require rotation."""
    conn = get_db()
    password_hash = generate_password_hash(new_password)
    conn.execute(
        '''
        UPDATE users SET password_hash = ?, must_change_password = ?,
            credential_version = COALESCE(credential_version, 0) + 1,
            credentials_changed_at = ?, credentials_changed_by = ?
        WHERE id = ?
        ''',
        (
            password_hash, 1 if must_change else 0,
            datetime.utcnow().isoformat(), changed_by, user_id,
        ),
    )
    conn.commit()
    conn.close()


def can_delete_user(actor, target):
    """Whether actor may delete target user."""
    if target.get('is_deleted'):
        return False, 'User already deleted.'
    if actor['id'] == target['id']:
        return False, 'You cannot delete your own account.'
    if target['role'] == 'Super Admin':
        return False, 'Super Admin account cannot be deleted.'
    if target['role'] == 'Admin' and actor['role'] != 'Super Admin':
        return False, 'Only Super Admin can delete Admin accounts.'
    return True, None


def format_datetime_display(iso_str):
    if not iso_str:
        return 'N/A'
    return iso_str.replace('T', ' ')[:19]


def format_nepal_datetime(iso_str):
    """Render a stored UTC timestamp in Nepal Time without changing storage."""
    if not iso_str:
        return 'N/A'
    try:
        value = datetime.fromisoformat(str(iso_str).replace('Z', '+00:00'))
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        local = value.astimezone(ZoneInfo(Config.LOCAL_TIMEZONE))
        return local.strftime('%Y-%m-%d %H:%M:%S NPT')
    except (TypeError, ValueError):
        return str(iso_str)


def create_approved_staff_user(data, created_by_id=None):
    """Emergency staff account creation by Admin/Super Admin (pre-approved, active)."""
    if not validate_role_department(
            data.get('role'), data.get('department'), public_only=True):
        raise ValueError('Select a valid department for the selected role.')
    data = dict(data)
    data['role'] = normalize_role(data['role'])
    data['department'] = normalize_department(data['department'])
    conn = get_db()
    password_hash = generate_password_hash(data['password'])
    now = datetime.utcnow().isoformat()
    cursor = conn.execute(
        """
        INSERT INTO users (
            full_name, staff_id, email, username, password_hash,
            role, department, work_start, work_end,
            approval_status, is_active, approved_by, approved_at,
            must_change_password, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'approved', 1, ?, ?, ?, ?)
        """,
        (
            data['full_name'], data['staff_id'], data['email'], data['username'],
            password_hash, data['role'], data['department'], data['work_start'],
            data['work_end'], created_by_id, now,
            1 if data.get('must_change_password') else 0, now,
        ),
    )
    user_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return user_id


def delete_alert(alert_id):
    conn = get_db()
    conn.execute('DELETE FROM alerts WHERE id = ?', (alert_id,))
    conn.commit()
    conn.close()


def delete_message(message_id, sender_id=None):
    conn = get_db()
    if sender_id:
        conn.execute('DELETE FROM messages WHERE id = ? AND sender_id = ?', (message_id, sender_id))
    else:
        conn.execute('DELETE FROM messages WHERE id = ?', (message_id,))
    conn.commit()
    conn.close()


# --- USB monitoring ---

USB_DEVICE_STATUSES = ('pending', 'whitelisted', 'blocked')


def normalize_usb_serial(value):
    """Canonicalise a stable USB identifier for matching and deduplication."""
    return '-'.join(str(value or '').strip().upper().split())


def get_usb_device(device_id):
    conn = get_db()
    row = conn.execute(
        '''
        SELECT d.*, u.full_name AS last_user_name,
               a.full_name AS status_changed_by_name
        FROM usb_devices d
        LEFT JOIN users u ON u.id = d.last_user_id
        LEFT JOIN users a ON a.id = d.status_changed_by
        WHERE d.id = ?
        ''',
        (device_id,),
    ).fetchone()
    conn.close()
    return row_to_dict(row)


def get_usb_device_by_serial(usb_serial):
    serial = normalize_usb_serial(usb_serial)
    if not serial:
        return None
    conn = get_db()
    row = conn.execute(
        'SELECT * FROM usb_devices WHERE UPPER(TRIM(usb_serial)) = ?',
        (serial,),
    ).fetchone()
    conn.close()
    return row_to_dict(row)


def get_usb_devices(whitelisted_only=False, status=None):
    conn = get_db()
    query = '''
        SELECT d.*, u.full_name AS last_user_name,
               a.full_name AS status_changed_by_name
        FROM usb_devices d
        LEFT JOIN users u ON u.id = d.last_user_id
        LEFT JOIN users a ON a.id = d.status_changed_by
        WHERE 1=1
    '''
    params = []
    if whitelisted_only:
        query += " AND d.status = 'whitelisted'"
    elif status in USB_DEVICE_STATUSES:
        query += ' AND d.status = ?'
        params.append(status)
    query += " ORDER BY CASE d.status WHEN 'pending' THEN 1 WHEN 'blocked' THEN 2 ELSE 3 END, d.last_seen DESC, d.id DESC"
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [row_to_dict(r) for r in rows]


def register_usb_device(usb_info, user=None, computer_name=None, browser_info=None):
    """Create or refresh the single inventory row for a detected USB device."""
    serial = normalize_usb_serial(
        usb_info.get('usb_serial')
        or usb_info.get('simulation_identifier')
    )
    if not serial:
        raise ValueError('A stable USB serial or simulation identifier is required.')

    user_dict = getattr(user, '_raw', user) or {}
    now = datetime.utcnow().isoformat()
    usb_name = str(usb_info.get('usb_name') or 'Detected USB').strip()[:120]
    usb_size = str(usb_info.get('usb_size') or '').strip()[:40]
    drive = str(usb_info.get('drive_letter') or '').strip().upper()[:20]
    vendor_id = str(usb_info.get('vendor_id') or '').strip().upper()[:40]
    product_id = str(usb_info.get('product_id') or '').strip().upper()[:40]
    computer_name = str(computer_name or 'Web session').strip()[:120]
    browser_info = str(browser_info or '').strip()[:500]

    conn = get_db()
    row = conn.execute(
        'SELECT * FROM usb_devices WHERE UPPER(TRIM(usb_serial)) = ?',
        (serial,),
    ).fetchone()
    if row:
        device_id = row['id']
        conn.execute(
            '''
            UPDATE usb_devices SET
                usb_name = COALESCE(NULLIF(?, ''), usb_name),
                usb_size = COALESCE(NULLIF(?, ''), usb_size),
                vendor_id = COALESCE(NULLIF(?, ''), vendor_id),
                product_id = COALESCE(NULLIF(?, ''), product_id),
                current_drive = COALESCE(NULLIF(?, ''), current_drive),
                last_seen = ?, last_user_id = COALESCE(?, last_user_id),
                last_staff_id = COALESCE(NULLIF(?, ''), last_staff_id),
                last_computer_name = COALESCE(NULLIF(?, ''), last_computer_name),
                last_browser = COALESCE(NULLIF(?, ''), last_browser)
            WHERE id = ?
            ''',
            (
                usb_name, usb_size, vendor_id, product_id, drive, now,
                user_dict.get('id'), user_dict.get('staff_id'), computer_name,
                browser_info, device_id,
            ),
        )
    else:
        cursor = conn.execute(
            '''
            INSERT INTO usb_devices (
                usb_name, usb_serial, usb_size, vendor_id, product_id,
                current_drive, status, is_whitelisted, added_at,
                first_seen, last_seen, last_user_id, last_staff_id,
                last_computer_name, last_browser, notes
            ) VALUES (?, ?, ?, ?, ?, ?, 'pending', 0, ?, ?, ?, ?, ?, ?, ?, '')
            ''',
            (
                usb_name, serial, usb_size, vendor_id, product_id, drive,
                now, now, now, user_dict.get('id'), user_dict.get('staff_id'),
                computer_name, browser_info,
            ),
        )
        device_id = cursor.lastrowid
    conn.commit()
    row = conn.execute('SELECT * FROM usb_devices WHERE id = ?', (device_id,)).fetchone()
    conn.close()
    return row_to_dict(row)


def set_usb_device_status(device_id, new_status, admin_id, notes=''):
    """Change persistent device policy state and record an immutable audit entry."""
    if new_status not in USB_DEVICE_STATUSES:
        raise ValueError('Invalid USB device status.')
    conn = get_db()
    device = conn.execute('SELECT * FROM usb_devices WHERE id = ?', (device_id,)).fetchone()
    if not device:
        conn.close()
        return None
    previous_status = device['status'] if device['status'] in USB_DEVICE_STATUSES else (
        'whitelisted' if device['is_whitelisted'] else 'pending'
    )
    now = datetime.utcnow().isoformat()
    clean_notes = str(notes or '').strip()[:1000]
    conn.execute(
        '''
        UPDATE usb_devices SET status = ?, is_whitelisted = ?,
            status_changed_by = ?, status_changed_at = ?,
            notes = CASE WHEN ? <> '' THEN ? ELSE notes END
        WHERE id = ?
        ''',
        (
            new_status, 1 if new_status == 'whitelisted' else 0,
            admin_id, now, clean_notes, clean_notes, device_id,
        ),
    )
    conn.execute(
        '''
        INSERT INTO usb_device_actions (
            device_id, admin_id, previous_status, new_status, notes, timestamp
        ) VALUES (?, ?, ?, ?, ?, ?)
        ''',
        (device_id, admin_id, previous_status, new_status, clean_notes, now),
    )
    conn.commit()
    row = conn.execute('SELECT * FROM usb_devices WHERE id = ?', (device_id,)).fetchone()
    conn.close()
    return row_to_dict(row)


def add_usb_to_whitelist(data, added_by_id):
    device = register_usb_device(data)
    conn = get_db()
    conn.execute(
        'UPDATE usb_devices SET added_by = COALESCE(added_by, ?) WHERE id = ?',
        (added_by_id, device['id']),
    )
    conn.commit()
    conn.close()
    set_usb_device_status(device['id'], 'whitelisted', added_by_id, data.get('notes', ''))
    return device['id']


def remove_usb_from_whitelist(device_id, admin_id, notes=''):
    return set_usb_device_status(device_id, 'pending', admin_id, notes)


def get_usb_device_actions(device_id):
    conn = get_db()
    rows = conn.execute(
        '''
        SELECT a.*, u.full_name AS admin_name
        FROM usb_device_actions a
        JOIN users u ON u.id = a.admin_id
        WHERE a.device_id = ? ORDER BY a.timestamp DESC
        ''',
        (device_id,),
    ).fetchall()
    conn.close()
    return [row_to_dict(row) for row in rows]


def get_usb_events(filters=None):
    filters = filters or {}
    conn = get_db()
    query = '''
        SELECT e.*, d.status AS device_status,
               d.id AS inventory_device_id, d.current_drive AS inventory_drive,
               ae.rule_score, ae.anomaly_score, ae.hybrid_score,
               ae.anomaly_method, ae.baseline_source, ae.model_version,
               ae.model_confidence, ae.explanation_json
        FROM usb_events e
        LEFT JOIN usb_devices d ON d.id = e.device_id
        LEFT JOIN access_events ae ON ae.id = e.access_event_id
        WHERE 1=1
    '''
    params = []
    if filters.get('username'):
        query += ' AND e.username LIKE ?'
        params.append(f"%{filters['username']}%")
    if filters.get('user_id'):
        query += ' AND e.user_id = ?'
        params.append(filters['user_id'])
    if filters.get('date_from'):
        query += ' AND e.timestamp >= ?'
        params.append(filters['date_from'])
    if filters.get('date_to'):
        query += ' AND e.timestamp <= ?'
        params.append(f"{filters['date_to']}T23:59:59")
    if filters.get('computer_name'):
        query += ' AND e.computer_name LIKE ?'
        params.append(f"%{filters['computer_name']}%")
    if filters.get('event_type'):
        query += ' AND e.event_type = ?'
        params.append(filters['event_type'])
    if filters.get('risk_level'):
        query += ' AND e.risk_level = ?'
        params.append(filters['risk_level'])
    if filters.get('device_id'):
        query += ' AND e.device_id = ?'
        params.append(filters['device_id'])
    if filters.get('usb_query'):
        query += ' AND (e.usb_serial LIKE ? OR e.usb_name LIKE ?)'
        value = f"%{filters['usb_query']}%"
        params.extend((value, value))
    if filters.get('device_status') in USB_DEVICE_STATUSES:
        query += ' AND d.status = ?'
        params.append(filters['device_status'])
    query += ' ORDER BY e.timestamp DESC LIMIT 200'
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [_enrich_explainability(row_to_dict(row)) for row in rows]


# --- Security management ---

def get_security_dashboard_stats():
    conn = get_db()
    today = datetime.utcnow().strftime('%Y-%m-%d')
    failed_today = conn.execute(
        """
        SELECT COUNT(*) as cnt FROM login_history
        WHERE success = 0 AND timestamp LIKE ?
        """,
        (f'{today}%',),
    ).fetchone()['cnt']
    locked_now = conn.execute(
        """
        SELECT COUNT(*) as cnt FROM users
        WHERE locked_until IS NOT NULL AND locked_until > ?
        AND COALESCE(is_deleted, 0) = 0
        """,
        (datetime.utcnow().isoformat(),),
    ).fetchone()['cnt']
    success_today = conn.execute(
        """
        SELECT COUNT(*) as cnt FROM login_history
        WHERE success = 1 AND timestamp LIKE ?
        """,
        (f'{today}%',),
    ).fetchone()['cnt']
    suspended = conn.execute(
        """
        SELECT COUNT(*) as cnt FROM users
        WHERE approval_status = 'suspended' AND COALESCE(is_deleted, 0) = 0
        """
    ).fetchone()['cnt']
    conn.close()
    return {
        'failed_attempts_today': failed_today,
        'locked_accounts': locked_now,
        'successful_logins_today': success_today,
        'suspended_accounts': suspended,
    }


def get_recent_failed_logins(limit=50):
    conn = get_db()
    rows = conn.execute(
        '''
        SELECT lh.*, u.staff_id, u.approval_status,
               CASE WHEN u.locked_until IS NOT NULL AND u.locked_until > ? THEN 1 ELSE 0 END AS is_locked
        FROM login_history lh
        LEFT JOIN users u ON lh.user_id = u.id
        WHERE lh.success = 0
        ORDER BY lh.timestamp DESC
        LIMIT ?
        ''',
        (datetime.utcnow().isoformat(), limit),
    ).fetchall()
    conn.close()
    return [row_to_dict(r) for r in rows]


def get_locked_accounts():
    conn = get_db()
    now = datetime.utcnow().isoformat()
    rows = conn.execute(
        '''
        SELECT id, username, staff_id, role, department, failed_attempts, locked_until
        FROM users
        WHERE locked_until IS NOT NULL AND locked_until > ?
        AND COALESCE(is_deleted, 0) = 0
        ORDER BY locked_until DESC
        ''',
        (now,),
    ).fetchall()
    conn.close()
    return [row_to_dict(r) for r in rows]
