"""SQLite database initialization and connection helpers."""
import os
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime

from werkzeug.security import generate_password_hash

from config import Config


def get_db():
    """Return a database connection with row factory."""
    os.makedirs(os.path.dirname(Config.DATABASE_PATH), exist_ok=True)
    busy_timeout_ms = max(int(Config.SQLITE_BUSY_TIMEOUT_MS), 1000)
    conn = sqlite3.connect(
        Config.DATABASE_PATH,
        timeout=busy_timeout_ms / 1000,
    )
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    conn.execute(f'PRAGMA busy_timeout = {busy_timeout_ms}')
    conn.execute('PRAGMA synchronous = NORMAL')
    return conn


@contextmanager
def write_connection():
    """Commit one write unit or always roll it back and close on failure."""
    conn = get_db()
    try:
        yield conn
        conn.commit()
    except Exception:
        if conn.in_transaction:
            conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    """Create all tables if they do not exist."""
    conn = get_db()
    # WAL lets readers continue while a writer commits. It is persistent for
    # future connections; busy_timeout handles brief races between writers.
    conn.execute('PRAGMA journal_mode = WAL')
    conn.execute('PRAGMA wal_autocheckpoint = 1000')
    cursor = conn.cursor()

    cursor.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            staff_id TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            department TEXT NOT NULL,
            work_start TEXT NOT NULL,
            work_end TEXT NOT NULL,
            approval_status TEXT NOT NULL DEFAULT 'pending',
            is_active INTEGER NOT NULL DEFAULT 1,
            is_deleted INTEGER NOT NULL DEFAULT 0,
            approved_by INTEGER,
            approved_at TEXT,
            rejection_reason TEXT,
            must_change_password INTEGER NOT NULL DEFAULT 0,
            credential_version INTEGER NOT NULL DEFAULT 0,
            credentials_changed_at TEXT,
            credentials_changed_by INTEGER,
            preferred_language TEXT NOT NULL DEFAULT 'en'
                CHECK (preferred_language IN ('en', 'ne')),
            created_at TEXT NOT NULL,
            last_login TEXT,
            FOREIGN KEY (approved_by) REFERENCES users(id),
            FOREIGN KEY (credentials_changed_by) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS patient_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_code TEXT NOT NULL UNIQUE,
            record_title TEXT NOT NULL,
            record_category TEXT NOT NULL,
            department TEXT NOT NULL,
            sensitivity_level TEXT NOT NULL,
            content TEXT NOT NULL,
            patient_identifier TEXT,
            patient_name TEXT,
            patient_age INTEGER,
            patient_gender TEXT,
            ward TEXT,
            admission_date TEXT,
            attending_doctor TEXT,
            primary_condition TEXT,
            clinical_notes TEXT,
            medication_or_treatment TEXT,
            relevant_observations TEXT,
            heart_rate INTEGER,
            blood_pressure TEXT,
            temperature REAL,
            oxygen_saturation REAL,
            created_at TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS access_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            staff_id TEXT NOT NULL,
            role TEXT NOT NULL,
            department TEXT NOT NULL,
            record_id INTEGER,
            record_category TEXT,
            sensitivity_level TEXT,
            action_type TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            ip_address TEXT,
            computer_name TEXT,
            is_after_hours INTEGER NOT NULL DEFAULT 0,
            is_sensitive INTEGER NOT NULL DEFAULT 0,
            department_match INTEGER NOT NULL DEFAULT 0,
            rule_result TEXT,
            ml_score INTEGER DEFAULT 0,
            rule_score INTEGER,
            anomaly_score INTEGER,
            hybrid_score INTEGER,
            baseline_source TEXT,
            anomaly_method TEXT,
            model_version TEXT,
            model_raw_score REAL,
            model_confidence TEXT,
            minimum_risk_override TEXT,
            human_review_required INTEGER NOT NULL DEFAULT 0,
            explanation_json TEXT,
            browser_info TEXT,
            final_risk_level TEXT NOT NULL DEFAULT 'Normal',
            alert_created INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (record_id) REFERENCES patient_records(id)
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            role TEXT NOT NULL,
            department TEXT NOT NULL,
            record_id INTEGER,
            severity TEXT NOT NULL,
            reason TEXT NOT NULL,
            triggered_rules TEXT,
            ml_score INTEGER DEFAULT 0,
            rule_score INTEGER,
            anomaly_score INTEGER,
            hybrid_score INTEGER,
            baseline_source TEXT,
            anomaly_method TEXT,
            model_version TEXT,
            model_confidence TEXT,
            minimum_risk_override TEXT,
            human_review_required INTEGER NOT NULL DEFAULT 1,
            explanation_json TEXT,
            status TEXT NOT NULL DEFAULT 'open',
            created_at TEXT NOT NULL,
            resolved_by INTEGER,
            resolved_at TEXT,
            notes TEXT,
            FOREIGN KEY (event_id) REFERENCES access_events(id),
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (resolved_by) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS login_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            success INTEGER NOT NULL,
            failure_reason TEXT,
            ip_address TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS admin_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id INTEGER NOT NULL,
            action_type TEXT NOT NULL,
            target_user_id INTEGER,
            details TEXT,
            timestamp TEXT NOT NULL,
            FOREIGN KEY (admin_id) REFERENCES users(id),
            FOREIGN KEY (target_user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_type TEXT NOT NULL,
            report_date TEXT NOT NULL,
            generated_by INTEGER,
            generated_at TEXT NOT NULL,
            file_path TEXT NOT NULL,
            format TEXT NOT NULL DEFAULT 'csv',
            FOREIGN KEY (generated_by) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            is_read INTEGER NOT NULL DEFAULT 0,
            is_urgent INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            read_at TEXT,
            FOREIGN KEY (sender_id) REFERENCES users(id),
            FOREIGN KEY (receiver_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS account_recovery_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            public_reference TEXT NOT NULL UNIQUE,
            request_type TEXT NOT NULL,
            submitted_staff_id TEXT NOT NULL,
            submitted_name TEXT NOT NULL,
            submitted_email TEXT,
            submitted_department TEXT NOT NULL,
            submitted_role TEXT NOT NULL,
            requested_destination TEXT NOT NULL,
            message TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            matched_user_id INTEGER,
            assigned_admin_id INTEGER,
            review_notes TEXT,
            identity_verification_notes TEXT,
            identity_verification_method TEXT,
            identity_verified_by_id INTEGER,
            resolution_type TEXT,
            created_at TEXT NOT NULL,
            review_started_at TEXT,
            identity_verified_at TEXT,
            completed_at TEXT,
            rejected_at TEXT,
            completed_by_id INTEGER,
            request_ip TEXT,
            request_user_agent TEXT,
            FOREIGN KEY (matched_user_id) REFERENCES users(id),
            FOREIGN KEY (assigned_admin_id) REFERENCES users(id),
            FOREIGN KEY (identity_verified_by_id) REFERENCES users(id),
            FOREIGN KEY (completed_by_id) REFERENCES users(id)
        );

        CREATE INDEX IF NOT EXISTS idx_access_timestamp ON access_events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_access_user ON access_events(user_id);
        CREATE INDEX IF NOT EXISTS idx_access_risk ON access_events(final_risk_level);
        CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
        CREATE INDEX IF NOT EXISTS idx_users_approval ON users(approval_status);
        CREATE INDEX IF NOT EXISTS idx_messages_receiver_read ON messages(receiver_id, is_read);
        CREATE INDEX IF NOT EXISTS idx_recovery_status_created
            ON account_recovery_requests(status, created_at);
        CREATE INDEX IF NOT EXISTS idx_recovery_staff_type
            ON account_recovery_requests(submitted_staff_id, request_type);
        CREATE INDEX IF NOT EXISTS idx_recovery_ip_created
            ON account_recovery_requests(request_ip, created_at);
        CREATE INDEX IF NOT EXISTS idx_recovery_destination
            ON account_recovery_requests(requested_destination, status);

        CREATE TABLE IF NOT EXISTS usb_devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usb_name TEXT NOT NULL,
            usb_serial TEXT NOT NULL UNIQUE,
            usb_size TEXT,
            vendor_id TEXT,
            product_id TEXT,
            current_drive TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            is_whitelisted INTEGER NOT NULL DEFAULT 0,
            added_by INTEGER,
            added_at TEXT NOT NULL,
            first_seen TEXT,
            last_seen TEXT,
            last_user_id INTEGER,
            last_staff_id TEXT,
            last_computer_name TEXT,
            last_browser TEXT,
            status_changed_by INTEGER,
            status_changed_at TEXT,
            notes TEXT,
            FOREIGN KEY (added_by) REFERENCES users(id),
            FOREIGN KEY (last_user_id) REFERENCES users(id),
            FOREIGN KEY (status_changed_by) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS usb_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            staff_id TEXT NOT NULL,
            role TEXT NOT NULL,
            department TEXT NOT NULL,
            computer_name TEXT,
            event_type TEXT NOT NULL,
            usb_name TEXT NOT NULL,
            usb_serial TEXT NOT NULL,
            usb_size TEXT,
            drive_letter TEXT,
            is_whitelisted INTEGER NOT NULL DEFAULT 0,
            timestamp TEXT NOT NULL,
            risk_level TEXT NOT NULL DEFAULT 'Normal',
            alert_created INTEGER NOT NULL DEFAULT 0,
            device_id INTEGER,
            access_event_id INTEGER,
            browser_info TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (device_id) REFERENCES usb_devices(id),
            FOREIGN KEY (access_event_id) REFERENCES access_events(id)
        );

        CREATE TABLE IF NOT EXISTS usb_device_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            admin_id INTEGER NOT NULL,
            previous_status TEXT NOT NULL,
            new_status TEXT NOT NULL,
            notes TEXT,
            timestamp TEXT NOT NULL,
            FOREIGN KEY (device_id) REFERENCES usb_devices(id),
            FOREIGN KEY (admin_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS model_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            model_type TEXT NOT NULL,
            model_version TEXT NOT NULL,
            trained_at TEXT NOT NULL,
            training_events INTEGER NOT NULL,
            feature_names TEXT NOT NULL,
            parameters TEXT,
            random_seed INTEGER,
            baseline_scope TEXT,
            validation_summary TEXT,
            artifact_path TEXT,
            trained_by INTEGER,
            status TEXT NOT NULL,
            error_message TEXT,
            FOREIGN KEY (trained_by) REFERENCES users(id)
        );

        CREATE INDEX IF NOT EXISTS idx_usb_events_timestamp ON usb_events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_usb_events_user ON usb_events(user_id);
        CREATE INDEX IF NOT EXISTS idx_usb_events_risk ON usb_events(risk_level);
        CREATE INDEX IF NOT EXISTS idx_usb_device_actions_device ON usb_device_actions(device_id);
        CREATE INDEX IF NOT EXISTS idx_model_runs_trained_at ON model_runs(trained_at);
    ''')

    migrate_schema(cursor)
    migrate_usb_inventory(cursor)
    migrate_explainability(cursor)
    conn.commit()
    conn.close()
    ensure_super_admin()


def ensure_super_admin():
    """Ensure built-in Super Admin exists (fixes existing databases without reseed)."""
    conn = get_db()
    row = conn.execute(
        "SELECT id, role FROM users WHERE username = ? AND COALESCE(is_deleted, 0) = 0",
        ('superadmin',),
    ).fetchone()
    now = datetime.utcnow().isoformat()
    pw = generate_password_hash('Super@123')

    if row is None:
        conn.execute(
            """
            INSERT INTO users (
                full_name, staff_id, email, username, password_hash,
                role, department, work_start, work_end,
                approval_status, is_active, is_deleted, created_at
            ) VALUES (?, ?, ?, ?, ?, 'Super Admin', 'Administration', '08:00', '17:00',
                'approved', 1, 0, ?)
            """,
            (
                'Super Administrator', 'SAD001', 'superadmin@hospital.demo',
                'superadmin', pw, now,
            ),
        )
    elif row['role'] != 'Super Admin':
        conn.execute(
            """
            UPDATE users SET role = 'Super Admin', approval_status = 'approved',
                is_active = 1, is_deleted = 0
            WHERE username = ?
            """,
            ('superadmin',),
        )
    conn.commit()
    conn.close()


def migrate_schema(cursor):
    """Lightweight migration for existing databases."""
    table_columns = {}
    for table in [
        'users', 'patient_records', 'messages', 'usb_devices', 'usb_events',
        'access_events', 'alerts',
    ]:
        exists = cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
            (table,),
        ).fetchone()
        if not exists:
            continue
        rows = cursor.execute(f'PRAGMA table_info({table})').fetchall()
        table_columns[table] = {row[1] for row in rows}

    users_cols = table_columns.get('users', set())
    if users_cols:
        if 'is_deleted' not in users_cols:
            cursor.execute("ALTER TABLE users ADD COLUMN is_deleted INTEGER NOT NULL DEFAULT 0")
        if 'approval_status' not in users_cols:
            cursor.execute("ALTER TABLE users ADD COLUMN approval_status TEXT NOT NULL DEFAULT 'pending'")
        if 'is_active' not in users_cols:
            cursor.execute("ALTER TABLE users ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1")
        if 'work_start' not in users_cols:
            cursor.execute("ALTER TABLE users ADD COLUMN work_start TEXT NOT NULL DEFAULT '08:00'")
        if 'work_end' not in users_cols:
            cursor.execute("ALTER TABLE users ADD COLUMN work_end TEXT NOT NULL DEFAULT '17:00'")
        if 'last_login' not in users_cols:
            cursor.execute("ALTER TABLE users ADD COLUMN last_login TEXT")
        if 'approved_by' not in users_cols:
            cursor.execute("ALTER TABLE users ADD COLUMN approved_by INTEGER")
        if 'approved_at' not in users_cols:
            cursor.execute("ALTER TABLE users ADD COLUMN approved_at TEXT")
        if 'rejection_reason' not in users_cols:
            cursor.execute("ALTER TABLE users ADD COLUMN rejection_reason TEXT")
        if 'failed_attempts' not in users_cols:
            cursor.execute("ALTER TABLE users ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0")
        if 'locked_until' not in users_cols:
            cursor.execute("ALTER TABLE users ADD COLUMN locked_until TEXT")
        if 'last_failed_login' not in users_cols:
            cursor.execute("ALTER TABLE users ADD COLUMN last_failed_login TEXT")
        if 'must_change_password' not in users_cols:
            cursor.execute(
                "ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0"
            )
        if 'credential_version' not in users_cols:
            cursor.execute(
                "ALTER TABLE users ADD COLUMN credential_version INTEGER NOT NULL DEFAULT 0"
            )
        if 'credentials_changed_at' not in users_cols:
            cursor.execute("ALTER TABLE users ADD COLUMN credentials_changed_at TEXT")
        if 'credentials_changed_by' not in users_cols:
            cursor.execute("ALTER TABLE users ADD COLUMN credentials_changed_by INTEGER")
        if 'preferred_language' not in users_cols:
            cursor.execute(
                "ALTER TABLE users ADD COLUMN preferred_language TEXT NOT NULL DEFAULT 'en'"
            )

    rec_cols = table_columns.get('patient_records', set())
    if rec_cols:
        patient_record_columns = {
            'is_active': 'INTEGER NOT NULL DEFAULT 1',
            'patient_identifier': 'TEXT',
            'patient_name': 'TEXT',
            'patient_age': 'INTEGER',
            'patient_gender': 'TEXT',
            'ward': 'TEXT',
            'admission_date': 'TEXT',
            'attending_doctor': 'TEXT',
            'primary_condition': 'TEXT',
            'clinical_notes': 'TEXT',
            'medication_or_treatment': 'TEXT',
            'relevant_observations': 'TEXT',
            'heart_rate': 'INTEGER',
            'blood_pressure': 'TEXT',
            'temperature': 'REAL',
            'oxygen_saturation': 'REAL',
        }
        for column_name, column_type in patient_record_columns.items():
            if column_name not in rec_cols:
                cursor.execute(
                    f'ALTER TABLE patient_records ADD COLUMN {column_name} {column_type}'
                )

    usb_device_cols = table_columns.get('usb_devices', set())
    if usb_device_cols:
        usb_device_columns = {
            'vendor_id': 'TEXT',
            'product_id': 'TEXT',
            'current_drive': 'TEXT',
            'status': "TEXT NOT NULL DEFAULT 'pending'",
            'first_seen': 'TEXT',
            'last_seen': 'TEXT',
            'last_user_id': 'INTEGER',
            'last_staff_id': 'TEXT',
            'last_computer_name': 'TEXT',
            'last_browser': 'TEXT',
            'status_changed_by': 'INTEGER',
            'status_changed_at': 'TEXT',
        }
        for column_name, column_type in usb_device_columns.items():
            if column_name not in usb_device_cols:
                cursor.execute(
                    f'ALTER TABLE usb_devices ADD COLUMN {column_name} {column_type}'
                )

    usb_event_cols = table_columns.get('usb_events', set())
    if usb_event_cols:
        if 'device_id' not in usb_event_cols:
            cursor.execute('ALTER TABLE usb_events ADD COLUMN device_id INTEGER')
        if 'access_event_id' not in usb_event_cols:
            cursor.execute('ALTER TABLE usb_events ADD COLUMN access_event_id INTEGER')
        if 'browser_info' not in usb_event_cols:
            cursor.execute('ALTER TABLE usb_events ADD COLUMN browser_info TEXT')

    access_cols = table_columns.get('access_events', set())
    if access_cols:
        access_columns = {
            'rule_score': 'INTEGER',
            'anomaly_score': 'INTEGER',
            'hybrid_score': 'INTEGER',
            'baseline_source': 'TEXT',
            'anomaly_method': 'TEXT',
            'model_version': 'TEXT',
            'model_raw_score': 'REAL',
            'model_confidence': 'TEXT',
            'minimum_risk_override': 'TEXT',
            'human_review_required': 'INTEGER NOT NULL DEFAULT 0',
            'explanation_json': 'TEXT',
            'browser_info': 'TEXT',
        }
        for column_name, column_type in access_columns.items():
            if column_name not in access_cols:
                cursor.execute(
                    f'ALTER TABLE access_events ADD COLUMN {column_name} {column_type}'
                )

    alert_cols = table_columns.get('alerts', set())
    if alert_cols:
        alert_columns = {
            'rule_score': 'INTEGER',
            'anomaly_score': 'INTEGER',
            'hybrid_score': 'INTEGER',
            'baseline_source': 'TEXT',
            'anomaly_method': 'TEXT',
            'model_version': 'TEXT',
            'model_confidence': 'TEXT',
            'minimum_risk_override': 'TEXT',
            'human_review_required': 'INTEGER NOT NULL DEFAULT 1',
            'explanation_json': 'TEXT',
        }
        for column_name, column_type in alert_columns.items():
            if column_name not in alert_cols:
                cursor.execute(
                    f'ALTER TABLE alerts ADD COLUMN {column_name} {column_type}'
                )


def _normalise_usb_serial(value):
    """Return the canonical serial representation used by the inventory."""
    return '-'.join(str(value or '').strip().upper().split())


def _looks_like_browser(value):
    text = str(value or '').strip().lower()
    return text.startswith(('mozilla/', 'chrome/', 'safari/', 'edge/', 'edg/', 'opera/', 'curl/'))


def migrate_usb_inventory(cursor):
    """Backfill one persistent device row per historical USB serial."""
    device_table = cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='usb_devices'"
    ).fetchone()
    event_table = cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='usb_events'"
    ).fetchone()
    if not device_table or not event_table:
        return

    now = datetime.utcnow().isoformat()
    existing = cursor.execute('SELECT * FROM usb_devices ORDER BY id').fetchall()
    for row in existing:
        row = dict(row)
        serial = _normalise_usb_serial(row.get('usb_serial'))
        if not serial:
            continue
        duplicate = cursor.execute(
            '''
            SELECT id FROM usb_devices
            WHERE UPPER(TRIM(usb_serial)) = ? AND id <> ? LIMIT 1
            ''',
            (serial, row['id']),
        ).fetchone()
        if not duplicate and row.get('usb_serial') != serial:
            cursor.execute(
                'UPDATE usb_devices SET usb_serial = ? WHERE id = ?',
                (serial, row['id']),
            )
        status = row.get('status')
        if status not in ('pending', 'whitelisted', 'blocked'):
            status = 'whitelisted' if row.get('is_whitelisted') else 'pending'
        elif status == 'pending' and row.get('is_whitelisted') and not row.get('status_changed_at'):
            # A legacy whitelist row receives the new column's pending default
            # during ALTER TABLE; preserve its prior approved state.
            status = 'whitelisted'
        cursor.execute(
            '''
            UPDATE usb_devices
            SET status = ?, is_whitelisted = ?,
                first_seen = COALESCE(first_seen, added_at, ?),
                last_seen = COALESCE(last_seen, added_at, ?)
            WHERE id = ?
            ''',
            (status, 1 if status == 'whitelisted' else 0, now, now, row['id']),
        )

    serial_rows = cursor.execute(
        '''
        SELECT UPPER(TRIM(usb_serial)) AS serial_key
        FROM usb_events
        WHERE TRIM(COALESCE(usb_serial, '')) <> ''
        GROUP BY UPPER(TRIM(usb_serial))
        '''
    ).fetchall()
    for serial_row in serial_rows:
        serial = _normalise_usb_serial(serial_row[0])
        if not serial:
            continue
        events = cursor.execute(
            '''
            SELECT * FROM usb_events
            WHERE UPPER(TRIM(usb_serial)) = ?
            ORDER BY timestamp ASC, id ASC
            ''',
            (serial_row[0],),
        ).fetchall()
        first_event = dict(events[0])
        last_event = dict(events[-1])
        device = cursor.execute(
            'SELECT * FROM usb_devices WHERE UPPER(TRIM(usb_serial)) = ? ORDER BY id LIMIT 1',
            (serial_row[0],),
        ).fetchone()
        historically_whitelisted = any(
            dict(event).get('is_whitelisted')
            or dict(event).get('event_type') == 'whitelisted_insert'
            for event in events
        )

        if device:
            device = dict(device)
            device_id = device['id']
            status = device.get('status')
            if status not in ('pending', 'whitelisted', 'blocked'):
                status = 'whitelisted' if device.get('is_whitelisted') else 'pending'
            if historically_whitelisted and status == 'pending':
                status = 'whitelisted'
            cursor.execute(
                '''
                UPDATE usb_devices SET
                    usb_name = COALESCE(NULLIF(?, ''), usb_name),
                    usb_size = COALESCE(NULLIF(?, ''), usb_size),
                    current_drive = COALESCE(NULLIF(?, ''), current_drive),
                    status = ?, is_whitelisted = ?,
                    first_seen = COALESCE(first_seen, ?),
                    last_seen = CASE WHEN COALESCE(last_seen, '') < ? THEN ? ELSE last_seen END,
                    last_user_id = ?, last_staff_id = ?,
                    last_computer_name = COALESCE(NULLIF(?, ''), last_computer_name)
                WHERE id = ?
                ''',
                (
                    last_event.get('usb_name'), last_event.get('usb_size'),
                    last_event.get('drive_letter'), status,
                    1 if status == 'whitelisted' else 0,
                    first_event.get('timestamp'), last_event.get('timestamp'),
                    last_event.get('timestamp'), last_event.get('user_id'),
                    last_event.get('staff_id'), last_event.get('computer_name'), device_id,
                ),
            )
        else:
            status = 'whitelisted' if historically_whitelisted else 'pending'
            cursor.execute(
                '''
                INSERT INTO usb_devices (
                    usb_name, usb_serial, usb_size, current_drive, status,
                    is_whitelisted, added_at, first_seen, last_seen,
                    last_user_id, last_staff_id, last_computer_name, notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''',
                (
                    last_event.get('usb_name') or 'Detected USB', serial,
                    last_event.get('usb_size'), last_event.get('drive_letter'), status,
                    1 if status == 'whitelisted' else 0,
                    first_event.get('timestamp') or now,
                    first_event.get('timestamp') or now,
                    last_event.get('timestamp') or now,
                    last_event.get('user_id'), last_event.get('staff_id'),
                    last_event.get('computer_name'),
                    'Migrated automatically from historical USB events.',
                ),
            )
            device_id = cursor.lastrowid

        cursor.execute(
            '''
            UPDATE usb_events
            SET device_id = ?, usb_serial = ?,
                is_whitelisted = CASE WHEN event_type = 'whitelisted_insert' THEN 1 ELSE is_whitelisted END
            WHERE UPPER(TRIM(usb_serial)) = ?
            ''',
            (device_id, serial, serial_row[0]),
        )

    browser_rows = cursor.execute(
        'SELECT id, computer_name FROM usb_events WHERE browser_info IS NULL'
    ).fetchall()
    for event_id, computer_name in browser_rows:
        if _looks_like_browser(computer_name):
            cursor.execute(
                'UPDATE usb_events SET browser_info = ?, computer_name = ? WHERE id = ?',
                (computer_name, 'Web session', event_id),
            )

    cursor.execute(
        'CREATE INDEX IF NOT EXISTS idx_usb_events_device ON usb_events(device_id)'
    )
    cursor.execute(
        'CREATE INDEX IF NOT EXISTS idx_usb_devices_status ON usb_devices(status)'
    )


def migrate_explainability(cursor):
    """Label historical scores honestly without recalculating security history."""
    access_exists = cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='access_events'"
    ).fetchone()
    alert_exists = cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='alerts'"
    ).fetchone()
    if not access_exists or not alert_exists:
        return

    cursor.execute('''
        UPDATE usb_events
        SET access_event_id = (
            SELECT ae.id FROM access_events ae
            WHERE ae.user_id = usb_events.user_id
              AND ae.timestamp = usb_events.timestamp
              AND ae.action_type = 'usb_monitor'
            ORDER BY ae.id LIMIT 1
        )
        WHERE access_event_id IS NULL
    ''')

    access_rows = cursor.execute(
        '''
        SELECT id, rule_result, ml_score, final_risk_level, computer_name
        FROM access_events WHERE explanation_json IS NULL
        '''
    ).fetchall()
    for row in access_rows:
        event = dict(row)
        try:
            rule_data = json.loads(event.get('rule_result') or '{}')
        except (TypeError, ValueError, json.JSONDecodeError):
            rule_data = {}
        explanation = {
            'schema_version': 1,
            'scoring_method': 'legacy_unverified',
            'summary': (
                'Historical event retained without recalculation. The stored legacy '
                'ML score predates explainable scoring and cannot be independently verified.'
            ),
            'triggered_rules': rule_data.get('triggered_rules', []),
            'legacy_ml_score': event.get('ml_score'),
            'final_risk_level': event.get('final_risk_level'),
            'human_review_required': event.get('final_risk_level') in ('Medium', 'High', 'Critical'),
        }
        browser_info = None
        computer_name = event.get('computer_name')
        if _looks_like_browser(computer_name):
            browser_info = computer_name
            computer_name = 'Web session'
        cursor.execute(
            '''
            UPDATE access_events SET anomaly_score = ml_score,
                baseline_source = 'legacy_unavailable',
                anomaly_method = 'legacy_unverified',
                model_confidence = 'unverified',
                human_review_required = ?, explanation_json = ?,
                browser_info = COALESCE(browser_info, ?), computer_name = ?
            WHERE id = ?
            ''',
            (
                1 if explanation['human_review_required'] else 0,
                json.dumps(explanation, separators=(',', ':')),
                browser_info, computer_name, event['id'],
            ),
        )

    alert_rows = cursor.execute(
        '''
        SELECT a.id, a.event_id, a.ml_score, a.severity, e.explanation_json
        FROM alerts a
        LEFT JOIN access_events e ON e.id = a.event_id
        WHERE a.explanation_json IS NULL
        '''
    ).fetchall()
    for row in alert_rows:
        alert = dict(row)
        explanation_json = alert.get('explanation_json')
        if not explanation_json:
            explanation_json = json.dumps({
                'schema_version': 1,
                'scoring_method': 'legacy_unverified',
                'summary': 'Historical alert retained without recalculating its original risk decision.',
                'legacy_ml_score': alert.get('ml_score'),
                'final_risk_level': alert.get('severity'),
                'human_review_required': True,
            }, separators=(',', ':'))
        cursor.execute(
            '''
            UPDATE alerts SET anomaly_score = ml_score,
                baseline_source = 'legacy_unavailable',
                anomaly_method = 'legacy_unverified',
                model_confidence = 'unverified', human_review_required = 1,
                explanation_json = ? WHERE id = ?
            ''',
            (explanation_json, alert['id']),
        )


def clear_all_data():
    """Delete all data from tables (for fresh seed)."""
    conn = get_db()
    cursor = conn.cursor()
    tables = ['account_recovery_requests', 'messages', 'alerts', 'model_runs', 'usb_device_actions', 'usb_events', 'usb_devices', 'access_events',
              'login_history', 'admin_actions', 'reports', 'patient_records', 'users']
    cursor.execute('PRAGMA foreign_keys = OFF')
    for table in tables:
        cursor.execute(f'DELETE FROM {table}')
    cursor.execute('PRAGMA foreign_keys = ON')
    conn.commit()
    conn.close()
