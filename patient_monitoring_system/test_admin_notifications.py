"""Focused checks for admin badges, alert ordering, and Critical popups."""
from __future__ import annotations

import json
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

from werkzeug.security import generate_password_hash

from config import Config


PROJECT_ROOT = Path(__file__).resolve().parent


def run_checks():
    checks = []
    original_database = Config.DATABASE_PATH

    with tempfile.TemporaryDirectory(prefix='meditrace-admin-notifications-') as temp_dir:
        Config.DATABASE_PATH = str(Path(temp_dir) / 'database.db')

        import app as app_module
        from database import get_db, init_db
        from models import (
            approve_user,
            get_alerts,
            get_pending_registration_count,
            get_unread_critical_notifications,
            insert_access_event,
            insert_alert,
            reject_user,
        )

        if app_module.scheduler:
            app_module.scheduler.shutdown(wait=False)
            app_module.scheduler = None
        init_db()
        app_module.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        test_password_hash = generate_password_hash('TestOnly@123')

        def create_account(username, role, status='approved', active=1, deleted=0):
            conn = get_db()
            user_id = conn.execute(
                '''
                INSERT INTO users (
                    full_name, staff_id, email, username, password_hash,
                    role, department, work_start, work_end, approval_status,
                    is_active, is_deleted, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, '08:00', '17:00', ?, ?, ?, ?)
                ''',
                (
                    f'{username} User', f'STAFF-{username}', f'{username}@example.invalid',
                    username, test_password_hash, role,
                    'General Medicine', status, active, deleted,
                    datetime.utcnow().isoformat(),
                ),
            ).lastrowid
            conn.commit()
            conn.close()
            return user_id

        admin_id = create_account('notification_admin', 'Admin')
        staff_id = create_account('notification_staff', 'Doctor')
        conn = get_db()
        superadmin_id = conn.execute(
            "SELECT id FROM users WHERE username = 'superadmin'"
        ).fetchone()['id']
        actor = dict(conn.execute(
            'SELECT * FROM users WHERE id = ?', (staff_id,),
        ).fetchone())
        message_columns = {
            row['name'] for row in conn.execute('PRAGMA table_info(messages)').fetchall()
        }
        assert {'notification_type', 'related_alert_id'} <= message_columns
        assert conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='index' AND name='idx_messages_critical_alert_recipient'"
        ).fetchone()
        conn.close()
        checks.append('minimal additive notification columns and recipient uniqueness index')

        assert get_pending_registration_count() == 0
        pending_ids = []
        for number in range(1, 4):
            pending_ids.append(create_account(
                f'pending_{number}', 'Doctor', status=' Pending ', active=0,
            ))
            assert get_pending_registration_count() == number

        conn = get_db()
        conn.execute(
            '''
            INSERT INTO account_recovery_requests (
                public_reference, request_type, submitted_staff_id,
                submitted_name, submitted_department, submitted_role,
                requested_destination, message, status, created_at
            ) VALUES (
                'REC-BADGE-TEST', 'forgot_password', 'REC-001', 'Recovery Test',
                'General Medicine', 'Doctor', 'administration', 'Test only',
                'pending', ?
            )
            ''',
            (datetime.utcnow().isoformat(),),
        )
        conn.commit()
        conn.close()
        assert get_pending_registration_count() == 3

        approve_user(pending_ids[0], superadmin_id, role='Doctor', department='General Medicine')
        assert get_pending_registration_count() == 2
        reject_user(pending_ids[1], 'Test rejection')
        assert get_pending_registration_count() == 1
        conn = get_db()
        conn.execute('UPDATE users SET is_deleted = 1 WHERE id = ?', (pending_ids[2],))
        conn.commit()
        conn.close()
        assert get_pending_registration_count() == 0
        checks.append('0/1/2/3 pending counts, approval/rejection, deletion, and recovery exclusion')

        suspended_admin_id = create_account(
            'suspended_notification_admin', 'Admin', status='suspended', active=0,
        )
        pending_admin_id = create_account(
            'pending_notification_admin', 'Admin', status='pending', active=0,
        )
        deleted_admin_id = create_account(
            'deleted_notification_admin', 'Super Admin', status='approved', active=1, deleted=1,
        )

        def add_alert(severity, created_at):
            event_id = insert_access_event({
                'user_id': actor['id'], 'username': actor['username'],
                'staff_id': actor['staff_id'], 'role': actor['role'],
                'department': actor['department'], 'action_type': 'view',
                'timestamp': created_at, 'final_risk_level': severity,
            })
            return insert_alert({
                'event_id': event_id, 'user_id': actor['id'],
                'username': actor['username'], 'role': actor['role'],
                'department': actor['department'], 'severity': severity,
                'reason': 'Synthetic ordering test.', 'created_at': created_at,
                'explanation_json': json.dumps({
                    'scoring_method': 'rules_only',
                    'rule_score': 0,
                    'final_hybrid_score': 0,
                    'final_risk_level': str(severity).strip().title(),
                    'rule_contributions': [],
                    'behavioural_deviations': [],
                    'baseline_source': 'test',
                    'model': {
                        'confidence': 'test', 'version': None,
                        'raw_decision_function': None,
                        'interpretation': 'Synthetic test fixture.',
                    },
                    'human_review_required': True,
                }),
            })

        start = datetime(2026, 7, 20, 0, 0)
        sequence = ('Critical', 'Medium', 'High', 'Critical', 'Medium')
        alert_ids = [
            add_alert(severity, (start + timedelta(seconds=index)).isoformat())
            for index, severity in enumerate(sequence)
        ]
        assert [row['id'] for row in get_alerts(limit=5)] == list(reversed(alert_ids))
        assert [row['id'] for row in get_alerts({'severity': 'Medium'})] == [
            alert_ids[4], alert_ids[1],
        ]
        assert [row['id'] for row in get_alerts({'severity': 'High'})] == [alert_ids[2]]
        assert [row['id'] for row in get_alerts({'severity': 'Critical'})] == [
            alert_ids[3], alert_ids[0],
        ]

        tied_old = add_alert('High', (start + timedelta(minutes=1)).isoformat())
        tied_new = add_alert('Medium', (start + timedelta(minutes=1)).isoformat())
        ordered = [row['id'] for row in get_alerts(limit=20)]
        assert ordered[:2] == [tied_new, tied_old]
        assert [row['id'] for row in get_alerts(limit=2, offset=0)] == ordered[:2]
        assert [row['id'] for row in get_alerts(limit=2, offset=2)] == ordered[2:4]
        checks.append('newest-first alert filtering, stable ID tie-breaker, and pagination')

        # Existing rows are not replayed. Only insert_alert creates future typed
        # notifications, and only for canonical Critical severity.
        conn = get_db()
        conn.execute("UPDATE messages SET is_read = 1, read_at = '2026-07-20T00:00:00'")
        existing_pairs = conn.execute(
            "SELECT COUNT(*) FROM messages WHERE notification_type = 'critical_alert'"
        ).fetchone()[0]
        conn.commit()
        conn.close()

        add_alert('Medium', (start + timedelta(minutes=2)).isoformat())
        add_alert('High', (start + timedelta(minutes=3)).isoformat())
        assert get_unread_critical_notifications(superadmin_id) == []
        assert get_unread_critical_notifications(admin_id) == []
        assert get_unread_critical_notifications(staff_id) == []
        assert get_unread_critical_notifications(suspended_admin_id) == []
        assert get_unread_critical_notifications(pending_admin_id) == []
        assert get_unread_critical_notifications(deleted_admin_id) == []

        critical_id = add_alert(' Critical ', (start + timedelta(minutes=4)).isoformat())
        super_notifications = get_unread_critical_notifications(superadmin_id)
        admin_notifications = get_unread_critical_notifications(admin_id)
        assert [item['alert_id'] for item in super_notifications] == [critical_id]
        assert [item['alert_id'] for item in admin_notifications] == [critical_id]
        assert get_unread_critical_notifications(staff_id) == []
        conn = get_db()
        recipients = conn.execute(
            '''
            SELECT receiver_id, COUNT(*) AS count
            FROM messages
            WHERE notification_type = 'critical_alert' AND related_alert_id = ?
            GROUP BY receiver_id ORDER BY receiver_id
            ''',
            (critical_id,),
        ).fetchall()
        assert {row['receiver_id']: row['count'] for row in recipients} == {
            superadmin_id: 1, admin_id: 1,
        }
        conn.execute(
            '''
            INSERT OR IGNORE INTO messages (
                sender_id, receiver_id, title, body, is_read, is_urgent,
                created_at, notification_type, related_alert_id
            )
            SELECT sender_id, receiver_id, title, body, is_read, is_urgent,
                   created_at, notification_type, related_alert_id
            FROM messages
            WHERE receiver_id = ? AND related_alert_id = ?
              AND notification_type = 'critical_alert'
            ''',
            (admin_id, critical_id),
        )
        assert conn.execute(
            '''SELECT COUNT(*) FROM messages
               WHERE receiver_id = ? AND related_alert_id = ?
                 AND notification_type = 'critical_alert' ''',
            (admin_id, critical_id),
        ).fetchone()[0] == 1
        assert conn.execute(
            "SELECT COUNT(*) FROM messages WHERE notification_type = 'critical_alert'"
        ).fetchone()[0] == existing_pairs + 2
        conn.close()
        checks.append('Critical-only active Admin/Super Admin recipients with per-user deduplication')

        def login(client, username, password):
            response = client.post(
                '/login', data={'username': username, 'password': password},
                follow_redirects=True,
            )
            assert response.status_code == 200

        super_client = app_module.app.test_client()
        login(super_client, 'superadmin', 'Super@123')
        dashboard = super_client.get('/admin/dashboard').get_data(as_text=True)
        assert 'criticalAlertToast' in dashboard
        assert f'#{critical_id}' in dashboard
        assert app_module.format_nepal_datetime(
            (start + timedelta(minutes=4)).isoformat(),
        ) in dashboard

        notification_id = super_notifications[0]['notification_id']
        dismissed = super_client.post(
            f'/admin/critical-notifications/{notification_id}/acknowledge',
            data={'action': 'dismiss', 'next': '/admin/dashboard'},
        )
        assert dismissed.status_code == 302 and dismissed.location.endswith('/admin/dashboard')
        assert get_unread_critical_notifications(superadmin_id) == []
        assert [item['alert_id'] for item in get_unread_critical_notifications(admin_id)] == [critical_id]

        admin_client = app_module.app.test_client()
        login(admin_client, 'notification_admin', 'TestOnly@123')
        before_language = get_db()
        before_count = before_language.execute(
            "SELECT COUNT(*) FROM messages WHERE receiver_id = ? AND related_alert_id = ?",
            (admin_id, critical_id),
        ).fetchone()[0]
        before_language.close()
        switched = admin_client.post(
            '/language', data={'language': 'ne', 'next': '/admin/dashboard'},
        )
        assert switched.status_code == 302
        nepali_dashboard = admin_client.get('/admin/dashboard').get_data(as_text=True)
        assert 'गम्भीर सुरक्षा चेतावनी' in nepali_dashboard
        after_language = get_db()
        after_count = after_language.execute(
            "SELECT COUNT(*) FROM messages WHERE receiver_id = ? AND related_alert_id = ?",
            (admin_id, critical_id),
        ).fetchone()[0]
        after_language.close()
        assert before_count == after_count == 1

        view_notification_id = admin_notifications[0]['notification_id']
        seen = admin_client.post(
            f'/admin/critical-notifications/{view_notification_id}/acknowledge',
            data={'action': 'seen'},
        )
        assert seen.status_code == 204
        assert get_unread_critical_notifications(admin_id) == []
        assert 'criticalAlertToast' not in admin_client.get('/admin/dashboard').get_data(as_text=True)
        viewed = admin_client.post(
            f'/admin/critical-notifications/{view_notification_id}/acknowledge',
            data={'action': 'view'},
        )
        assert viewed.status_code == 302
        assert f'/admin/alerts?search={critical_id}#alert-{critical_id}' in viewed.location
        assert get_unread_critical_notifications(admin_id) == []
        checks.append('localized popup, Nepal time, seen/dismiss isolation, and authorized View Alert')

        older_new_critical = add_alert(
            'Critical', (start + timedelta(minutes=5)).isoformat(),
        )
        newest_critical = add_alert(
            'Critical', (start + timedelta(minutes=6)).isoformat(),
        )
        assert [item['alert_id'] for item in get_unread_critical_notifications(admin_id)] == [
            newest_critical, older_new_critical,
        ]
        assert [item['alert_id'] for item in get_unread_critical_notifications(superadmin_id)] == [
            newest_critical, older_new_critical,
        ]
        checks.append('multiple unique Critical notifications remain newest-first per recipient')

        # Sidebar count appears on shared admin pages, clamps at 99+, and is
        # absent from staff navigation. Use canonical pending rows here because
        # that is what registration submission creates.
        for number in range(100):
            create_account(f'bulk_pending_{number}', 'Doctor', status='pending', active=0)
        english_page = super_client.get('/admin/dashboard').get_data(as_text=True)
        alerts_page = super_client.get('/admin/alerts').get_data(as_text=True)
        assert 'Pending Registrations' in english_page and '>99+<' in english_page
        assert '>99+<' in alerts_page

        staff_client = app_module.app.test_client()
        login(staff_client, 'notification_staff', 'TestOnly@123')
        staff_page = staff_client.get('/staff/dashboard').get_data(as_text=True)
        assert 'Pending Registrations' not in staff_page
        assert 'criticalAlertToast' not in staff_page
        denied = staff_client.post(
            f'/admin/critical-notifications/{view_notification_id}/acknowledge',
            data={'action': 'view'},
        )
        assert denied.status_code == 403
        checks.append('shared 99+ admin badge and staff navigation/popup exclusion')

        conn = get_db()
        assert conn.execute('PRAGMA foreign_key_check').fetchall() == []
        conn.close()

        sidebar = (PROJECT_ROOT / 'templates' / 'sidebar_macros.html').read_text(encoding='utf-8')
        base = (PROJECT_ROOT / 'templates' / 'base.html').read_text(encoding='utf-8')
        css = (PROJECT_ROOT / 'static' / 'css' / 'style.css').read_text(encoding='utf-8')
        assert 'pending_registration_count' in sidebar and "'99+'" in sidebar
        assert 'bootstrap.Toast.getOrCreateInstance' in base and 'window.alert(' not in base
        assert "formData.append('action', 'seen')" in base
        assert '--app-surface' in css and '.critical-alert-toast' in css
        checks.append('non-blocking responsive toast using existing Light/Dark variables')

    Config.DATABASE_PATH = original_database
    return checks


if __name__ == '__main__':
    completed = run_checks()
    print(f'Admin notification checks passed: {len(completed)}/{len(completed)}')
    for check in completed:
        print(f'  PASS - {check}')
