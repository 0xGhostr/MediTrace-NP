"""Central role/department patient-record authorization regression checks."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from werkzeug.security import generate_password_hash

from config import Config


def _user(role, department, **overrides):
    value = {
        'role': role, 'department': department, 'approval_status': 'approved',
        'is_active': 1, 'is_deleted': 0,
    }
    value.update(overrides)
    return value


def _record(code, category, department, sensitivity='Low'):
    return {
        'patient_code': code, 'record_title': f'Synthetic {code}',
        'record_category': category, 'department': department,
        'sensitivity_level': sensitivity, 'content': 'Synthetic test content.',
    }


def run_checks():
    checks = []
    original_database = Config.DATABASE_PATH
    with tempfile.TemporaryDirectory(prefix='meditrace-access-policy-') as temp_dir:
        Config.DATABASE_PATH = str(Path(temp_dir) / 'database.db')

        import app as app_module
        from database import get_db, init_db, write_connection
        from models import (
            create_patient_record, create_user, get_authorized_patient_records,
            get_patient_records_page, get_user_by_username,
        )
        from record_access import (
            can_delete_record, can_edit_record, can_export_record, can_view_record,
            departments_for_role, get_access_policy_reason, normalize_department,
            normalize_role, record_for_display, validate_role_department,
        )

        if app_module.scheduler:
            app_module.scheduler.shutdown(wait=False)
            app_module.scheduler = None
        init_db()
        app_module.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)

        assert normalize_role(' Superadmin ') == 'Super Admin'
        assert normalize_role('laboratory-staff') == 'Laboratory Staff'
        assert normalize_role('Doctors') is None
        assert normalize_department(' infectious-disease ') == 'Infectious Disease'
        assert validate_role_department('Doctor', 'Psychiatry')
        assert validate_role_department('Nurse', 'Infectious Disease')
        assert not validate_role_department('Doctor', 'Laboratory')
        assert not validate_role_department('Nurse', 'Reception')
        assert departments_for_role('Laboratory Staff') == ('Laboratory',)
        assert not validate_role_department('Admin', 'Administration', public_only=True)
        checks.append('canonical normalization and explicit role/department matrix')

        records = {}
        for code, category, department, sensitivity in (
            ('GM', 'General Medical', 'General Medicine', 'Low'),
            ('GM-LAB', 'Laboratory', 'General Medicine', 'Medium'),
            ('ER', 'Emergency', 'Emergency', 'High'),
            ('ER-LAB', 'Laboratory', 'Emergency', 'Medium'),
            ('ER-HIV', 'HIV-related', 'Emergency', 'Critical'),
            ('ER-PSY', 'Psychiatric', 'Emergency', 'Critical'),
            ('PSY', 'Psychiatric', 'Psychiatry', 'Critical'),
            ('ID', 'HIV-related', 'Infectious Disease', 'Critical'),
            ('LAB', 'Laboratory', 'Laboratory', 'Low'),
            ('BILL', 'Billing', 'Billing', 'Low'),
            ('FRONT', 'General Medical', 'Reception', 'Low'),
            ('ADMIN-CONF', 'Confidential', 'Administration', 'Critical'),
            ('GM-CONF', 'Confidential', 'General Medicine', 'Critical'),
        ):
            record = _record(code, category, department, sensitivity)
            record['id'] = create_patient_record(record)
            records[code] = record

        users = {
            'gm_doctor': _user('Doctor', 'General Medicine'),
            'er_doctor': _user('Doctor', 'Emergency'),
            'psy_doctor': _user('Doctor', 'Psychiatry'),
            'id_doctor': _user('Doctor', 'Infectious Disease'),
            'gm_nurse': _user('Nurse', 'General Medicine'),
            'er_nurse': _user('Nurse', 'Emergency'),
            'lab': _user('Laboratory Staff', 'Laboratory'),
            'billing': _user('Billing Staff', 'Billing'),
            'reception': _user('Receptionist', 'Reception'),
            'admin': _user('Admin', 'Administration'),
            'superadmin': _user('Super Admin', 'Administration'),
            'invalid_nurse': _user('Nurse', 'Reception'),
            'invalid_doctor': _user('Doctor', 'Administration'),
            'invalid_lab': _user('Laboratory Staff', 'General Medicine'),
        }
        expected = {
            'gm_doctor': {'GM', 'GM-LAB', 'GM-CONF'}, 'er_doctor': {'ER', 'ER-LAB'},
            'psy_doctor': {'PSY'}, 'id_doctor': {'ID'},
            'gm_nurse': {'GM', 'GM-LAB'}, 'er_nurse': {'ER', 'ER-LAB'},
            'lab': {'GM-LAB', 'ER-LAB', 'LAB'}, 'billing': {'BILL'},
            'reception': {'FRONT'},
            'admin': set(records), 'superadmin': set(records),
            'invalid_nurse': set(), 'invalid_doctor': set(), 'invalid_lab': set(),
        }
        for user_name, user in users.items():
            visible = {code for code, record in records.items() if can_view_record(user, record)}
            assert visible == expected[user_name], (user_name, visible)
        assert get_access_policy_reason(users['admin'], records['PSY']) == 'privileged_admin_view'
        assert get_access_policy_reason(users['superadmin'], records['ID']) == 'privileged_superadmin_view'
        assert get_access_policy_reason(users['gm_nurse'], records['GM-CONF']) == 'restricted_record_denied'
        checks.append('all controlled roles, service scopes, privileged views, and invalid assignments')

        assert can_export_record(users['gm_doctor'], records['GM'])
        assert not can_export_record(users['gm_doctor'], records['GM-LAB'])
        assert can_export_record(users['lab'], records['ER-LAB'])
        assert not can_export_record(users['reception'], records['FRONT'])
        assert can_edit_record(users['admin'], records['PSY'])
        assert not can_delete_record(users['superadmin'], records['ID'])
        assert not can_edit_record(users['gm_doctor'], records['GM'])
        assert not can_delete_record(users['gm_doctor'], records['GM'])
        detailed = dict(records['ER-LAB'], clinical_notes='withheld', heart_rate=80)
        limited = record_for_display(users['lab'], detailed)
        assert limited['clinical_notes'] is None and limited['heart_rate'] is None
        assert limited['record_title'] == detailed['record_title']
        assert not record_for_display(users['er_doctor'], detailed)['service_scope_limited']
        checks.append('view/export/edit are separate and permanent delete is unavailable')

        for index, (name, user) in enumerate(users.items(), start=1):
            if name.startswith('invalid_'):
                continue
            user_data = {
                'full_name': f'Synthetic {name}', 'staff_id': f'POL-{index:03d}',
                'email': f'{name}@example.test', 'username': name,
                'password': 'Policy@Test123', 'role': user['role'],
                'department': user['department'], 'work_start': '08:00',
                'work_end': '17:00', 'approval_status': 'approved', 'is_active': 1,
            }
            if user['role'] not in Config.ADMIN_PANEL_ROLES:
                create_user(user_data)

        gm_db_user = get_user_by_username('gm_doctor')
        dashboard_rows = get_authorized_patient_records(gm_db_user)
        page_rows, page_meta = get_patient_records_page(gm_db_user, page=1, per_page=15)
        assert {row['patient_code'] for row in dashboard_rows} == {'GM', 'GM-LAB', 'GM-CONF'}
        assert {row['id'] for row in dashboard_rows} == {row['id'] for row in page_rows}
        assert page_meta['total'] == 3
        hidden, hidden_meta = get_patient_records_page(
            gm_db_user, filters={'search': 'Synthetic ER'}, page=1, per_page=15,
        )
        assert hidden == [] and hidden_meta['total'] == 0
        admin_rows, admin_meta = get_patient_records_page(
            users['admin'], filters={'sensitivity': 'Critical'}, page=1, per_page=15,
        )
        assert {row['patient_code'] for row in admin_rows} == {
            'ER-HIV', 'ER-PSY', 'PSY', 'ID', 'ADMIN-CONF', 'GM-CONF',
        }
        assert admin_meta['total'] == 6
        checks.append('shared dashboard/list SQL scope before search, totals, and pagination')

        client = app_module.app.test_client()
        forged = client.post('/register', data={
            'full_name': 'Forged User', 'staff_id': 'FORGED-1',
            'email': 'forged@example.com', 'username': 'forged_user',
            'password': 'Policy@Test123', 'confirm_password': 'Policy@Test123',
            'role': 'Nurse', 'department': 'Reception',
            'work_start': '08:00', 'work_end': '17:00',
        })
        assert forged.status_code == 200
        assert b'Select a valid department for the selected role.' in forged.data
        assert get_user_by_username('forged_user') is None
        register_html = client.get('/register').get_data(as_text=True)
        assert '>Admin<' not in register_html and '>Super Admin<' not in register_html
        assert 'value="Administration"' not in register_html
        checks.append('public registration UI and forged server request validation')

        now = '2026-07-21T00:00:00'
        with write_connection() as conn:
            cursor = conn.execute('''
                INSERT INTO users (
                    full_name, staff_id, email, username, password_hash, role,
                    department, work_start, work_end, approval_status, is_active,
                    created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, '08:00', '17:00', 'approved', 1, ?)
            ''', (
                'Legacy Invalid', 'LEGACY-INVALID', 'legacy-invalid@example.test',
                'legacy_invalid', generate_password_hash('Policy@Test123'),
                'Doctor', 'Laboratory', now,
            ))
            legacy_invalid_id = cursor.lastrowid
            cursor = conn.execute('''
                INSERT INTO users (
                    full_name, staff_id, email, username, password_hash, role,
                    department, work_start, work_end, approval_status, is_active,
                    created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, '08:00', '17:00', 'pending', 0, ?)
            ''', (
                'Pending Invalid', 'PENDING-INVALID', 'pending-invalid@example.test',
                'pending_invalid', generate_password_hash('Policy@Test123'),
                'Nurse', 'Reception', now,
            ))
            pending_id = cursor.lastrowid

        client.post('/login', data={
            'username': 'legacy_invalid', 'password': 'Policy@Test123',
        })
        invalid_list = client.get('/records')
        assert invalid_list.status_code == 200
        assert b'Your role and department assignment requires administrator review' in invalid_list.data
        invalid_direct = client.get(f'/records/{records["GM"]["id"]}')
        assert invalid_direct.status_code == 403
        assert b'Synthetic GM' not in invalid_direct.data
        conn = get_db()
        invalid_evidence = [
            json.loads(row['explanation_json'])['authorization']
            for row in conn.execute(
                'SELECT explanation_json FROM access_events WHERE user_id = ?',
                (legacy_invalid_id,),
            ).fetchall()
        ]
        conn.close()
        assert any(
            not item['allowed']
            and item['policy_reason_code'] == 'invalid_role_department_assignment'
            for item in invalid_evidence
        )
        client.get('/logout')
        checks.append('legacy invalid account login, safe zero scope, and review evidence')

        client.post('/login', data={'username': 'superadmin', 'password': 'Super@123'})
        response = client.post('/admin/pending-users', data={
            'action': 'approve', 'user_id': pending_id,
            'role': 'Nurse', 'department': 'Reception',
        })
        assert response.status_code == 302
        assert get_user_by_username('pending_invalid')['approval_status'] == 'pending'
        response = client.post('/admin/pending-users', data={
            'action': 'approve', 'user_id': pending_id,
            'role': 'Nurse', 'department': 'Emergency',
        })
        assert response.status_code == 302
        assert get_user_by_username('pending_invalid')['approval_status'] == 'approved'
        checks.append('pending approval blocks invalid and accepts valid assignments')

        target = get_user_by_username('gm_nurse')
        response = client.post(f'/admin/users/{target["id"]}/edit', data={
            'full_name': target['full_name'], 'staff_id': target['staff_id'],
            'email': target['email'], 'username': target['username'],
            'role': 'Nurse', 'department': 'Reception',
            'work_start': target['work_start'], 'work_end': target['work_end'],
            'temporary_password': '', 'confirm_temporary_password': '',
            'admin_password': 'Super@123',
        })
        assert response.status_code == 200
        assert get_user_by_username('gm_nurse')['department'] == 'General Medicine'
        response = client.post(f'/admin/users/{target["id"]}/edit', data={
            'full_name': target['full_name'], 'staff_id': target['staff_id'],
            'email': target['email'], 'username': target['username'],
            'role': 'Nurse', 'department': 'Emergency',
            'work_start': target['work_start'], 'work_end': target['work_end'],
            'temporary_password': '', 'confirm_temporary_password': '',
            'admin_password': 'Super@123',
        })
        assert response.status_code == 302
        assert get_user_by_username('gm_nurse')['department'] == 'Emergency'
        conn = get_db()
        audit_details = conn.execute('''
            SELECT details FROM admin_actions
            WHERE action_type = 'edit_account' AND target_user_id = ?
            ORDER BY id DESC LIMIT 1
        ''', (target['id'],)).fetchone()['details']
        conn.close()
        assert 'department=General Medicine->Emergency' in audit_details
        checks.append('User Management validation and previous/new assignment auditing')

        client.get('/logout')
        client.post('/login', data={
            'username': 'gm_doctor', 'password': 'Policy@Test123',
        })
        denied = client.get(f'/records/{records["ER"]["id"]}')
        assert denied.status_code == 403 and b'Synthetic ER' not in denied.data
        allowed = client.get(f'/records/{records["GM"]["id"]}')
        assert allowed.status_code == 200
        denied_export = client.get(f'/records/{records["GM-LAB"]["id"]}/export')
        assert denied_export.status_code == 403
        conn = get_db()
        events = conn.execute('''
            SELECT explanation_json FROM access_events
            WHERE user_id = ? ORDER BY id DESC
        ''', (gm_db_user['id'],)).fetchall()
        evidence = [json.loads(row['explanation_json'])['authorization'] for row in events]
        assert any(not item['allowed'] and item['policy_reason_code'] == 'clinical_department_mismatch' for item in evidence)
        assert any(not item['allowed'] and item['policy_reason_code'] == 'export_not_permitted' for item in evidence)
        assert any(item['allowed'] and item['policy_reason_code'] == 'clinical_department_match' for item in evidence)
        assert not conn.execute('PRAGMA foreign_key_check').fetchall()
        assert conn.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
        conn.close()
        checks.append('direct URL/IDOR denial and allowed/denied policy audit evidence')

    Config.DATABASE_PATH = original_database
    return checks


if __name__ == '__main__':
    completed = run_checks()
    print(f'Record-access policy checks passed: {len(completed)}/{len(completed)}')
    for check in completed:
        print(f'  PASS - {check}')
