"""Patient-record retention and controlled lifecycle regression checks."""
from __future__ import annotations

import json
import sqlite3
import tempfile
from pathlib import Path

from config import Config


def _record(code):
    return {
        'patient_code': code,
        'record_title': f'Lifecycle record {code}',
        'record_category': 'General Medical',
        'department': 'General Medicine',
        'sensitivity_level': 'Medium',
        'content': 'Synthetic lifecycle regression content.',
    }


def run_checks():
    checks = []
    original_database = Config.DATABASE_PATH
    with tempfile.TemporaryDirectory(prefix='meditrace-record-status-') as temp_dir:
        Config.DATABASE_PATH = str(Path(temp_dir) / 'database.db')

        import app as app_module
        from database import get_db, init_db, write_connection
        from models import (
            change_patient_record_status, create_patient_record, create_user,
            get_patient_record, get_patient_record_status_history,
            get_patient_records_page, get_user_by_username,
        )
        from record_status import available_record_status_transitions

        if app_module.scheduler:
            app_module.scheduler.shutdown(wait=False)
            app_module.scheduler = None
        init_db()
        app_module.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)

        conn = get_db()
        columns = {
            row['name'] for row in conn.execute('PRAGMA table_info(patient_records)')
        }
        assert {
            'record_status', 'status_reason', 'status_changed_at',
            'status_changed_by',
        } <= columns
        history_table = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name='patient_record_status_history'"
        ).fetchone()
        conn.close()
        assert history_table
        checks.append('additive lifecycle columns and append-only history table')

        create_user({
            'full_name': 'Lifecycle Doctor', 'staff_id': 'LIFE-DOC',
            'email': 'life-doctor@example.test', 'username': 'lifedoctor',
            'password': 'Doctor@Test123', 'role': 'Doctor',
            'department': 'General Medicine', 'work_start': '08:00',
            'work_end': '17:00', 'approval_status': 'approved', 'is_active': 1,
        })
        admin = get_user_by_username('superadmin')
        doctor = get_user_by_username('lifedoctor')
        record_id = create_patient_record(_record('LIFE-001'))
        terminal_id = create_patient_record(_record('LIFE-TERMINAL'))
        assert get_patient_record(record_id)['record_status'] == 'active'

        before = get_patient_record(record_id, include_nonactive=True)
        try:
            change_patient_record_status(record_id, 'archived', '   ', admin)
            raise AssertionError('blank lifecycle reason was accepted')
        except ValueError:
            pass
        after = get_patient_record(record_id, include_nonactive=True)
        assert after['record_status'] == before['record_status']
        assert not get_patient_record_status_history(record_id)
        checks.append('blank reason rejects atomically without partial history')

        archived = change_patient_record_status(
            record_id, 'archived', 'Retention period completed.', admin,
            ip_address='127.0.0.1', computer_name='TEST-PC',
        )
        assert archived['reason_code'] == 'record_archived'
        assert get_patient_record(record_id) is None
        stored = get_patient_record(record_id, include_nonactive=True)
        assert stored['record_status'] == 'archived' and stored['is_active'] == 0
        history = get_patient_record_status_history(record_id)
        assert len(history) == 1
        assert history[0]['reason'] == 'Retention period completed.'
        assert history[0]['changed_by_username'] == 'superadmin'
        for statement in (
            'UPDATE patient_record_status_history SET reason = ? WHERE id = ?',
            'DELETE FROM patient_record_status_history WHERE id = ?',
        ):
            try:
                with write_connection() as guarded_conn:
                    params = (
                        ('tampered', history[0]['id'])
                        if statement.startswith('UPDATE')
                        else (history[0]['id'],)
                    )
                    guarded_conn.execute(statement, params)
                raise AssertionError('immutable status history was modified')
            except sqlite3.IntegrityError:
                pass
        assert get_patient_record_status_history(record_id)[0]['reason'] == 'Retention period completed.'
        checks.append('archive preserves row and writes complete immutable audit snapshot')

        doctor_rows, doctor_meta = get_patient_records_page(
            doctor, filters={'status': 'archived'}, page=1, per_page=15,
        )
        admin_rows, admin_meta = get_patient_records_page(
            admin, filters={'status': 'archived'}, page=1, per_page=15,
        )
        assert record_id not in {row['id'] for row in doctor_rows}
        assert doctor_meta['total'] == 1  # the still-active terminal test row
        assert {row['id'] for row in admin_rows} == {record_id}
        assert admin_meta['total'] == 1
        checks.append('staff SQL scope stays active-only while administrators filter all statuses')

        restored = change_patient_record_status(
            record_id, 'active', 'Archive reviewed and record restored.', admin,
        )
        assert restored['reason_code'] == 'record_reactivated'
        assert get_patient_record(record_id)['is_active'] == 1
        assert len(get_patient_record_status_history(record_id)) == 2
        checks.append('archived record can be reactivated with a second audited reason')

        change_patient_record_status(
            terminal_id, 'entered_in_error', 'Duplicate record entered in error.', admin,
        )
        assert available_record_status_transitions('entered_in_error') == ()
        try:
            change_patient_record_status(
                terminal_id, 'active', 'Attempted ordinary restoration.', admin,
            )
            raise AssertionError('terminal error state was restored')
        except ValueError:
            pass
        assert get_patient_record(
            terminal_id, include_nonactive=True
        )['record_status'] == 'entered_in_error'
        checks.append('entered-in-error and void-style states use controlled terminal policy')

        client = app_module.app.test_client()
        client.post('/login', data={
            'username': 'superadmin', 'password': 'Super@123',
        })
        detail = client.get(f'/records/{record_id}')
        detail_html = detail.get_data(as_text=True)
        assert detail.status_code == 200
        assert 'Log Export' in detail_html
        assert 'Log Export / Copy to USB' not in detail_html
        assert 'Attempt Delete (Demo)' not in detail_html
        assert 'Record lifecycle controls' in detail_html
        assert f'/records/{record_id}/status' in detail_html

        blank = client.post(f'/records/{record_id}/status', data={
            'confirmed': '1', 'record_status': 'archived', 'status_reason': ' ',
        })
        assert blank.status_code == 302
        assert get_patient_record(record_id)['record_status'] == 'active'
        archived_route = client.post(f'/records/{record_id}/status', data={
            'confirmed': '1', 'record_status': 'archived',
            'status_reason': 'Administrative retention decision.',
        })
        assert archived_route.status_code == 302
        assert get_patient_record(
            record_id, include_nonactive=True
        )['record_status'] == 'archived'
        admin_list = client.get('/records?status=archived&search=LIFE-001')
        assert admin_list.status_code == 200 and b'LIFE-001' in admin_list.data
        inactive_detail = client.get(f'/records/{record_id}')
        assert b'This record is not active' in inactive_detail.data
        assert b'Administrative retention decision.' in inactive_detail.data
        assert b'NPT' in inactive_detail.data
        checks.append('administrator confirmation UI, route validation, filter and Nepal display')

        row_count_before = 2
        assert client.post(f'/records/{record_id}/delete').status_code == 403
        assert client.post('/admin/patient-data', data={
            'action': 'deactivate', 'record_id': record_id,
        }).status_code == 403
        conn = get_db()
        assert conn.execute('SELECT COUNT(*) FROM patient_records').fetchone()[0] == row_count_before
        conn.close()
        checks.append('administrator delete and obsolete deactivation bypass both return 403')

        client.get('/logout')
        client.post('/login', data={
            'username': 'lifedoctor', 'password': 'Doctor@Test123',
        })
        staff_list = client.get('/records?status=archived&search=LIFE-001')
        assert b'Lifecycle record LIFE-001' not in staff_list.data
        assert client.get(f'/records/{record_id}').status_code == 403
        assert client.get(f'/records/{record_id}/export').status_code == 403
        assert client.post(f'/records/{record_id}/status', data={
            'confirmed': '1', 'record_status': 'active',
            'status_reason': 'Forged staff request.',
        }).status_code == 403
        assert client.post(f'/records/{record_id}/delete').status_code == 403
        conn = get_db()
        assert conn.execute('SELECT COUNT(*) FROM patient_records').fetchone()[0] == row_count_before
        events = conn.execute(
            "SELECT explanation_json FROM access_events WHERE user_id = ? "
            "ORDER BY id DESC", (doctor['id'],)
        ).fetchall()
        evidence = [json.loads(row['explanation_json'])['authorization'] for row in events]
        conn.close()
        assert any(
            not item['allowed']
            and item['policy_reason_code'] == 'unauthorized_record_status_attempt'
            for item in evidence
        )
        assert any(
            not item['allowed']
            and item['policy_reason_code'] == 'permanent_delete_not_permitted'
            for item in evidence
        )
        checks.append('staff inactive view/export/status/delete are denied, preserved and monitored')

        client.get('/logout')
        client.post('/login', data={
            'username': 'superadmin', 'password': 'Super@123',
        })
        client.post('/language', data={'language': 'ne', 'next': f'/records/{record_id}'})
        nepali = client.get(f'/records/{record_id}').get_data(as_text=True)
        assert 'अभिलेख स्थिति' in nepali and 'अभिलेखीकृत' in nepali
        conn = get_db()
        assert conn.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
        assert not conn.execute('PRAGMA foreign_key_check').fetchall()
        conn.close()
        checks.append('English/Nepali rendering and database integrity remain valid')

    Config.DATABASE_PATH = original_database
    return checks


if __name__ == '__main__':
    completed = run_checks()
    print(f'Record-status workflow checks passed: {len(completed)}/{len(completed)}')
    for check in completed:
        print(f'  PASS - {check}')
