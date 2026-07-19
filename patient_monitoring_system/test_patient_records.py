"""Patient-record sensitivity, restriction, pagination, and permission checks."""
from __future__ import annotations

import re
import sqlite3
import tempfile
from pathlib import Path

from config import Config


def record_data(code, sensitivity='Low', category='General Medical', department='General Medicine'):
    return {
        'patient_code': code,
        'record_title': f'Simulated title {code}',
        'record_category': category,
        'department': department,
        'sensitivity_level': sensitivity,
        'content': 'Synthetic regression content.',
    }


def run_checks():
    checks = []
    original_database = Config.DATABASE_PATH

    with tempfile.TemporaryDirectory(prefix='meditrace-records-') as temp_dir:
        Config.DATABASE_PATH = str(Path(temp_dir) / 'database.db')

        import app as app_module
        from database import get_db, init_db, write_connection
        from models import (
            create_patient_record, create_user, get_patient_record,
            get_patient_records_page, update_patient_record,
        )
        from record_policy import (
            is_restricted_record, normalize_sensitivity, sensitivity_display,
        )

        if app_module.scheduler:
            app_module.scheduler.shutdown(wait=False)
            app_module.scheduler = None
        init_db()
        app_module.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)

        # Canonical creation accepts safe capitalization/whitespace and stores
        # the project's existing title-case values used by risk/ML engines.
        variants = (
            ('SENS-LOW', ' low ', 'Low'),
            ('SENS-MEDIUM', 'MEDIUM', 'Medium'),
            ('SENS-HIGH', 'High', 'High'),
            ('SENS-CRITICAL', ' critical ', 'Critical'),
        )
        for code, submitted, expected in variants:
            record_id = create_patient_record(record_data(code, submitted))
            assert get_patient_record(record_id)['sensitivity_level'] == expected
        assert normalize_sensitivity('CrItIcAl') == 'Critical'
        assert sensitivity_display(' critical ') == 'Critical'

        before_count = len(variants)
        for invalid in ('Extreme', '', None):
            try:
                create_patient_record(record_data(f'INVALID-{invalid}', invalid))
                raise AssertionError(f'invalid sensitivity accepted: {invalid!r}')
            except ValueError:
                pass
        conn = get_db()
        assert conn.execute('SELECT COUNT(*) FROM patient_records').fetchone()[0] == before_count
        conn.close()
        checks.append('canonical sensitivity creation and invalid-value rejection')

        # Editing must preserve or change meaning exactly, and an invalid edit
        # must leave the prior committed value untouched.
        edit_id = create_patient_record(record_data('SENS-EDIT', 'High'))
        edit_data = record_data('SENS-EDIT', 'Critical')
        update_patient_record(edit_id, edit_data)
        assert get_patient_record(edit_id)['sensitivity_level'] == 'Critical'
        edit_data['sensitivity_level'] = 'Medium'
        update_patient_record(edit_id, edit_data)
        assert get_patient_record(edit_id)['sensitivity_level'] == 'Medium'
        edit_data['sensitivity_level'] = 'unknown'
        try:
            update_patient_record(edit_id, edit_data)
            raise AssertionError('invalid edit unexpectedly succeeded')
        except ValueError:
            pass
        assert get_patient_record(edit_id)['sensitivity_level'] == 'Medium'
        checks.append('sensitivity editing and failed-edit preservation')

        assert is_restricted_record({'record_category': 'Confidential'})
        assert is_restricted_record({'record_category': ' confidential '})
        assert is_restricted_record({'record_category': 'HIV related'})
        assert is_restricted_record({'record_category': 'Psychiatric'})
        assert is_restricted_record({'record_category': 'General Medical', 'is_restricted': 1})
        assert not is_restricted_record({'record_category': 'Confidential', 'is_restricted': 0})
        assert not is_restricted_record({'record_category': 'General Medical'})
        checks.append('central explicit/fallback restricted classification')

        def clear_records():
            with write_connection() as conn:
                conn.execute('DELETE FROM alerts')
                conn.execute('DELETE FROM access_events')
                conn.execute('DELETE FROM patient_records')

        def insert_page_records(count):
            rows = []
            for index in range(1, count + 1):
                category = ('General Medical', 'Laboratory', 'Confidential')[index % 3]
                department = {
                    'General Medical': 'General Medicine',
                    'Laboratory': 'Laboratory',
                    'Confidential': 'General Medicine',
                }[category]
                sensitivity = ('Low', 'Medium', 'High', 'Critical')[index % 4]
                code = 'PR-222' if count == 37 and index == 37 else f'PAGE-{index:03d}'
                if code == 'PR-222':
                    category, department, sensitivity = 'Confidential', 'General Medicine', 'Critical'
                rows.append((
                    code, f'Pagination record {index}', category, department,
                    sensitivity, 'Synthetic pagination content.',
                    f'2026-01-01T00:00:{index:02d}',
                ))
            with write_connection() as conn:
                conn.executemany('''
                    INSERT INTO patient_records (
                        patient_code, record_title, record_category, department,
                        sensitivity_level, content, created_at, is_active
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 1)
                ''', rows)

        expectations = {
            0: (0, 0), 1: (1, 1), 15: (1, 15), 16: (2, 15),
            30: (2, 15), 31: (3, 15), 37: (3, 15),
        }
        for total, (pages, first_page_size) in expectations.items():
            clear_records()
            insert_page_records(total)
            records, metadata = get_patient_records_page(
                'Super Admin', True, page=1, per_page=15
            )
            assert metadata['total'] == total
            assert metadata['total_pages'] == pages
            assert len(records) == first_page_size
        records_2, meta_2 = get_patient_records_page('Super Admin', True, page=2, per_page=15)
        records_3, meta_3 = get_patient_records_page('Super Admin', True, page=3, per_page=15)
        assert len(records_2) == 15 and (meta_2['start'], meta_2['end']) == (16, 30)
        assert len(records_3) == 7 and (meta_3['start'], meta_3['end']) == (31, 37)
        assert records_3[-1]['patient_code'] == 'PAGE-001'
        checks.append('0/1/15/16/30/31/37 server-pagination boundaries')

        client = app_module.app.test_client()
        login = client.post(
            '/login', data={'username': 'superadmin', 'password': 'Super@123'},
            follow_redirects=True,
        )
        assert login.status_code == 200

        page_1 = client.get('/records')
        page_2 = client.get('/records?page=2')
        page_3 = client.get('/records?page=3')
        assert page_1.status_code == page_2.status_code == page_3.status_code == 200
        assert page_1.data.count(b'data-record-id=') == 15
        assert page_2.data.count(b'data-record-id=') == 15
        assert page_3.data.count(b'data-record-id=') == 7
        assert b'Showing 1-15 of 37' in page_1.data
        assert b'Showing 16-30 of 37' in page_2.data
        assert b'Showing 31-37 of 37' in page_3.data
        assert b'aria-current="page"' in page_2.data
        assert client.get('/records?page=invalid').data.count(b'data-record-id=') == 15
        assert client.get('/records?page=-5').data.count(b'data-record-id=') == 15
        assert client.get('/records?page=9999').data.count(b'data-record-id=') == 7
        checks.append('route pagination counts, controls, and safe invalid pages')

        critical_records, critical_meta = get_patient_records_page(
            'Super Admin', True, {'sensitivity': 'critical'}, page=1, per_page=15
        )
        assert critical_meta['total'] and all(
            record['sensitivity_level'] == 'Critical' for record in critical_records
        )
        restricted_records, restricted_meta = get_patient_records_page(
            'Super Admin', True, {'restricted': 'restricted'}, page=1, per_page=15
        )
        assert restricted_meta['total'] and all(
            record['is_restricted'] for record in restricted_records
        )
        searched, search_meta = get_patient_records_page(
            'Super Admin', True, {'search': 'PR-222'}, page=1, per_page=15
        )
        assert search_meta['total'] == 1 and searched[0]['patient_code'] == 'PR-222'
        department_records, department_meta = get_patient_records_page(
            'Super Admin', True, {'department': 'Laboratory'}, page=1, per_page=15
        )
        assert department_meta['total'] and all(
            record['department'] == 'Laboratory' for record in department_records
        )
        filtered_html = client.get(
            '/records?search=record&category=Confidential&department=General+Medicine'
            '&sensitivity=Critical&restricted=restricted'
        ).get_data(as_text=True)
        assert 'page=2' in filtered_html or 'Showing 1-' in filtered_html
        for expected_query in (
            'search=record', 'category=Confidential',
            'department=General+Medicine', 'sensitivity=Critical',
            'restricted=restricted',
        ):
            assert expected_query in filtered_html
        checks.append('search/filter totals and pagination query preservation')

        pr222_html = client.get('/records?search=PR-222').get_data(as_text=True)
        pr222_row = re.search(r'<tr[^>]*>.*?PR-222.*?</tr>', pr222_html, re.S)
        assert pr222_row
        assert 'pr-row-restricted' in pr222_row.group(0)
        assert 'Restricted' in pr222_row.group(0)
        assert 'pr-sensitivity-critical' in pr222_row.group(0)
        assert '>Critical<' in pr222_row.group(0)
        assert '>High<' not in pr222_row.group(0)
        checks.append('PR-222 Confidential/Restricted/Critical display')

        # Route creation and editing exercise the same validation policy while
        # keeping rejected form values visible for correction.
        critical_form = record_data('ROUTE-CRITICAL', 'Critical')
        response = client.post('/simulated-patient-data', data=critical_form)
        assert response.status_code == 302
        conn = get_db()
        assert conn.execute(
            "SELECT sensitivity_level FROM patient_records WHERE patient_code='ROUTE-CRITICAL'"
        ).fetchone()[0] == 'Critical'
        conn.close()

        invalid_form = record_data('ROUTE-INVALID', 'Extreme')
        invalid_form['record_title'] = 'Preserve this rejected title'
        response = client.post('/simulated-patient-data', data=invalid_form)
        assert response.status_code == 400
        assert b'Unsupported sensitivity' in response.data
        assert b'Preserve this rejected title' in response.data
        conn = get_db()
        assert conn.execute(
            "SELECT COUNT(*) FROM patient_records WHERE patient_code='ROUTE-INVALID'"
        ).fetchone()[0] == 0
        conn.close()

        edit_route_id = create_patient_record(record_data('ROUTE-EDIT', 'High'))
        update_form = record_data('ROUTE-EDIT', 'Critical')
        update_form.update({'action': 'update', 'record_id': str(edit_route_id)})
        response = client.post('/admin/patient-data', data=update_form)
        assert response.status_code == 302
        assert get_patient_record(edit_route_id)['sensitivity_level'] == 'Critical'
        update_form['sensitivity_level'] = 'invalid'
        response = client.post('/admin/patient-data', data=update_form)
        assert response.status_code == 400
        assert get_patient_record(edit_route_id)['sensitivity_level'] == 'Critical'
        checks.append('route Critical creation/editing and rejected-form preservation')

        # Nepali changes only the display label, never the stored canonical data.
        client.post('/language', data={'language': 'ne', 'next': '/records'})
        nepali = client.get('/records?search=PR-222').get_data(as_text=True)
        assert 'गम्भीर' in nepali
        assert get_patient_record(searched[0]['id'])['sensitivity_level'] == 'Critical'
        client.post('/language', data={'language': 'en', 'next': '/records'})
        checks.append('English/Nepali Critical display with canonical storage')

        # Authorization is applied in SQL before total/count/pagination. A
        # Doctor sees permitted General Medical/Confidential rows, not Laboratory.
        create_user({
            'full_name': 'Pagination Doctor', 'staff_id': 'PAGE-DOCTOR',
            'email': 'page-doctor@example.test', 'username': 'pagedoctor',
            'password': 'Doctor@Test123', 'role': 'Doctor',
            'department': 'General Medicine', 'work_start': '08:00',
            'work_end': '17:00', 'approval_status': 'approved', 'is_active': 1,
        })
        client.get('/logout')
        client.post(
            '/login', data={'username': 'pagedoctor', 'password': 'Doctor@Test123'}
        )
        doctor_records, doctor_meta = get_patient_records_page(
            'Doctor', False, page=1, per_page=15
        )
        assert doctor_meta['total'] < 39
        assert all(record['record_category'] != 'Laboratory' for record in doctor_records)
        doctor_page = client.get('/records').get_data(as_text=True)
        assert f'>{doctor_meta["total"]}<' in doctor_page
        lab_record = get_patient_records_page(
            'Super Admin', True, {'category': 'Laboratory'}, page=1, per_page=15
        )[0][0]
        assert client.get(f'/records/{lab_record["id"]}').status_code == 403
        assert client.get(f'/records/{lab_record["id"]}/export').status_code == 403
        conn = get_db()
        assert conn.execute(
            'SELECT COUNT(*) FROM access_events WHERE user_id = '
            '(SELECT id FROM users WHERE username = ?) AND record_id = ?',
            ('pagedoctor', lab_record['id']),
        ).fetchone()[0] >= 2
        conn.close()
        checks.append('authorization-before-pagination and blocked direct view/export')

        # Authorized detail/view/export workflows remain operational.
        client.get('/logout')
        client.post('/login', data={'username': 'superadmin', 'password': 'Super@123'})
        pr222_id = get_patient_records_page(
            'Super Admin', True, {'search': 'PR-222'}, page=1, per_page=15
        )[0][0]['id']
        detail = client.get(f'/records/{pr222_id}')
        assert detail.status_code == 200
        assert b'Restricted' in detail.data and b'Critical' in detail.data
        export = client.get(f'/records/{pr222_id}/export')
        assert export.status_code == 302
        checks.append('authorized detail, access logging, alert path, and export regression')

        conn = get_db()
        assert not conn.execute('PRAGMA foreign_key_check').fetchall()
        assert conn.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
        conn.close()

    Config.DATABASE_PATH = original_database
    return checks


if __name__ == '__main__':
    completed = run_checks()
    print(f'Patient-record checks passed: {len(completed)}/{len(completed)}')
    for check in completed:
        print(f'  PASS - {check}')
