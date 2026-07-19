"""Regression checks for patient-record writes and SQLite lock recovery."""
from __future__ import annotations

import sqlite3
import tempfile
import threading
import time
from pathlib import Path

from config import Config


def record_data(code):
    return {
        'patient_code': code,
        'record_title': 'Concurrency regression record',
        'record_category': 'General Medical',
        'department': 'General Medicine',
        'sensitivity_level': 'Medium',
        'content': 'Simulated content used only by the lock regression test.',
    }


def run_checks():
    checks = []
    original_database = Config.DATABASE_PATH

    with tempfile.TemporaryDirectory(prefix='meditrace-locking-') as temp_dir:
        Config.DATABASE_PATH = str(Path(temp_dir) / 'database.db')

        # Import only after redirecting Config so application startup never
        # initializes or changes the live database during this test.
        import app as app_module
        from database import get_db, init_db
        from models import create_patient_record, create_user, get_all_patient_records

        if app_module.scheduler:
            app_module.scheduler.shutdown(wait=False)
            app_module.scheduler = None

        init_db()
        app_module.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)

        conn = get_db()
        assert conn.execute('PRAGMA journal_mode').fetchone()[0].lower() == 'wal'
        assert conn.execute('PRAGMA busy_timeout').fetchone()[0] == 30000
        conn.close()
        checks.append('WAL mode and 30-second busy timeout')

        # A failed UNIQUE insert must roll back and close its transaction. The
        # next save should work immediately instead of inheriting a stale lock.
        create_patient_record(record_data('LOCK-DUPLICATE'))
        try:
            create_patient_record(record_data('LOCK-DUPLICATE'))
            raise AssertionError('duplicate patient code unexpectedly succeeded')
        except sqlite3.IntegrityError:
            pass
        create_patient_record(record_data('LOCK-AFTER-ERROR'))
        checks.append('rollback and connection release after failed insert')

        # Hold a real SQLite writer lock briefly. The application writer should
        # wait, then complete when the other transaction commits.
        holder = sqlite3.connect(Config.DATABASE_PATH, timeout=1)
        holder.execute('PRAGMA journal_mode = WAL')
        holder.execute('BEGIN IMMEDIATE')
        result = {}

        def delayed_writer():
            try:
                result['id'] = create_patient_record(record_data('LOCK-WAITED'))
            except Exception as exc:  # surfaced by the assertion below
                result['error'] = exc

        worker = threading.Thread(target=delayed_writer, daemon=True)
        worker.start()
        time.sleep(0.5)
        assert worker.is_alive(), 'writer did not encounter the held transaction'
        holder.commit()
        holder.close()
        worker.join(timeout=5)
        assert not worker.is_alive(), 'writer did not resume after lock release'
        assert 'error' not in result, result.get('error')
        assert result.get('id')
        checks.append('brief concurrent writer lock waits and recovers')

        # Exercise multiple near-simultaneous saves through independent
        # connections, matching requests handled by Flask threads.
        errors = []

        def parallel_writer(index):
            try:
                create_patient_record(record_data(f'LOCK-PARALLEL-{index}'))
            except Exception as exc:
                errors.append(exc)

        workers = [threading.Thread(target=parallel_writer, args=(i,)) for i in range(8)]
        for thread in workers:
            thread.start()
        for thread in workers:
            thread.join(timeout=10)
        assert all(not thread.is_alive() for thread in workers)
        assert not errors, errors
        conn = get_db()
        count = conn.execute(
            "SELECT COUNT(*) FROM patient_records WHERE patient_code LIKE 'LOCK-PARALLEL-%'"
        ).fetchone()[0]
        conn.close()
        assert count == len(workers)
        checks.append('eight parallel patient-record saves')

        # Verify the reported browser workflow: a valid form save succeeds and
        # a duplicate returns a friendly message instead of Flask's traceback.
        client = app_module.app.test_client()
        login_response = client.post(
            '/login',
            data={'username': 'superadmin', 'password': 'Super@123'},
            follow_redirects=True,
        )
        assert login_response.status_code == 200

        form_data = {
            'patient_code': 'LOCK-ROUTE',
            'record_title': 'Route regression record',
            'record_category': 'General Medical',
            'department': 'General Medicine',
            'sensitivity_level': 'Medium',
            'content': 'Created through the simulated-patient-data route.',
        }
        response = client.post('/simulated-patient-data', data=form_data, follow_redirects=True)
        assert response.status_code == 200
        assert b'Simulated record LOCK-ROUTE created' in response.data
        response = client.post('/simulated-patient-data', data=form_data, follow_redirects=True)
        assert response.status_code == 200
        assert b'A patient record with this code already exists' in response.data
        assert b'OperationalError' not in response.data
        checks.append('form route success and friendly duplicate handling')

        # Confidential is authorized for Doctors but independently classified
        # as Restricted; permission and classification must not be conflated.
        client.get('/logout')
        create_user({
            'full_name': 'Visibility Test Doctor',
            'staff_id': 'LOCK-DOCTOR-1',
            'email': 'lock-doctor@example.test',
            'username': 'lockdoctor',
            'password': 'Doctor@Test123',
            'role': 'Doctor',
            'department': 'General Medicine',
            'work_start': '08:00',
            'work_end': '17:00',
            'approval_status': 'approved',
            'is_active': 1,
        })
        login_response = client.post(
            '/login',
            data={'username': 'lockdoctor', 'password': 'Doctor@Test123'},
            follow_redirects=True,
        )
        assert login_response.status_code == 200

        restricted_form = {
            'patient_code': 'LOCK-RESTRICTED',
            'record_title': 'New confidential visibility record',
            'record_category': 'Confidential',
            'department': 'General Medicine',
            'sensitivity_level': 'Critical',
            'content': 'Synthetic restricted-category route check.',
        }
        response = client.post(
            '/simulated-patient-data', data=restricted_form, follow_redirects=True
        )
        assert response.status_code == 200
        assert b'Simulated record LOCK-RESTRICTED created' in response.data

        listing = client.get('/records').get_data(as_text=True)
        assert 'LOCK-RESTRICTED' in listing
        assert 'pr-row-restricted' in listing and 'Restricted' in listing
        assert listing.index('LOCK-RESTRICTED') < listing.index('LOCK-ROUTE')

        for query in ('LOCK-RESTRICTED', 'confidential visibility', 'General Medicine'):
            search_response = client.get('/records', query_string={'search': query})
            assert search_response.status_code == 200
            assert 'LOCK-RESTRICTED' in search_response.get_data(as_text=True), query

        ordered_records = get_all_patient_records()
        assert ordered_records[0]['patient_code'] == 'LOCK-RESTRICTED'
        checks.append('authorized Confidential record is restricted, newest, and searchable')

    Config.DATABASE_PATH = original_database
    return checks


if __name__ == '__main__':
    completed = run_checks()
    print(f'Database locking checks passed: {len(completed)}/{len(completed)}')
    for check in completed:
        print(f'  PASS - {check}')
