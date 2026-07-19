"""Isolated end-to-end verification for account recovery and credential controls."""
import re
import shutil
import tempfile
from pathlib import Path

from config import Config


def _csrf(response):
    match = re.search(
        r'name="csrf_token"[^>]*value="([^"]+)"',
        response.get_data(as_text=True),
    )
    assert match, 'CSRF token was not rendered.'
    return match.group(1)


def _login(client, username, password):
    page = client.get('/login')
    return client.post(
        '/login',
        data={
            'username': username, 'password': password,
            'csrf_token': _csrf(page),
        },
        follow_redirects=False,
    )


def main():
    temp_root = Path(tempfile.mkdtemp(prefix='meditrace-account-recovery-'))
    Config.DATABASE_PATH = str(temp_root / 'database.db')
    Config.REPORTS_DIR = str(temp_root / 'reports')

    import app as app_module
    from database import get_db
    from models import create_admin_user, create_approved_staff_user, get_user_by_username

    app = app_module.app
    app.config.update(TESTING=True)
    try:
        conn = get_db()
        super_user = dict(conn.execute(
            "SELECT * FROM users WHERE username = 'superadmin'"
        ).fetchone())
        conn.close()
        staff_id = create_approved_staff_user({
            'full_name': 'Recovery Staff', 'staff_id': 'REC001',
            'email': 'recovery@example.com', 'username': 'recoverystaff',
            'password': 'Original@123', 'role': 'Nurse',
            'department': 'General Medicine', 'work_start': '08:00',
            'work_end': '17:00',
        }, super_user['id'])
        suspended_id = create_approved_staff_user({
            'full_name': 'Suspended Staff', 'staff_id': 'REC002',
            'email': 'suspended@example.com', 'username': 'suspendedstaff',
            'password': 'Original@123', 'role': 'Nurse',
            'department': 'General Medicine', 'work_start': '08:00',
            'work_end': '17:00',
        }, super_user['id'])
        admin_id = create_admin_user({
            'full_name': 'Scoped Administrator', 'staff_id': 'ADM900',
            'email': 'scoped-admin@example.com', 'username': 'scopedadmin',
            'password': 'AdminScope@123', 'department': 'Administration',
            'work_start': '08:00', 'work_end': '17:00',
        }, super_user['id'])
        conn = get_db()
        conn.execute(
            "UPDATE users SET approval_status = 'suspended', is_active = 0 WHERE id = ?",
            (suspended_id,),
        )
        conn.commit()
        original = dict(conn.execute(
            'SELECT password_hash, approval_status, credential_version FROM users WHERE id = ?',
            (staff_id,),
        ).fetchone())
        conn.close()

        public = app.test_client()
        assert public.post('/account-recovery', data={}).status_code == 400
        page = public.get('/account-recovery')
        payload = {
            'csrf_token': _csrf(page), 'request_type': 'forgot_password',
            'staff_id': 'REC001', 'full_name': 'Recovery Staff',
            'email': 'recovery@example.com', 'department': 'General Medicine',
            'role': 'Nurse', 'requested_destination': 'administrator',
            'message': 'I cannot remember my password and require institutional support.',
        }
        accepted = public.post('/account-recovery', data=payload, follow_redirects=True)
        duplicate = public.post('/account-recovery', data=payload, follow_redirects=True)
        generic = 'Your account recovery request has been submitted for review.'
        assert generic in accepted.get_data(as_text=True)
        assert generic in duplicate.get_data(as_text=True)
        # Fill the configured source-IP window with syntactically valid,
        # unmatched requests; the final request is suppressed with the same
        # public response and without exposing the active limit.
        for index in range(Config.RECOVERY_MAX_REQUESTS_PER_IP):
            rate_payload = dict(payload)
            rate_payload['staff_id'] = f'UNKNOWN{index:02d}'
            rate_response = public.post(
                '/account-recovery', data=rate_payload, follow_redirects=True,
            )
            assert generic in rate_response.get_data(as_text=True)
        xss_client = app.test_client()
        xss_page = xss_client.get('/account-recovery')
        xss_payload = dict(payload)
        xss_payload.update({
            'csrf_token': _csrf(xss_page), 'staff_id': 'XSS001',
            'message': 'I forgot my password. <script>alert("stored")</script>',
        })
        xss_response = xss_client.post(
            '/account-recovery', data=xss_payload, follow_redirects=True,
            environ_overrides={'REMOTE_ADDR': '10.20.30.40'},
        )
        assert generic in xss_response.get_data(as_text=True)
        conn = get_db()
        requests = conn.execute('SELECT * FROM account_recovery_requests').fetchall()
        assert len(requests) == Config.RECOVERY_MAX_REQUESTS_PER_IP + 1
        recovery = dict(next(
            row for row in requests if row['submitted_staff_id'] == 'REC001'
        ))
        xss_recovery = dict(next(
            row for row in requests if row['submitted_staff_id'] == 'XSS001'
        ))
        unchanged = dict(conn.execute(
            'SELECT password_hash, approval_status, credential_version FROM users WHERE id = ?',
            (staff_id,),
        ).fetchone())
        assert unchanged == original
        columns = {row['name'] for row in conn.execute(
            'PRAGMA table_info(account_recovery_requests)'
        )}
        assert not {'password', 'temporary_password', 'password_hash'} & columns
        conn.close()

        staff_client = app.test_client()
        assert _login(staff_client, 'recoverystaff', 'Original@123').status_code == 302
        super_client = app.test_client()
        assert _login(super_client, 'superadmin', 'Super@123').status_code == 302
        xss_detail = super_client.get(
            f"/admin/account-recovery/{xss_recovery['id']}"
        ).get_data(as_text=True)
        assert '<script>alert("stored")</script>' not in xss_detail
        assert '&lt;script&gt;alert' in xss_detail
        detail_url = f"/admin/account-recovery/{recovery['id']}"

        # Credentials cannot be resolved before review and identity verification.
        detail = super_client.get(detail_url)
        premature = super_client.post(detail_url, data={
            'csrf_token': _csrf(detail), 'action': 'resolve',
            'resolution_type': 'password_reset',
            'temporary_password': 'Temporary@123',
            'confirm_temporary_password': 'Temporary@123',
            'admin_password': 'Super@123',
        }, follow_redirects=True)
        assert 'Identity must be verified' in premature.get_data(as_text=True)

        started = super_client.post(detail_url, data={
            'csrf_token': _csrf(premature), 'action': 'start_review',
            'matched_user_id': staff_id,
            'review_notes': 'Institutional directory account selected.',
            'admin_password': 'Super@123',
        }, follow_redirects=True)
        assert 'Recovery review started' in started.get_data(as_text=True)
        verified = super_client.post(detail_url, data={
            'csrf_token': _csrf(started), 'action': 'verify_identity',
            'identity_verification_method': 'in_person',
            'identity_verification_notes': (
                'Hospital identity card and Human Resources record verified in person.'
            ),
            'admin_password': 'Super@123',
        }, follow_redirects=True)
        assert 'Identity verification recorded' in verified.get_data(as_text=True)
        resolved = super_client.post(detail_url, data={
            'csrf_token': _csrf(verified), 'action': 'resolve',
            'resolution_type': 'password_reset',
            'temporary_password': 'Temporary@123',
            'confirm_temporary_password': 'Temporary@123',
            'admin_password': 'Super@123',
        }, follow_redirects=True)
        assert 'Recovery completed' in resolved.get_data(as_text=True)

        stale = staff_client.get('/staff/dashboard', follow_redirects=False)
        assert stale.status_code == 302 and '/login' in stale.location
        temp_client = app.test_client()
        temp_login = _login(temp_client, 'recoverystaff', 'Temporary@123')
        assert '/account/change-temporary-password' in temp_login.location
        blocked = temp_client.get('/staff/dashboard', follow_redirects=False)
        assert '/account/change-temporary-password' in blocked.location
        change_page = temp_client.get('/account/change-temporary-password')
        changed = temp_client.post('/account/change-temporary-password', data={
            'csrf_token': _csrf(change_page),
            'current_password': 'Temporary@123',
            'new_password': 'Permanent@1234',
            'confirm_password': 'Permanent@1234',
        }, follow_redirects=False)
        assert changed.status_code == 302
        assert temp_client.get('/staff/dashboard').status_code == 200
        final_user = get_user_by_username('recoverystaff')
        assert final_user['must_change_password'] == 0
        assert final_user['credential_version'] == 2

        # Direct editing preserves a suspended state while rotating credentials.
        edit_page = super_client.get(f'/admin/users/{suspended_id}/edit')
        edited = super_client.post(f'/admin/users/{suspended_id}/edit', data={
            'csrf_token': _csrf(edit_page), 'full_name': 'Suspended Staff',
            'staff_id': 'REC002', 'email': 'suspended@example.com',
            'username': 'suspended-staff-updated', 'role': 'Nurse',
            'department': 'General Medicine', 'work_start': '08:00',
            'work_end': '17:00', 'temporary_password': 'Temporary@456',
            'confirm_temporary_password': 'Temporary@456',
            'admin_password': 'Super@123',
        }, follow_redirects=True)
        assert 'Account updated' in edited.get_data(as_text=True)
        conn = get_db()
        suspended = dict(conn.execute(
            'SELECT * FROM users WHERE id = ?', (suspended_id,)
        ).fetchone())
        assert suspended['approval_status'] == 'suspended' and suspended['is_active'] == 0
        assert suspended['must_change_password'] == 1

        # A regular Admin cannot edit Admin/Super Admin accounts.
        admin_client = app.test_client()
        assert _login(admin_client, 'scopedadmin', 'AdminScope@123').status_code == 302
        assert admin_client.get(f"/admin/users/{super_user['id']}/edit").status_code == 403
        assert admin_client.get(f'/admin/users/{admin_id}/edit').status_code == 403

        request_row = dict(conn.execute(
            'SELECT * FROM account_recovery_requests WHERE id = ?',
            (recovery['id'],),
        ).fetchone())
        audit_text = ' '.join(
            row['details'] or '' for row in conn.execute('SELECT details FROM admin_actions')
        )
        assert request_row['status'] == 'completed'
        assert request_row['identity_verified_at'] and request_row['completed_at']
        for secret in ('Temporary@123', 'Permanent@1234', 'Temporary@456'):
            assert secret not in audit_text
        assert not list(conn.execute('PRAGMA foreign_key_check'))
        conn.close()

        checks = [
            'CSRF enforcement and generic public responses',
            'duplicate suppression without credential changes',
            'configurable source-IP rate limiting',
            'stored-XSS-safe administrative rendering',
            'verified-identity state transition enforcement',
            'administrator re-authentication and secret-free auditing',
            'session invalidation after credential changes',
            'forced temporary-password rotation',
            'direct account editing with status preservation',
            'Admin/Super Admin target permission boundaries',
            'database foreign-key integrity',
        ]
        for check in checks:
            print(f'[PASS] {check}')
        print(f'{len(checks)}/{len(checks)} account-recovery checks passed')
        return True
    finally:
        if app_module.scheduler is not None:
            app_module.scheduler.shutdown(wait=False)
        shutil.rmtree(temp_root, ignore_errors=True)


if __name__ == '__main__':
    raise SystemExit(0 if main() else 1)
