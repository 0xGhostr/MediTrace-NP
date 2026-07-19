"""
Account lockout and login security helpers.
Lock after 3 failed attempts for 2 minutes.
"""
from datetime import datetime, timedelta

from database import get_db

LOCKOUT_THRESHOLD = 3
LOCKOUT_MINUTES = 2


def _now():
    return datetime.utcnow()


def _parse_dt(value):
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    return datetime.fromisoformat(str(value).replace('Z', ''))


def is_account_locked(user_dict):
    """Return (locked: bool, message: str|None). Clears expired lock automatically."""
    if not user_dict:
        return False, None
    locked_until = _parse_dt(user_dict.get('locked_until'))
    if locked_until and locked_until > _now():
        return True, (
            'Account temporarily locked due to multiple failed login attempts. '
            'Please try again after 2 minutes or contact admin.'
        )
    if locked_until and locked_until <= _now():
        clear_lockout(user_dict['id'], reset_attempts=False)
    return False, None


def record_failed_password_attempt(user_id):
    """Increment failed attempts; lock account at threshold."""
    conn = get_db()
    row = conn.execute('SELECT failed_attempts FROM users WHERE id = ?', (user_id,)).fetchone()
    attempts = (row['failed_attempts'] or 0) + 1
    now = _now().isoformat()
    locked_until = None
    if attempts >= LOCKOUT_THRESHOLD:
        locked_until = (_now() + timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
    conn.execute(
        '''
        UPDATE users SET failed_attempts = ?, last_failed_login = ?, locked_until = ?
        WHERE id = ?
        ''',
        (attempts, now, locked_until, user_id),
    )
    conn.commit()
    conn.close()
    return attempts, locked_until is not None


def reset_login_security(user_id):
    """Reset failed attempts and lockout after successful login."""
    conn = get_db()
    conn.execute(
        '''
        UPDATE users SET failed_attempts = 0, locked_until = NULL, last_failed_login = NULL
        WHERE id = ?
        ''',
        (user_id,),
    )
    conn.commit()
    conn.close()


def clear_lockout(user_id, reset_attempts=True):
    conn = get_db()
    if reset_attempts:
        conn.execute(
            'UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?',
            (user_id,),
        )
    else:
        conn.execute('UPDATE users SET locked_until = NULL WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()


def admin_unlock_account(user_id, admin_id):
    clear_lockout(user_id, reset_attempts=True)
    from models import log_admin_action
    log_admin_action(admin_id, 'unlock_account', user_id, 'Manual account unlock')
