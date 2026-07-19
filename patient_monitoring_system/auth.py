"""Flask-Login authentication and role-based access decorators."""
from functools import wraps

from flask import flash, redirect, url_for, abort
from flask_login import UserMixin, current_user

from config import Config
from models import get_user_by_id, verify_password
from i18n import _


class User(UserMixin):
    """Flask-Login user wrapper."""

    def __init__(self, user_dict):
        self.id = user_dict['id']
        self.username = user_dict['username']
        self.full_name = user_dict['full_name']
        self.staff_id = user_dict['staff_id']
        self.email = user_dict['email']
        self.role = user_dict['role']
        self.department = user_dict['department']
        self.work_start = user_dict['work_start']
        self.work_end = user_dict['work_end']
        self.approval_status = user_dict['approval_status']
        self.is_active_account = bool(user_dict['is_active'])
        self.is_deleted = bool(user_dict.get('is_deleted', 0))
        self.must_change_password = bool(user_dict.get('must_change_password', 0))
        self.credential_version = int(user_dict.get('credential_version', 0) or 0)
        self.preferred_language = user_dict.get('preferred_language', 'en') or 'en'
        self._raw = user_dict

    def get_id(self):
        return str(self.id)

    @property
    def is_super_admin(self):
        return self.role == 'Super Admin'

    @property
    def is_admin(self):
        return self.role == 'Admin'

    @property
    def is_admin_panel(self):
        """Super Admin or Admin — dashboard / management access."""
        return self.role in Config.ADMIN_PANEL_ROLES

    @property
    def is_approved(self):
        return (
            self.approval_status == 'approved'
            and self.is_active_account
            and not self.is_deleted
        )


def load_user(user_id):
    """Flask-Login user loader - only approved active users get sessions."""
    user_dict = get_user_by_id(int(user_id))
    if user_dict is None:
        return None
    if (
        user_dict['approval_status'] != 'approved'
        or not user_dict['is_active']
        or user_dict.get('is_deleted', 0)
    ):
        return None
    return User(user_dict)


def authenticate_user(username, password):
    """
    Authenticate user and return (User, error_message, failure_reason).
    Enforces account lockout after repeated failed passwords.
    """
    from models import get_user_by_username
    from security_engine import (
        is_account_locked, record_failed_password_attempt, reset_login_security,
    )

    user_dict = get_user_by_username(username)
    if user_dict is None:
        return None, _('Invalid username or password.'), 'wrong password'

    locked, lock_msg = is_account_locked(user_dict)
    if locked:
        return None, _(lock_msg), 'temporarily locked'

    if not verify_password(user_dict, password):
        record_failed_password_attempt(user_dict['id'])
        user_dict = get_user_by_username(username)
        locked, lock_msg = is_account_locked(user_dict)
        if locked:
            return None, _(lock_msg), 'temporarily locked'
        return None, _('Invalid username or password.'), 'wrong password'

    status = user_dict['approval_status']
    if status == 'pending':
        return None, _('Your account is waiting for admin approval.'), 'pending approval'
    if status == 'rejected':
        return None, _('Your registration was rejected. Please contact administrator.'), 'rejected account'
    if status == 'suspended':
        return None, _('Your account has been suspended.'), 'suspended account'
    if status == 'deleted' or user_dict.get('is_deleted', 0):
        return None, _('Your account has been deleted. Please contact administrator.'), 'deleted account'
    if status != 'approved':
        return None, _('Your account is not authorized to access the system.'), 'rejected account'
    if not user_dict.get('is_active'):
        return None, _('Your account is inactive. Please contact administrator.'), 'suspended account'

    reset_login_security(user_dict['id'])
    return User(user_dict), None, None


def admin_panel_required(f):
    """Decorator: require Super Admin or Admin."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        if not current_user.is_admin_panel:
            abort(403)
        return f(*args, **kwargs)
    return decorated


def super_admin_required(f):
    """Decorator: require Super Admin only."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        if not current_user.is_super_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated


# Backward-compatible alias
admin_required = admin_panel_required


def staff_or_admin_required(f):
    """Decorator: require any approved logged-in user."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        if not current_user.is_approved:
            flash(_('Your account is not authorized.'), 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated
