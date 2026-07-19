"""
MediTrace-Np - Main Flask Application
Thesis prototype for behavioural anomaly detection in healthcare (Kathmandu Valley).
"""
import os
import sqlite3
from datetime import datetime

from flask import (
    Flask, render_template, redirect, url_for, flash as flask_flash, request,
    abort, send_file, jsonify, session, g
)
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm, CSRFProtect
from flask_wtf.csrf import CSRFError
from wtforms import StringField, PasswordField, SelectField, TimeField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from apscheduler.schedulers.background import BackgroundScheduler

from config import Config
from database import init_db
from auth import (
    User, load_user, authenticate_user, admin_panel_required, super_admin_required,
    staff_or_admin_required,
)
from models import (
    create_user, get_user_by_username, get_user_by_staff_id, get_user_by_email, update_user_login,
    log_login_attempt, log_admin_action, get_pending_users, get_all_users,
    approve_user, reject_user, suspend_user, reactivate_user, soft_delete_user, update_user_details,
    get_patient_record, get_all_patient_records, get_patient_records_page,
    role_can_access_category,
    get_access_events, get_alerts, get_alert_count, get_alert_summary,
    get_alert_filter_options, resolve_alert, get_dashboard_stats,
    get_chart_access_timeline, get_chart_alerts_by_severity, get_chart_user_registrations,
    get_user_activity_summary, create_patient_record, update_patient_record, deactivate_patient_record,
    send_message, get_messages_for_user, get_sent_messages, get_unread_messages_for_user,
    mark_message_read, get_message, get_admin_users, create_admin_user, update_admin_user,
    set_user_password, can_delete_user, get_user_by_id, format_datetime_display,
    format_nepal_datetime, verify_password,
    update_user_language,
    create_approved_staff_user, delete_alert, delete_message,
    get_usb_devices, add_usb_to_whitelist, remove_usb_from_whitelist,
    set_usb_device_status, get_usb_events,
    get_security_dashboard_stats, get_recent_failed_logins, get_locked_accounts,
)
from account_recovery import (
    REQUEST_TYPES, DESTINATIONS, RECOVERY_STATUSES, VERIFICATION_METHODS,
    RESOLUTION_TYPES, submit_recovery_request, get_recovery_request_count,
    get_recovery_requests, get_recovery_request, get_manageable_users,
    can_manage_user, start_recovery_review, verify_recovery_identity,
    reject_recovery_request, resolve_recovery_request, edit_account,
    validate_password_policy,
)
from access_service import process_access
import ai_engine
from report_generator import (
    generate_daily_report, generate_alert_report,
    generate_user_activity_report, get_report_history,
    get_report_by_id, read_report_as_table,
)
from i18n import (
    _, LANGUAGE_COOKIE, LocalizedFormMixin, SUPPORTED_LOCALES,
    get_locale, install_i18n, is_safe_next_url, normalize_locale, translate_display,
)
from record_policy import (
    is_restricted_record, normalize_sensitivity, sensitivity_display,
    sensitivity_key,
)


def flash(message, category='message'):
    """Translate all server-originated flash text with English fallback."""
    return flask_flash(_(message), category)

app = Flask(__name__)
app.config.from_object(Config)
app.config['WTF_CSRF_ENABLED'] = True
csrf = CSRFProtect(app)
install_i18n(app)
app.jinja_env.globals.update(
    is_restricted_record=is_restricted_record,
    sensitivity_label=sensitivity_display,
    sensitivity_key=sensitivity_key,
)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.user_loader(load_user)

scheduler = None

@app.context_processor
def inject_message_context():
    """Inject unread messages and nav highlight helper."""
    ep = request.endpoint

    def nav_active(*endpoints):
        return 'active' if ep in endpoints else ''

    ctx = {
        'unread_messages': [],
        'unread_message_count': 0,
        'nav_active': nav_active,
        'APP_NAME': Config.APP_NAME,
        'open_recovery_request_count': 0,
        'is_restricted_record': is_restricted_record,
        'sensitivity_label': sensitivity_display,
        'sensitivity_key': sensitivity_key,
    }
    if current_user.is_authenticated:
        ctx['unread_messages'] = get_unread_messages_for_user(current_user.id)
        ctx['unread_message_count'] = len(ctx['unread_messages'])
        if current_user.is_admin_panel:
            ctx['open_recovery_request_count'] = get_recovery_request_count(current_user)
    return ctx


@app.template_filter('nepal_datetime')
def nepal_datetime_filter(value):
    return format_nepal_datetime(value)


@app.before_request
def enforce_credential_session_state():
    """Invalidate stale sessions and contain temporary-password sessions."""
    if not current_user.is_authenticated:
        return None
    stored_version = int(session.get('credential_version', 0) or 0)
    if stored_version != current_user.credential_version:
        harmless_language = get_locale()
        logout_user()
        session.clear()
        session['language'] = harmless_language
        flash(
            'Your credentials were updated. Sign in again with your current credentials.',
            'info',
        )
        return redirect(url_for('login'))
    allowed = {'change_temporary_password', 'change_language', 'logout', 'static'}
    if current_user.must_change_password and request.endpoint not in allowed:
        flash('You must replace your temporary password before continuing.', 'warning')
        return redirect(url_for('change_temporary_password'))
    return None


def start_scheduler():
    """Start APScheduler for daily reports (avoid double-start in debug)."""
    global scheduler
    if scheduler is not None:
        return
    if app.debug and os.environ.get('WERKZEUG_RUN_MAIN') != 'true':
        return

    scheduler = BackgroundScheduler(daemon=True)

    def daily_job():
        with app.app_context():
            generate_daily_report()

    scheduler.add_job(daily_job, 'cron', hour=23, minute=55, id='daily_report')
    scheduler.start()


# --- Forms ---
class LoginForm(LocalizedFormMixin, FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(max=50)])
    password = PasswordField('Password', validators=[DataRequired(), Length(max=128)])
    submit = SubmitField('Login')


class RegisterForm(LocalizedFormMixin, FlaskForm):
    full_name = StringField('Full Name', validators=[DataRequired(), Length(max=100)])
    staff_id = StringField('Staff ID', validators=[DataRequired(), Length(max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=50)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    role = SelectField('Requested Role', choices=[(r, r) for r in Config.STAFF_REGISTER_ROLES])
    department = SelectField('Department', choices=[(d, d) for d in Config.DEPARTMENTS])
    work_start = StringField('Work Start (HH:MM)', default='08:00', validators=[DataRequired()])
    work_end = StringField('Work End (HH:MM)', default='17:00', validators=[DataRequired()])
    submit = SubmitField('Register')


class AccountRecoveryForm(LocalizedFormMixin, FlaskForm):
    request_type = SelectField(
        'What do you need help recovering?',
        choices=list(REQUEST_TYPES.items()),
        validators=[DataRequired()],
    )
    staff_id = StringField('Staff ID', validators=[DataRequired(), Length(max=20)])
    full_name = StringField(
        'Registered Full Name', validators=[DataRequired(), Length(max=100)]
    )
    email = StringField(
        'Registered Email', validators=[DataRequired(), Email(), Length(max=254)]
    )
    department = SelectField(
        'Department', choices=[('', 'Select department')] + [(d, d) for d in Config.DEPARTMENTS],
        validators=[DataRequired()],
    )
    role = SelectField(
        'Role', choices=[('', 'Select role')] + [(r, r) for r in Config.ROLES],
        validators=[DataRequired()],
    )
    requested_destination = SelectField(
        'Requested Support Destination',
        choices=list(DESTINATIONS.items()),
        validators=[DataRequired()],
    )
    message = TextAreaField(
        'Request Message',
        validators=[DataRequired(), Length(min=10, max=Config.RECOVERY_MESSAGE_MAX_LENGTH)],
    )
    submit = SubmitField('Submit Recovery Request')


class TemporaryPasswordChangeForm(LocalizedFormMixin, FlaskForm):
    current_password = PasswordField(
        'Current Temporary Password', validators=[DataRequired(), Length(max=128)]
    )
    new_password = PasswordField(
        'New Password', validators=[DataRequired(), Length(max=128)]
    )
    confirm_password = PasswordField(
        'Confirm New Password',
        validators=[DataRequired(), EqualTo('new_password')],
    )
    submit = SubmitField('Set New Password')


# --- Public routes ---
@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.is_admin_panel:
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('staff_dashboard'))
    return redirect(url_for('login'))


@app.route('/language', methods=['POST'])
def change_language():
    """Change UI locale with CSRF protection and a local-only return path."""
    locale = normalize_locale(request.form.get('language'))
    if locale not in SUPPORTED_LOCALES:
        abort(400)
    destination = request.form.get('next')
    if not is_safe_next_url(destination):
        destination = url_for('index')
    session['language'] = locale
    g.locale = locale
    if current_user.is_authenticated:
        update_user_language(current_user.id, locale)
        current_user.preferred_language = locale
        current_user._raw['preferred_language'] = locale
    response = redirect(destination)
    response.set_cookie(
        LANGUAGE_COOKIE, locale, max_age=60 * 60 * 24 * 365,
        secure=request.is_secure, httponly=True, samesite='Lax', path='/',
    )
    return response


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = LoginForm()
    if form.validate_on_submit():
        user, error, failure_reason = authenticate_user(form.username.data, form.password.data)
        ip = request.remote_addr

        if error:
            from models import get_user_by_username as get_u
            u = get_u(form.username.data)
            log_login_attempt(
                form.username.data, u['id'] if u else None, False,
                failure_reason or error, ip,
            )
            flash(
                error,
                'warning' if failure_reason in (
                    'pending approval', 'rejected account', 'suspended account', 'deleted account',
                ) else 'danger'
            )
        else:
            login_user(user)
            session['language'] = normalize_locale(user.preferred_language) or 'en'
            session['credential_version'] = user.credential_version
            update_user_login(user.id)
            log_login_attempt(user.username, user.id, True, None, ip)
            flash(_('Welcome, {name}!', name=user.full_name), 'success')
            if user.must_change_password:
                return redirect(url_for('change_temporary_password'))
            if user.is_admin_panel:
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('staff_dashboard'))

    return render_template('login.html', form=form)


@app.route('/account-recovery', methods=['GET', 'POST'])
def account_recovery_request():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = AccountRecoveryForm()
    if request.method == 'POST':
        if form.validate():
            try:
                submit_recovery_request(
                    {
                        'request_type': form.request_type.data,
                        'staff_id': form.staff_id.data,
                        'full_name': form.full_name.data,
                        'email': form.email.data,
                        'department': form.department.data,
                        'role': form.role.data,
                        'requested_destination': form.requested_destination.data,
                        'message': form.message.data,
                    },
                    request.remote_addr,
                    request.headers.get('User-Agent', ''),
                )
            except Exception:
                app.logger.exception('Account recovery intake failed safely.')
        flash(
            'Your account recovery request has been submitted for review. '
            'An authorized administrator will contact you through the institution’s '
            'approved verification process.',
            'success',
        )
        return redirect(url_for('login'))
    return render_template('account_recovery.html', form=form)


@app.route('/logout')
@login_required
def logout():
    harmless_language = get_locale()
    logout_user()
    session['language'] = harmless_language
    flash(_('You have been logged out.'), 'info')
    return redirect(url_for('login'))


@app.route('/account/change-temporary-password', methods=['GET', 'POST'])
@login_required
def change_temporary_password():
    if not current_user.must_change_password:
        return redirect(url_for('index'))
    form = TemporaryPasswordChangeForm()
    if form.validate_on_submit():
        if not verify_password(current_user._raw, form.current_password.data):
            flash('The current temporary password is incorrect.', 'danger')
        else:
            valid, error = validate_password_policy(form.new_password.data)
            if not valid:
                flash(error, 'danger')
            elif verify_password(current_user._raw, form.new_password.data):
                flash('Choose a password different from the temporary password.', 'danger')
            else:
                set_user_password(
                    current_user.id, form.new_password.data,
                    must_change=False, changed_by=current_user.id,
                )
                refreshed = get_user_by_id(current_user.id)
                session['credential_version'] = int(
                    refreshed.get('credential_version', 0) or 0
                )
                log_admin_action(
                    current_user.id, 'complete_temporary_password_change',
                    current_user.id,
                    'Required self-service password rotation completed; no secret logged.',
                )
                flash('Your password has been changed securely.', 'success')
                return redirect(url_for('index'))
    return render_template('change_temporary_password.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if get_user_by_username(form.username.data):
            flash('Username already exists.', 'danger')
        elif get_user_by_staff_id(form.staff_id.data):
            flash('Staff ID already registered.', 'danger')
        elif get_user_by_email(form.email.data):
            flash('Email already registered.', 'danger')
        else:
            try:
                create_user({
                    'full_name': form.full_name.data,
                    'staff_id': form.staff_id.data,
                    'email': form.email.data,
                    'username': form.username.data,
                    'password': form.password.data,
                    'role': form.role.data,
                    'department': form.department.data,
                    'work_start': form.work_start.data,
                    'work_end': form.work_end.data,
                    'approval_status': 'pending',
                    'is_active': 0,
                })
                flash('Registration submitted successfully. Please wait for admin approval.', 'success')
                return redirect(url_for('login'))
            except Exception:
                flash('Registration failed due to invalid or duplicate data. Please review your details.', 'danger')
    elif request.method == 'POST':
        flash('Please correct the highlighted form errors and submit again.', 'danger')
    return render_template('register.html', form=form)


# --- Staff routes ---
@app.route('/staff/dashboard')
@login_required
@staff_or_admin_required
def staff_dashboard():
    if current_user.is_admin_panel:
        return redirect(url_for('admin_dashboard'))

    search = request.args.get('search', '')
    allowed_categories = Config.ROLE_ACCESS.get(current_user.role) or []
    records = get_all_patient_records(
        category_filter=allowed_categories, search=search or None
    )
    for rec in records:
        rec['allowed'] = True
        rec['is_restricted'] = is_restricted_record(rec)
    return render_template('staff_dashboard.html', records=records, search=search)


@app.route('/staff/profile')
@login_required
@staff_or_admin_required
def staff_profile():
    return render_template('staff_profile.html', user=current_user._raw)


# --- Patient records ---
def patient_record_form_data(form_data, allowed_categories=None):
    """Normalize simulated patient-record form values for create and update flows."""
    def optional_text(name):
        return form_data.get(name, '').strip() or None

    def optional_number(name, label, cast, minimum, maximum):
        raw_value = form_data.get(name, '').strip()
        if not raw_value:
            return None
        try:
            value = cast(raw_value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f'{label} must be a valid number.') from exc
        if value < minimum or value > maximum:
            raise ValueError(f'{label} must be between {minimum} and {maximum}.')
        return value

    category = str(form_data.get('record_category') or '').strip()
    valid_categories = (
        Config.RECORD_CATEGORIES if allowed_categories is None else allowed_categories
    )
    if category not in valid_categories:
        raise ValueError('Select a valid record category permitted for your role.')

    department = str(form_data.get('department') or '').strip()
    if department not in Config.DEPARTMENTS:
        raise ValueError('Select a valid department.')

    sensitivity = normalize_sensitivity(form_data.get('sensitivity_level'))

    return {
        'patient_code': form_data.get('patient_code', '').strip(),
        'record_title': form_data.get('record_title', '').strip(),
        'record_category': category,
        'department': department,
        'sensitivity_level': sensitivity,
        'content': form_data.get('content', '').strip(),
        'patient_identifier': optional_text('patient_identifier'),
        'patient_name': optional_text('patient_name'),
        'patient_age': optional_number('patient_age', 'Patient age', int, 0, 130),
        'patient_gender': optional_text('patient_gender'),
        'ward': optional_text('ward'),
        'admission_date': optional_text('admission_date'),
        'attending_doctor': optional_text('attending_doctor'),
        'primary_condition': optional_text('primary_condition'),
        'clinical_notes': optional_text('clinical_notes'),
        'medication_or_treatment': optional_text('medication_or_treatment'),
        'relevant_observations': optional_text('relevant_observations'),
        'heart_rate': optional_number('heart_rate', 'Heart rate', int, 0, 300),
        'blood_pressure': optional_text('blood_pressure'),
        'temperature': optional_number('temperature', 'Temperature', float, 20, 50),
        'oxygen_saturation': optional_number(
            'oxygen_saturation', 'Oxygen saturation', float, 0, 100
        ),
    }


def record_categories_for_user(user):
    """Return only categories the current role may create and later access."""
    if user.is_admin_panel:
        return list(Config.RECORD_CATEGORIES)
    allowed = Config.ROLE_ACCESS.get(user.role) or []
    return [category for category in Config.RECORD_CATEGORIES if category in allowed]


def handle_patient_record_database_error(exc):
    """Convert expected SQLite write failures into safe, actionable UI errors."""
    if isinstance(exc, sqlite3.IntegrityError):
        flash('A patient record with this code already exists. Use a unique patient code.', 'danger')
        return
    if isinstance(exc, sqlite3.OperationalError) and any(
        marker in str(exc).lower() for marker in ('locked', 'busy')
    ):
        app.logger.warning('Patient-record write waited for SQLite but remained busy.')
        flash('The database is busy with another save. Please wait a moment and try again.', 'warning')
        return
    app.logger.exception('Patient-record database write failed safely.')
    flash('The patient record could not be saved safely. No partial changes were kept.', 'danger')


@app.route('/records')
@login_required
@staff_or_admin_required
def patient_records():
    filters = {
        'search': request.args.get('search', '').strip(),
        'category': request.args.get('category', '').strip(),
        'department': request.args.get('department', '').strip(),
        'sensitivity': request.args.get('sensitivity', '').strip(),
        'restricted': request.args.get('restricted', '').strip(),
    }
    try:
        page = max(int(request.args.get('page', 1)), 1)
    except (TypeError, ValueError):
        page = 1
    if filters['sensitivity']:
        try:
            filters['sensitivity'] = normalize_sensitivity(filters['sensitivity'])
        except ValueError:
            filters['sensitivity'] = ''

    records, pagination = get_patient_records_page(
        current_user.role,
        current_user.is_admin_panel,
        filters=filters,
        page=page,
        per_page=15,
    )

    if filters['search']:
        for rec in records[:5]:
            process_access(current_user, rec, 'search')

    return render_template(
        'patient_records.html',
        records=records,
        filters=filters,
        pagination=pagination,
        page_numbers=pagination_window(pagination['page'], pagination['total_pages']),
        categories=Config.RECORD_CATEGORIES,
        departments=Config.DEPARTMENTS,
        sensitivities=Config.SENSITIVITY_LEVELS,
    )


def pagination_window(current_page, total_pages):
    """Return compact accessible page numbers with None as an ellipsis."""
    if total_pages <= 7:
        return list(range(1, total_pages + 1))
    candidates = {1, total_pages, current_page - 1, current_page, current_page + 1}
    ordered = sorted(page for page in candidates if 1 <= page <= total_pages)
    result = []
    previous = None
    for page in ordered:
        if previous is not None and page - previous > 1:
            result.append(None)
        result.append(page)
        previous = page
    return result


@app.route('/records/<int:record_id>')
@login_required
@staff_or_admin_required
def record_detail(record_id):
    record = get_patient_record(record_id)
    if not record:
        abort(404)

    # Log an unauthorized direct attempt for investigation, but never render
    # patient-record content outside the user's category permissions.
    if not current_user.is_admin_panel and not role_can_access_category(
            current_user.role, record['record_category']):
        process_access(current_user, record, 'view')
        abort(403)

    record['is_restricted'] = is_restricted_record(record)

    result = process_access(current_user, record, 'view')
    usb_warning = session.pop('usb_popup', None) or result.get('usb_warning')
    flash(
        _(
            'Record accessed. Risk level: {risk} (hybrid score: {score}/100). '
            'Human review is required when an alert is created.',
            risk=translate_display(result['final_risk_level']),
            score=result['final_hybrid_score'],
        ),
        'info' if result['final_risk_level'] == 'Normal' else 'warning'
    )
    return render_template(
        'record_detail.html', record=record, result=result, usb_warning=usb_warning,
    )


@app.route('/records/<int:record_id>/export')
@login_required
@staff_or_admin_required
def record_export(record_id):
    record = get_patient_record(record_id)
    if not record:
        abort(404)
    if not current_user.is_admin_panel and not role_can_access_category(
            current_user.role, record['record_category']):
        process_access(current_user, record, 'export')
        abort(403)
    result = process_access(current_user, record, 'export')
    if result.get('usb_warning'):
        session['usb_popup'] = result['usb_warning']
    if not result.get('usb_export_allowed', True):
        status = result['usb_warning'].get('device_status', 'pending')
        flash(
            _(
                'USB export denied: this device is {status}. '
                'The attempt was logged and administrators were alerted.',
                status=translate_display(status),
            ),
            'danger',
        )
    else:
        flash(
            _('Export logged. Risk: {risk}', risk=translate_display(result['final_risk_level'])),
            'warning',
        )
    return redirect(url_for('record_detail', record_id=record_id))


@app.route('/records/<int:record_id>/delete', methods=['POST'])
@login_required
@staff_or_admin_required
def record_delete(record_id):
    record = get_patient_record(record_id)
    if not record:
        abort(404)
    result = process_access(current_user, record, 'delete_attempt')
    if current_user.is_admin_panel:
        flash('Delete blocked. Admin audit logged.', 'info')
    else:
        flash(
            _(
                'Delete attempt blocked and logged. Risk: {risk}. '
                'Alert sent to administrator.',
                risk=translate_display(result['final_risk_level']),
            ),
            'danger'
        )
    return redirect(url_for('patient_records'))


# --- Admin routes ---
def _require_admin_password_confirmation():
    password = request.form.get('admin_password', '')
    if not password or not verify_password(current_user._raw, password):
        log_admin_action(
            current_user.id, 'credential_action_reauthentication_failed',
            details=f'endpoint={request.endpoint}; no secret logged',
        )
        raise ValueError('Your administrator password confirmation is incorrect.')


@app.route('/admin/dashboard')
@login_required
@admin_panel_required
def admin_dashboard():
    stats = get_dashboard_stats()
    return render_template('admin_dashboard.html', stats=stats)


@app.route('/admin/pending-users', methods=['GET', 'POST'])
@login_required
@admin_panel_required
def pending_users():
    if request.method == 'POST':
        action = request.form.get('action')
        user_id = int(request.form.get('user_id'))
        role = request.form.get('role')
        department = request.form.get('department')

        if action == 'approve':
            approve_user(user_id, current_user.id, role=role, department=department)
            log_admin_action(current_user.id, 'approve_user', user_id, f'Approved as {role}')
            flash('User approved successfully.', 'success')
        elif action == 'reject':
            reason = request.form.get('rejection_reason', 'Registration rejected by admin.')
            reject_user(user_id, reason)
            log_admin_action(current_user.id, 'reject_user', user_id, reason)
            flash('User registration rejected.', 'warning')

        return redirect(url_for('pending_users'))

    users = get_pending_users()
    for u in users:
        u['created_at_display'] = format_datetime_display(u.get('created_at'))
    return render_template(
        'pending_users.html',
        users=users,
        roles=Config.STAFF_REGISTER_ROLES,
        departments=Config.DEPARTMENTS,
    )


@app.route('/admin/users', methods=['GET', 'POST'])
@login_required
@admin_panel_required
def user_management():
    if request.method == 'POST':
        action = request.form.get('action')
        user_id = request.form.get('user_id', type=int)
        if not user_id:
            abort(400)
        target = get_user_by_id(user_id)
        if not target:
            abort(404)

        if action == 'suspend':
            if not can_manage_user(current_user, target) or target['role'] in Config.ADMIN_PANEL_ROLES:
                abort(403)
            suspend_user(user_id)
            log_admin_action(current_user.id, 'suspend_user', user_id)
            flash('User suspended.', 'warning')
        elif action == 'reactivate':
            if not can_manage_user(current_user, target) or target['role'] in Config.ADMIN_PANEL_ROLES:
                abort(403)
            reactivate_user(user_id)
            log_admin_action(current_user.id, 'reactivate_user', user_id)
            flash('User reactivated.', 'success')
        elif action == 'update':
            if not can_manage_user(current_user, target) or target['role'] in Config.ADMIN_PANEL_ROLES:
                abort(403)
            update_user_details(
                user_id,
                role=request.form.get('role'),
                department=request.form.get('department'),
                work_start=request.form.get('work_start'),
                work_end=request.form.get('work_end'),
            )
            log_admin_action(current_user.id, 'update_user', user_id, 'Details updated')
            flash('User details updated.', 'success')
        elif action == 'delete':
            ok, msg = can_delete_user(current_user._raw, target)
            if not ok:
                flash(msg, 'danger')
            else:
                soft_delete_user(user_id)
                log_admin_action(current_user.id, 'delete_user', user_id, 'Soft deleted user account')
                flash('User account deleted (soft delete). Audit logs are preserved.', 'warning')

        return redirect(url_for('user_management'))

    users = get_all_users()
    for u in users:
        u['created_at_display'] = format_datetime_display(u.get('created_at'))
    return render_template(
        'user_management.html',
        users=users,
        roles=Config.STAFF_REGISTER_ROLES,
        departments=Config.DEPARTMENTS,
        is_super_admin=current_user.is_super_admin,
    )


@app.route('/admin/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_panel_required
def edit_user_account(user_id):
    target = get_user_by_id(user_id)
    if not target:
        abort(404)
    if not can_manage_user(current_user, target):
        abort(403)
    if request.method == 'POST':
        try:
            _require_admin_password_confirmation()
            temporary_password = request.form.get('temporary_password', '')
            if temporary_password != request.form.get('confirm_temporary_password', ''):
                raise ValueError('Temporary password confirmation does not match.')
            result = edit_account(
                current_user, user_id,
                {
                    'full_name': request.form.get('full_name'),
                    'staff_id': request.form.get('staff_id'),
                    'email': request.form.get('email'),
                    'username': request.form.get('username'),
                    'role': request.form.get('role'),
                    'department': request.form.get('department'),
                    'work_start': request.form.get('work_start'),
                    'work_end': request.form.get('work_end'),
                },
                temporary_password=temporary_password or None,
            )
            log_admin_action(
                current_user.id, 'edit_account', user_id,
                (
                    f"username_changed={result['username_changed']};"
                    f"temporary_password_set={result['password_reset']};"
                    f"approval_status_preserved={result['approval_status_preserved']}"
                ),
            )
            if result['credential_changed']:
                flash(
                    'Account updated. Existing sessions were invalidated and any '
                    'temporary password must be changed at the next login.',
                    'success',
                )
            else:
                flash('Account details updated. Account status was preserved.', 'success')
            return redirect(url_for('user_management'))
        except PermissionError:
            abort(403)
        except ValueError as exc:
            flash(str(exc), 'danger')
    return render_template(
        'edit_account.html', user=target,
        roles=['Admin'] if target['role'] == 'Admin' else Config.STAFF_REGISTER_ROLES,
        departments=Config.DEPARTMENTS,
        password_min_length=Config.TEMPORARY_PASSWORD_MIN_LENGTH,
    )


@app.route('/admin/account-recovery')
@login_required
@admin_panel_required
def recovery_requests():
    filters = {
        'status': request.args.get('status', '').strip(),
        'request_type': request.args.get('request_type', '').strip(),
        'requested_destination': request.args.get('requested_destination', '').strip(),
        'search': request.args.get('search', '').strip(),
    }
    rows = get_recovery_requests(current_user, filters)
    visible_rows = get_recovery_requests(current_user)
    stats = {
        status: sum(1 for row in visible_rows if row['status'] == status)
        for status in RECOVERY_STATUSES
    }
    return render_template(
        'recovery_requests.html', requests=rows, filters=filters, stats=stats,
        request_types=REQUEST_TYPES, destinations=DESTINATIONS,
        statuses=RECOVERY_STATUSES,
    )


@app.route('/admin/account-recovery/<int:request_id>', methods=['GET', 'POST'])
@login_required
@admin_panel_required
def recovery_request_detail(request_id):
    recovery = get_recovery_request(request_id, current_user)
    if not recovery:
        abort(404)
    if request.method == 'POST':
        action = request.form.get('action', '')
        try:
            _require_admin_password_confirmation()
            if action == 'start_review':
                matched_user_id = request.form.get('matched_user_id', type=int)
                if not matched_user_id:
                    raise ValueError('Select the institutional account being reviewed.')
                start_recovery_review(
                    request_id, current_user, matched_user_id,
                    request.form.get('review_notes', ''),
                )
                log_admin_action(
                    current_user.id, 'start_account_recovery_review', matched_user_id,
                    f"reference={recovery['public_reference']}",
                )
                flash('Recovery review started and assigned securely.', 'success')
            elif action == 'verify_identity':
                target = verify_recovery_identity(
                    request_id, current_user,
                    request.form.get('identity_verification_method', ''),
                    request.form.get('identity_verification_notes', ''),
                )
                log_admin_action(
                    current_user.id, 'verify_recovery_identity', target['id'],
                    (
                        f"reference={recovery['public_reference']};"
                        f"method={request.form.get('identity_verification_method', '')}"
                    ),
                )
                flash('Identity verification recorded. Credential actions are now available.', 'success')
            elif action == 'reject':
                target = reject_recovery_request(
                    request_id, current_user, request.form.get('review_notes', ''),
                )
                log_admin_action(
                    current_user.id, 'reject_account_recovery',
                    target['id'] if target else None,
                    f"reference={recovery['public_reference']}; no credentials changed",
                )
                flash('Recovery request rejected. No account credentials were changed.', 'warning')
            elif action == 'resolve':
                temporary_password = request.form.get('temporary_password', '')
                if temporary_password != request.form.get('confirm_temporary_password', ''):
                    raise ValueError('Temporary password confirmation does not match.')
                result = resolve_recovery_request(
                    request_id, current_user,
                    request.form.get('resolution_type', ''),
                    request.form.get('new_username', ''),
                    temporary_password or None,
                )
                target = result['target']
                log_admin_action(
                    current_user.id, 'resolve_account_recovery', target['id'],
                    (
                        f"reference={recovery['public_reference']};"
                        f"resolution={result['resolution_type']};"
                        f"sessions_invalidated={result['credential_changed']}"
                    ),
                )
                send_message(
                    current_user.id, target['id'], 'Account recovery request completed',
                    'Your account recovery request was completed after identity verification. '
                    'Use only the institution’s approved support process to receive any account '
                    'instructions. No password is included in this message.',
                    is_urgent=True,
                )
                flash(
                    'Recovery completed. Communicate account instructions only through the '
                    'institution’s approved verification process.',
                    'success',
                )
            else:
                abort(400)
            return redirect(url_for('recovery_request_detail', request_id=request_id))
        except PermissionError:
            abort(403)
        except ValueError as exc:
            flash(str(exc), 'danger')
    recovery = get_recovery_request(request_id, current_user)
    allowed_resolutions = {
        key: label for key, label in RESOLUTION_TYPES.items()
        if key in {
            'forgot_username': {'username_recovered', 'username_updated'},
            'forgot_password': {'password_reset'},
            'forgot_both': {'both_recovered', 'both_updated'},
        }.get(recovery['request_type'], set())
    }
    return render_template(
        'recovery_request_detail.html', recovery=recovery,
        manageable_users=get_manageable_users(current_user),
        request_types=REQUEST_TYPES, destinations=DESTINATIONS,
        verification_methods=VERIFICATION_METHODS,
        resolution_types=allowed_resolutions,
        password_min_length=Config.TEMPORARY_PASSWORD_MIN_LENGTH,
    )


@app.route('/admin/users/<int:user_id>/activity')
@login_required
@admin_panel_required
def user_activity(user_id):
    activity = get_user_activity_summary(user_id)
    if not activity:
        abort(404)
    return render_template('user_activity.html', activity=activity)


@app.route('/admin/events')
@login_required
@admin_panel_required
def admin_events():
    filters = {
        'username': request.args.get('username'),
        'staff_id': request.args.get('staff_id'),
        'record_id': request.args.get('record_id'),
        'date_from': request.args.get('date_from'),
        'date_to': request.args.get('date_to'),
        'role': request.args.get('role'),
        'department': request.args.get('department'),
        'risk_level': request.args.get('risk_level'),
    }
    filters = {k: v for k, v in filters.items() if v}
    events = get_access_events(filters)
    return render_template('events.html', events=events, filters=filters,
                           roles=Config.ROLES, departments=Config.DEPARTMENTS,
                           risk_levels=Config.RISK_LEVELS)


@app.route('/admin/alerts', methods=['GET', 'POST'])
@login_required
@admin_panel_required
def admin_alerts():
    if request.method == 'POST':
        alert_id = int(request.form.get('alert_id'))
        action = request.form.get('action', 'resolve')
        if action == 'delete':
            delete_alert(alert_id)
            log_admin_action(current_user.id, 'delete_alert', details=f'alert_id={alert_id}')
            flash('Alert deleted.', 'warning')
        else:
            notes = request.form.get('notes', '')
            resolve_alert(alert_id, current_user.id, notes)
            flash('Alert marked as resolved.', 'success')
        return_filters = {
            key: request.form.get(key, '').strip()
            for key in ('severity', 'status', 'search', 'page')
            if request.form.get(key, '').strip()
        }
        return redirect(url_for('admin_alerts', **return_filters))

    filters = {
        'severity': request.args.get('severity'),
        'status': request.args.get('status'),
        'search': request.args.get('search', '').strip(),
    }
    filters = {k: v for k, v in filters.items() if v}
    per_page = 10
    page = max(request.args.get('page', 1, type=int) or 1, 1)
    filtered_total = get_alert_count(filters)
    total_pages = max((filtered_total + per_page - 1) // per_page, 1)
    page = min(page, total_pages)
    alerts = get_alerts(filters, limit=per_page, offset=(page - 1) * per_page)
    alert_summary = get_alert_summary()
    filter_options = get_alert_filter_options()
    pagination = {
        'page': page,
        'per_page': per_page,
        'total_pages': total_pages,
        'filtered_total': filtered_total,
        'showing_from': ((page - 1) * per_page + 1) if filtered_total else 0,
        'showing_to': min(page * per_page, filtered_total),
    }
    return render_template(
        'alerts.html', alerts=alerts, filters=filters,
        alert_summary=alert_summary, filter_options=filter_options,
        pagination=pagination,
    )


@app.route('/admin/reports', methods=['GET', 'POST'])
@login_required
@admin_panel_required
def admin_reports():
    if request.method == 'POST':
        report_type = request.form.get('report_type', 'daily')
        if report_type == 'daily':
            path = generate_daily_report(generated_by=current_user.id)
            flash(f'Daily report generated: {os.path.basename(path)}', 'success')
        elif report_type == 'alerts':
            path = generate_alert_report(generated_by=current_user.id)
            flash(f'Alert report generated: {os.path.basename(path)}', 'success')
        elif report_type == 'activity':
            path = generate_user_activity_report(generated_by=current_user.id)
            flash(f'User activity report generated: {os.path.basename(path)}', 'success')
        return redirect(url_for('admin_reports'))

    history = get_report_history()
    return render_template('reports.html', reports=history)


@app.route('/admin/patient-data', methods=['GET', 'POST'])
@login_required
@admin_panel_required
def patient_data_management():
    if request.method == 'POST':
        action = request.form.get('action', 'create')
        if action in ('create', 'update'):
            try:
                record_data = patient_record_form_data(request.form)
            except ValueError as exc:
                flash(str(exc), 'danger')
                return render_patient_data_management_form(
                    request.form, action, status=400
                )
            if not record_data['patient_code'] or not record_data['record_title'] or not record_data['content']:
                flash('Patient code, record title, and general content are required.', 'danger')
                return render_patient_data_management_form(
                    request.form, action, status=400
                )

            if action == 'create':
                try:
                    create_patient_record(record_data)
                    log_admin_action(current_user.id, 'create_patient_record', details=record_data['patient_code'])
                except sqlite3.DatabaseError as exc:
                    handle_patient_record_database_error(exc)
                    return redirect(url_for('patient_data_management'))
                flash('Simulated patient record created.', 'success')
            else:
                record_id = int(request.form.get('record_id'))
                try:
                    update_patient_record(record_id, record_data)
                    log_admin_action(current_user.id, 'update_patient_record', details=f"id={record_id}")
                except sqlite3.DatabaseError as exc:
                    handle_patient_record_database_error(exc)
                    return redirect(url_for('patient_data_management'))
                flash('Simulated patient record updated.', 'success')
        elif action == 'deactivate':
            record_id = int(request.form.get('record_id'))
            try:
                deactivate_patient_record(record_id)
                log_admin_action(current_user.id, 'deactivate_patient_record', details=f"id={record_id}")
            except sqlite3.DatabaseError as exc:
                handle_patient_record_database_error(exc)
                return redirect(url_for('patient_data_management'))
            flash('Patient record deactivated.', 'warning')
        return redirect(url_for('patient_data_management'))

    return render_patient_data_management_form()


def render_patient_data_management_form(
        submitted_record=None, submitted_action=None, status=200):
    """Render admin record forms while preserving rejected submissions."""
    records = get_all_patient_records()
    for record in records:
        record['is_restricted'] = is_restricted_record(record)
    rendered = render_template(
        'patient_data_management.html',
        records=records,
        categories=Config.RECORD_CATEGORIES,
        departments=Config.DEPARTMENTS,
        sensitivities=Config.SENSITIVITY_LEVELS,
        submitted_record=submitted_record,
        submitted_action=submitted_action,
    )
    return (rendered, status) if status != 200 else rendered


@app.route('/admin/messages', methods=['GET', 'POST'])
@login_required
@admin_panel_required
def admin_messages():
    if request.method == 'POST' and request.form.get('action') == 'delete_message':
        msg_id = int(request.form.get('message_id'))
        delete_message(msg_id, sender_id=current_user.id)
        flash('Message deleted.', 'warning')
        return redirect(url_for('admin_messages'))

    sent_messages = get_sent_messages(current_user.id)
    users = [
        u for u in get_all_users()
        if u['id'] != current_user.id and u['role'] not in Config.ADMIN_PANEL_ROLES
    ]
    return render_template('admin_messages.html', sent_messages=sent_messages, users=users)


@app.route('/admin/create-user', methods=['GET', 'POST'])
@login_required
@admin_panel_required
def admin_create_user():
    """Emergency pre-approved staff account (when self-registration is not possible)."""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        staff_id = request.form.get('staff_id', '').strip()
        email = request.form.get('email', '').strip()
        if get_user_by_username(username):
            flash('Username already exists.', 'danger')
        elif get_user_by_staff_id(staff_id):
            flash('Staff ID already exists.', 'danger')
        elif get_user_by_email(email):
            flash('Email already exists.', 'danger')
        else:
            valid, password_error = validate_password_policy(request.form.get('password', ''))
            if not valid:
                flash(password_error, 'danger')
                return redirect(url_for('admin_create_user'))
            create_approved_staff_user({
                'full_name': request.form.get('full_name'),
                'staff_id': staff_id,
                'email': email,
                'username': username,
                'password': request.form.get('password'),
                'role': request.form.get('role'),
                'department': request.form.get('department'),
                'work_start': request.form.get('work_start', '08:00'),
                'work_end': request.form.get('work_end', '17:00'),
                'must_change_password': True,
            }, created_by_id=current_user.id)
            log_admin_action(
                current_user.id, 'emergency_create_user', details=f'username={username}'
            )
            flash(
                f'Emergency account created for {username}. User can log in immediately.',
                'success',
            )
            return redirect(url_for('user_management'))
    return render_template(
        'create_staff_user.html',
        roles=Config.STAFF_REGISTER_ROLES,
        departments=Config.DEPARTMENTS,
    )


@app.route('/admin/messages/send', methods=['POST'])
@login_required
@admin_panel_required
def send_admin_message():
    receiver_id = int(request.form.get('receiver_id'))
    title = request.form.get('title', '').strip()
    body = request.form.get('body', '').strip()
    is_urgent = bool(request.form.get('is_urgent'))
    if not title or not body:
        flash('Message title and content are required.', 'danger')
    else:
        send_message(current_user.id, receiver_id, title, body, is_urgent=is_urgent)
        log_admin_action(current_user.id, 'send_message', receiver_id, title)
        flash('Message sent successfully.', 'success')
    return redirect(url_for('admin_messages'))


@app.route('/admin/messages/send', methods=['GET'])
@login_required
@admin_panel_required
def send_admin_message_page():
    users = [
        u for u in get_all_users()
        if u['id'] != current_user.id and u['role'] not in Config.ADMIN_PANEL_ROLES
    ]
    return render_template('send_message.html', users=users)


@app.route('/messages')
@login_required
@staff_or_admin_required
def user_messages():
    messages = get_messages_for_user(current_user.id)
    return render_template('user_messages.html', messages=messages)


@app.route('/messages/mark-read/<int:message_id>', methods=['POST'])
@login_required
@staff_or_admin_required
def user_mark_message_read(message_id):
    message = get_message(message_id)
    if not message or message['receiver_id'] != current_user.id:
        abort(403)
    mark_message_read(message_id, current_user.id)
    return redirect(request.referrer or url_for('user_messages'))


@app.route('/admin/manage-admins', methods=['GET', 'POST'])
@login_required
@super_admin_required
def manage_admins():
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'create':
            if get_user_by_username(request.form.get('username', '').strip()):
                flash('Username already exists.', 'danger')
            elif get_user_by_staff_id(request.form.get('staff_id', '').strip()):
                flash('Staff ID already exists.', 'danger')
            else:
                valid, password_error = validate_password_policy(request.form.get('password', ''))
                if not valid:
                    flash(password_error, 'danger')
                    return redirect(url_for('manage_admins'))
                create_admin_user({
                    'full_name': request.form.get('full_name'),
                    'staff_id': request.form.get('staff_id'),
                    'email': request.form.get('email'),
                    'username': request.form.get('username'),
                    'password': request.form.get('password'),
                    'department': request.form.get('department', 'Administration'),
                    'work_start': request.form.get('work_start', '08:00'),
                    'work_end': request.form.get('work_end', '17:00'),
                    'must_change_password': True,
                }, current_user.id)
                log_admin_action(current_user.id, 'create_admin', details=request.form.get('username'))
                flash('New Admin account created.', 'success')
        elif action == 'update':
            uid = int(request.form.get('user_id'))
            target = get_user_by_id(uid)
            username = request.form.get('username', '').strip()
            staff_id = request.form.get('staff_id', '').strip()
            email = request.form.get('email', '').strip()
            duplicates = (
                (get_user_by_username(username), 'Username'),
                (get_user_by_staff_id(staff_id), 'Staff ID'),
                (get_user_by_email(email), 'Email'),
            )
            conflict = next(
                (label for existing, label in duplicates if existing and existing['id'] != uid),
                None,
            )
            if not target or target['role'] != 'Admin':
                abort(404)
            elif conflict:
                flash(f'{conflict} is already in use.', 'danger')
            else:
                try:
                    _require_admin_password_confirmation()
                except ValueError as exc:
                    flash(str(exc), 'danger')
                    return redirect(url_for('manage_admins'))
                update_admin_user(
                    uid,
                    full_name=request.form.get('full_name'),
                    staff_id=staff_id,
                    email=email,
                    username=username,
                    department=request.form.get('department'),
                    work_start=request.form.get('work_start'),
                    work_end=request.form.get('work_end'),
                    changed_by=current_user.id,
                )
                log_admin_action(
                    current_user.id, 'update_admin_account', uid,
                    'Admin details updated; username change invalidates sessions.',
                )
                flash('Admin details updated.', 'success')
        elif action == 'password':
            uid = int(request.form.get('user_id'))
            target = get_user_by_id(uid)
            if not target or target['role'] != 'Admin':
                abort(403)
            pwd = request.form.get('new_password', '')
            try:
                _require_admin_password_confirmation()
            except ValueError as exc:
                flash(str(exc), 'danger')
                return redirect(url_for('manage_admins'))
            valid, password_error = validate_password_policy(pwd)
            if not valid:
                flash(password_error, 'danger')
            else:
                set_user_password(
                    uid, pwd, must_change=True, changed_by=current_user.id,
                )
                log_admin_action(
                    current_user.id, 'change_admin_password', uid,
                    'Temporary password set; sessions invalidated; no secret logged.',
                )
                flash(
                    'Temporary password set. Existing sessions were invalidated and '
                    'the Admin must change it at next login.',
                    'success',
                )
        elif action == 'delete':
            uid = int(request.form.get('user_id'))
            target = get_user_by_id(uid)
            if target and target['role'] == 'Admin':
                soft_delete_user(uid)
                log_admin_action(current_user.id, 'delete_admin', uid)
                flash('Admin account deleted.', 'warning')
        return redirect(url_for('manage_admins'))

    admins = get_admin_users()
    for a in admins:
        a['created_at_display'] = format_datetime_display(a.get('created_at'))
    return render_template(
        'manage_admins.html',
        admins=admins,
        departments=Config.DEPARTMENTS,
    )


@app.route('/simulated-patient-data', methods=['GET', 'POST'])
@login_required
@staff_or_admin_required
def simulated_patient_data():
    """Approved users can add simulated records within their role categories."""
    allowed_categories = record_categories_for_user(current_user)
    if request.method == 'POST':
        try:
            record_data = patient_record_form_data(
                request.form, allowed_categories=allowed_categories
            )
        except ValueError as exc:
            flash(str(exc), 'danger')
            return render_template(
                'simulated_patient_data.html',
                categories=allowed_categories,
                departments=Config.DEPARTMENTS,
                sensitivities=Config.SENSITIVITY_LEVELS,
                submitted_record=request.form,
            ), 400
        if not record_data['patient_code'] or not record_data['record_title'] or not record_data['content']:
            flash('Patient code, record title, and general content are required.', 'danger')
            return render_template(
                'simulated_patient_data.html',
                categories=allowed_categories,
                departments=Config.DEPARTMENTS,
                sensitivities=Config.SENSITIVITY_LEVELS,
                submitted_record=request.form,
            ), 400
        else:
            try:
                create_patient_record(record_data)
            except sqlite3.DatabaseError as exc:
                handle_patient_record_database_error(exc)
                return redirect(url_for('simulated_patient_data'))
            flash(
                f"Simulated record {record_data['patient_code']} created. "
                'It is now available in Patient Records.',
                'success',
            )
            return redirect(url_for('simulated_patient_data'))

    return render_template(
        'simulated_patient_data.html',
        categories=allowed_categories,
        departments=Config.DEPARTMENTS,
        sensitivities=Config.SENSITIVITY_LEVELS,
        submitted_record=None,
    )


@app.route('/admin/reports/view/<int:report_id>')
@login_required
@admin_panel_required
def view_report(report_id):
    report = get_report_by_id(report_id)
    if not report or not os.path.exists(report['file_path']):
        abort(404)
    rows = read_report_as_table(report['file_path'])
    return render_template('report_view.html', report=report, rows=rows)


@app.route('/admin/reports/download/<int:report_id>')
@login_required
@admin_panel_required
def download_report(report_id):
    from database import get_db
    conn = get_db()
    report = conn.execute('SELECT * FROM reports WHERE id = ?', (report_id,)).fetchone()
    conn.close()
    if not report or not os.path.exists(report['file_path']):
        abort(404)
    return send_file(report['file_path'], as_attachment=True)


# --- USB Monitoring ---
@app.route('/admin/usb-monitoring', methods=['GET', 'POST'])
@login_required
@admin_panel_required
def usb_monitoring():
    import usb_engine

    if request.method == 'POST':
        action = request.form.get('action')
        computer = (request.form.get('computer_name') or 'SIM-PC').strip()[:120]
        browser_info = request.headers.get('User-Agent', '')[:500]

        if action == 'add_whitelist':
            try:
                add_usb_to_whitelist({
                    'usb_name': request.form.get('usb_name', '').strip(),
                    'usb_serial': request.form.get('usb_serial', '').strip(),
                    'usb_size': request.form.get('usb_size', '').strip(),
                    'notes': request.form.get('notes', '').strip(),
                }, current_user.id)
                log_admin_action(
                    current_user.id, 'whitelist_usb_device',
                    details=f"serial={request.form.get('usb_serial', '').strip()}",
                )
                flash('USB device added to whitelist.', 'success')
            except (ValueError, KeyError):
                flash('A valid USB name and stable serial are required.', 'danger')
        elif action == 'remove_whitelist':
            device_id = request.form.get('device_id', type=int)
            device = remove_usb_from_whitelist(
                device_id, current_user.id, request.form.get('review_notes', ''),
            ) if device_id else None
            if device:
                log_admin_action(
                    current_user.id, 'set_usb_device_pending',
                    details=f'device_id={device_id}',
                )
                flash('USB device returned to pending review.', 'info')
            else:
                flash('USB device was not found.', 'danger')
        elif action in ('whitelist_device', 'block_device', 'set_pending'):
            device_id = request.form.get('device_id', type=int)
            new_status = {
                'whitelist_device': 'whitelisted',
                'block_device': 'blocked',
                'set_pending': 'pending',
            }[action]
            device = set_usb_device_status(
                device_id, new_status, current_user.id,
                request.form.get('review_notes', ''),
            ) if device_id else None
            if device:
                log_admin_action(
                    current_user.id, f'{new_status}_usb_device',
                    details=f'device_id={device_id};serial={device["usb_serial"]}',
                )
                flash(
                    _('USB device status changed to {status}.', status=translate_display(new_status)),
                    'success',
                )
            else:
                flash('USB device was not found.', 'danger')
        elif action == 'simulate_unknown':
            usb_engine.simulate_unknown_insert(
                current_user, computer, session, browser_info=browser_info,
            )
            flash(
                'Unknown USB simulated and registered for auto-monitoring on patient access.',
                'warning',
            )
        elif action == 'simulate_whitelisted':
            usb_engine.simulate_whitelisted_insert(
                current_user, computer, session, browser_info=browser_info,
            )
            simulation_status = usb_engine.get_usb_device_status(
                usb_engine.WHITELISTED_USB['usb_serial']
            )
            if simulation_status == 'whitelisted':
                flash('Hospital simulation USB inserted and logged as whitelisted.', 'success')
            else:
                flash(
                    _(
                        'Hospital simulation USB inserted with {status} status. '
                        'Administrator review is required before export.',
                        status=translate_display(simulation_status),
                    ),
                    'warning',
                )
        elif action == 'simulate_removed':
            usb_engine.simulate_usb_removed(
                current_user, computer_name=computer, session=session,
                browser_info=browser_info,
            )
            flash('USB removed — auto-monitoring cleared for this session.', 'info')
        elif action == 'simulate_export':
            export_result = usb_engine.simulate_export_to_usb(
                current_user, computer, session, browser_info=browser_info,
            )
            if export_result['export_allowed']:
                flash('Simulated patient-record export permitted and logged.', 'warning')
            else:
                flash(
                    _(
                        'USB export denied: device is {status}. Attempt logged and alerted.',
                        status=translate_display(export_result['device_status']),
                    ),
                    'danger',
                )
        return redirect(url_for('usb_monitoring'))

    filters = {
        'username': request.args.get('username', '').strip() or None,
        'date_from': request.args.get('date_from') or None,
        'date_to': request.args.get('date_to') or None,
        'computer_name': request.args.get('computer_name', '').strip() or None,
        'event_type': request.args.get('event_type') or None,
        'risk_level': request.args.get('risk_level') or None,
        'usb_query': request.args.get('usb_query', '').strip() or None,
        'device_status': request.args.get('device_status') or None,
        'device_id': request.args.get('device_id', type=int),
    }
    return render_template(
        'usb_monitoring.html',
        devices=get_usb_devices(),
        events=get_usb_events(filters),
        filters=filters,
        event_types=[
            'inserted', 'whitelisted_insert', 'auto_detected', 'removed',
            'export_to_usb', 'blocked_export', 'patient_access_usb', 'sensitive_access_usb',
        ],
        risk_levels=Config.RISK_LEVELS,
        device_statuses=['pending', 'whitelisted', 'blocked'],
    )


# --- Security Management ---
@app.route('/admin/security', methods=['GET', 'POST'])
@login_required
@admin_panel_required
def security_management():
    from security_engine import admin_unlock_account

    if request.method == 'POST' and request.form.get('unlock_user_id'):
        user_id = int(request.form['unlock_user_id'])
        admin_unlock_account(user_id, current_user.id)
        flash('Account unlocked successfully.', 'success')
        return redirect(url_for('security_management'))

    return render_template(
        'security_management.html',
        stats=get_security_dashboard_stats(),
        failed_logins=get_recent_failed_logins(),
        locked_accounts=get_locked_accounts(),
        model_status=ai_engine.get_model_status(),
    )


@app.route('/admin/security/model/retrain', methods=['POST'])
@login_required
@admin_panel_required
def retrain_behaviour_model():
    try:
        metadata = ai_engine.train_and_save_model(trained_by=current_user.id)
        log_admin_action(
            current_user.id, 'retrain_behaviour_model',
            details=(
                f"version={metadata['model_version']};"
                f"events={metadata['training_events']}"
            ),
        )
        flash(
            f"Behavioural model {metadata['model_version']} trained on "
            f"{metadata['training_events']} historical events.",
            'success',
        )
    except Exception as exc:
        log_admin_action(
            current_user.id, 'retrain_behaviour_model_failed',
            details=str(exc)[:500],
        )
        flash(f'Model retraining failed safely: {exc}', 'danger')
    return redirect(url_for('security_management'))


@app.route('/api/usb/check')
@login_required
@staff_or_admin_required
def api_usb_check():
    """Live USB status check for patient data pages."""
    import usb_engine
    browser_info = request.headers.get('User-Agent', '')[:500]
    computer_name = (
        request.headers.get('X-Computer-Name')
        or session.get('usb_computer_name')
        or 'Web session'
    )[:120]
    devices = usb_engine.detect_usb_for_session(
        session, current_user, computer_name=computer_name, browser_info=browser_info,
    )
    for device in devices:
        if not usb_engine.is_usb_connection_active(current_user.id, device['usb_serial']):
            whitelisted = device.get('status') == 'whitelisted'
            usb_engine.record_usb_event(
                current_user,
                'whitelisted_insert' if whitelisted else 'auto_detected',
                device,
                computer_name,
                risk_level='Normal' if whitelisted else 'Critical',
                create_alert=not whitelisted,
                browser_info=browser_info,
            )
    active = usb_engine.get_active_usb_connection(current_user.id)
    payload = {
        'connected': len(devices) > 0,
        'devices': devices,
        'active_usb': active,
        'monitoring': True,
    }
    return jsonify(payload)


# --- Chart APIs ---
@app.route('/api/charts/access-timeline')
@login_required
@admin_panel_required
def api_access_timeline():
    return jsonify(get_chart_access_timeline())


@app.route('/api/charts/alerts-by-severity')
@login_required
@admin_panel_required
def api_alerts_severity():
    return jsonify(get_chart_alerts_by_severity())


@app.route('/api/charts/user-registrations')
@login_required
@admin_panel_required
def api_user_registrations():
    return jsonify(get_chart_user_registrations())


# --- Error handlers ---
@app.errorhandler(403)
def forbidden(e):
    return render_template('error.html', code=403, message='Access denied.'), 403


@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', code=404, message='Page not found.'), 404


@app.errorhandler(400)
def bad_request(e):
    return render_template('error.html', code=400, message='Bad request.'), 400


@app.errorhandler(CSRFError)
def csrf_error(e):
    return render_template('error.html', code=400, message=_(e.description)), 400


# --- Init ---
with app.app_context():
    init_db()
    os.makedirs(Config.REPORTS_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(Config.ML_MODEL_PATH), exist_ok=True)
    ai_engine.load_model()

if __name__ == '__main__':
    # Werkzeug imports this module once in the reloader parent and again in the
    # serving child. Only the child should run scheduled database jobs.
    if os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
        start_scheduler()
    app.run(debug=True, host='127.0.0.1', port=5000)
else:
    # Production WSGI servers import the application instead of executing it.
    start_scheduler()
