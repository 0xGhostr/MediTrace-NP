/** Live USB inventory status on patient-data pages. */
document.addEventListener('DOMContentLoaded', function () {
    const i18n = (window.MediTraceI18n && window.MediTraceI18n.messages) || {};
    const t = (key) => i18n[key] || key;
    const bannerHost = document.getElementById('usbLiveBanner');
    if (!bannerHost) return;

    let lastState = null;

    function escapeHtml(value) {
        return String(value == null ? '' : value)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;')
            .replace(/>/g, '&gt;').replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    function renderBanner(data) {
        if (!data.connected || !data.devices || !data.devices.length) {
            bannerHost.innerHTML = '';
            bannerHost.classList.add('d-none');
            return;
        }

        const dev = data.devices[0];
        const status = dev.status || (data.active_usb && data.active_usb.device_status) || 'pending';
        const approved = status === 'whitelisted';
        const cls = approved ? 'alert-success usb-status-banner whitelisted' : 'alert-danger usb-status-banner';
        const heading = status === 'blocked' ? t('Blocked USB Connected') :
            (approved ? t('USB Connected (Whitelisted)') : t('USB Pending Review — Monitoring Active'));
        const policyText = approved ?
            t('Patient-data USB operations are permitted and continue to be logged.') :
            t('Patient-record USB export is denied until an administrator whitelists this device.');

        bannerHost.className = 'mb-3';
        bannerHost.innerHTML =
            '<div class="alert ' + cls + ' d-flex align-items-start gap-2 mb-0" role="alert">' +
            '<i class="bi bi-usb-drive-fill fs-5"></i><div>' +
            '<strong>' + escapeHtml(heading) + '</strong>' +
            '<div class="small mt-1">' + escapeHtml(dev.usb_name) + ' · ' +
            escapeHtml(dev.drive_letter || t('N/A')) + ' · ' + escapeHtml(t('Serial')) + ': <code>' +
            escapeHtml(dev.usb_serial) + '</code></div>' +
            '<div class="small text-muted">' + policyText + '</div></div></div>';
    }

    function poll() {
        fetch('/api/usb/check', { credentials: 'same-origin' })
            .then(function (response) { return response.json(); })
            .then(function (data) {
                const key = JSON.stringify(data.devices || []);
                if (key !== lastState) {
                    lastState = key;
                    renderBanner(data);
                }
            })
            .catch(function () {});
    }

    poll();
    setInterval(poll, 15000);
});
