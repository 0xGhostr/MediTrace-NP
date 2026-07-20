/** Frontend-only MediTrace-NP light/dark preference control. */
(function () {
    'use strict';

    var STORAGE_KEY = 'meditrace-theme';
    var ALLOWED_THEMES = ['light', 'dark'];

    function normalizeTheme(value) {
        return ALLOWED_THEMES.indexOf(value) !== -1 ? value : 'light';
    }

    function currentTheme() {
        return normalizeTheme(document.documentElement.getAttribute('data-theme'));
    }

    function updateControls(theme) {
        document.querySelectorAll('.theme-toggle').forEach(function (button) {
            var darkActive = theme === 'dark';
            var targetLabel = darkActive ? button.dataset.labelLight : button.dataset.labelDark;
            var icon = button.querySelector('i');
            button.setAttribute('aria-pressed', darkActive ? 'true' : 'false');
            button.setAttribute('aria-label', targetLabel);
            button.setAttribute('title', targetLabel);
            if (icon) icon.className = darkActive ? 'bi bi-sun' : 'bi bi-moon-stars';
        });
    }

    function applyTheme(value, persist) {
        var theme = normalizeTheme(value);
        document.documentElement.setAttribute('data-theme', theme);
        if (persist !== false) {
            try {
                window.localStorage.setItem(STORAGE_KEY, theme);
            } catch (error) {
                // The theme still works for this page when storage is unavailable.
            }
        }
        updateControls(theme);
        document.dispatchEvent(new CustomEvent('meditrace:themechange', {
            detail: { theme: theme }
        }));
        return theme;
    }

    document.addEventListener('DOMContentLoaded', function () {
        updateControls(currentTheme());
        document.querySelectorAll('.theme-toggle').forEach(function (button) {
            button.addEventListener('click', function () {
                applyTheme(currentTheme() === 'dark' ? 'light' : 'dark', true);
            });
        });
    });

    window.MediTraceTheme = Object.freeze({
        get: currentTheme,
        set: function (theme) { return applyTheme(theme, true); }
    });
}());
