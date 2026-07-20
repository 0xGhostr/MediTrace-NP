/** Apply the allowlisted saved theme before stylesheets render. */
(function () {
    'use strict';
    var theme = 'light';
    try {
        var saved = window.localStorage.getItem('meditrace-theme');
        if (saved === 'dark' || saved === 'light') theme = saved;
    } catch (error) {
        theme = 'light';
    }
    document.documentElement.setAttribute('data-theme', theme);
}());
