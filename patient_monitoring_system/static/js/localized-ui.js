/** Shared localized UI behaviours that do not change server-side workflows. */
document.addEventListener('DOMContentLoaded', function () {
    document.querySelectorAll('form[data-confirm]').forEach(function (form) {
        form.addEventListener('submit', function (event) {
            if (!window.confirm(form.dataset.confirm)) event.preventDefault();
        });
    });
    document.querySelectorAll('button[data-confirm]').forEach(function (button) {
        button.addEventListener('click', function (event) {
            if (!window.confirm(button.dataset.confirm)) event.preventDefault();
        });
    });
});
