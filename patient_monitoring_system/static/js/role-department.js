/** Role-aware department choices. Server-side validation remains authoritative. */
document.addEventListener('DOMContentLoaded', function () {
    const matrix = window.MediTraceRoleDepartments || {};

    document.querySelectorAll('form').forEach(function (form) {
        const role = form.querySelector('[data-role-department-role]');
        const department = form.querySelector('[data-role-department-department]');
        if (!role || !department) return;

        const initialDepartment = department.value;
        const reviewLabel = department.dataset.reviewLabel || 'requires review';

        function renderDepartments(preserveLegacy) {
            const selected = department.value || initialDepartment;
            const allowed = matrix[role.value] || [];
            department.replaceChildren();

            allowed.forEach(function (item) {
                const option = document.createElement('option');
                option.value = item.value;
                option.textContent = item.label;
                department.appendChild(option);
            });

            const valid = allowed.some(function (item) { return item.value === selected; });
            if (preserveLegacy && selected && !valid) {
                const legacy = document.createElement('option');
                legacy.value = selected;
                legacy.textContent = selected + ' - ' + reviewLabel;
                legacy.selected = true;
                department.prepend(legacy);
            } else if (valid) {
                department.value = selected;
            } else if (department.options.length) {
                department.selectedIndex = 0;
            }
        }

        renderDepartments(true);
        role.addEventListener('change', function () { renderDepartments(false); });
    });
});
