/**
 * Patient Records — client-side filter panel (no backend changes).
 * Server search still uses GET ?search= via form submit.
 */
document.addEventListener('DOMContentLoaded', function () {
    const i18n = (window.MediTraceI18n && window.MediTraceI18n.messages) || {};
    const t = (key) => i18n[key] || key;
    const table = document.getElementById('prRecordsTable');
    if (!table) return;

    const rows = Array.from(table.querySelectorAll('tbody tr[data-record-id]'));
    const filterCategory = document.getElementById('prFilterCategory');
    const filterDepartment = document.getElementById('prFilterDepartment');
    const filterSensitivity = document.getElementById('prFilterSensitivity');
    const clearBtn = document.getElementById('prClearFilters');
    const showingEl = document.getElementById('prShowingCount');
    const total = rows.length;

    function applyClientFilters() {
        const cat = filterCategory ? filterCategory.value : '';
        const dept = filterDepartment ? filterDepartment.value : '';
        const sens = filterSensitivity ? filterSensitivity.value : '';
        let visible = 0;

        rows.forEach(function (row) {
            const matchCat = !cat || row.dataset.category === cat;
            const matchDept = !dept || row.dataset.department === dept;
            const matchSens = !sens || row.dataset.sensitivity === sens;
            const show = matchCat && matchDept && matchSens;
            row.classList.toggle('pr-row-hidden', !show);
            if (show) visible += 1;
        });

        if (showingEl) {
            showingEl.textContent = t('Showing {visible} of {total} records')
                .replace('{visible}', visible).replace('{total}', total);
        }
    }

    [filterCategory, filterDepartment, filterSensitivity].forEach(function (el) {
        if (el) el.addEventListener('change', applyClientFilters);
    });

    if (clearBtn) {
        clearBtn.addEventListener('click', function () {
            if (filterCategory) filterCategory.value = '';
            if (filterDepartment) filterDepartment.value = '';
            if (filterSensitivity) filterSensitivity.value = '';
            applyClientFilters();
        });
    }

    applyClientFilters();
});
