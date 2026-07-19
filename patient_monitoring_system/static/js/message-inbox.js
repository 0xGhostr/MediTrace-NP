(function () {
    'use strict';

    function initMessageCenter(center) {
        const i18n = (window.MediTraceI18n && window.MediTraceI18n.messages) || {};
        const t = (key) => i18n[key] || key;
        const rows = Array.from(center.querySelectorAll('[data-message-row]'));
        const searchInput = center.querySelector('[data-message-search]');
        const statusFilter = center.querySelector('[data-message-status-filter]');
        const priorityFilter = center.querySelector('[data-message-priority-filter]');
        const filteredCount = center.querySelector('[data-message-filter-count]');
        const noResults = center.querySelector('[data-message-no-results]');
        const detailPanel = center.querySelector('[data-message-detail-panel]');

        function messageLabel(count) {
            return count === 1 ? t('message') : t('messages');
        }

        function updateFilters() {
            const query = (searchInput.value || '').trim().toLowerCase();
            const status = statusFilter.value;
            const priority = priorityFilter.value;
            let visibleCount = 0;

            rows.forEach(function (row) {
                const matchesSearch = !query || row.dataset.search.includes(query);
                const matchesStatus = status === 'all' || row.dataset.status === status;
                const matchesPriority = priority === 'all' || row.dataset.priority === priority;
                const isVisible = matchesSearch && matchesStatus && matchesPriority;

                row.hidden = !isVisible;
                if (isVisible) visibleCount += 1;
            });

            if (noResults) {
                noResults.hidden = rows.length === 0 || visibleCount !== 0;
            }

            if (filteredCount) {
                const total = Number(filteredCount.dataset.total || rows.length);
                filteredCount.textContent = visibleCount === total
                    ? `${total} ${messageLabel(total)}`
                    : t('{visible} of {total} messages')
                        .replace('{visible}', visibleCount).replace('{total}', total);
            }
        }

        function selectMessage(row) {
            const templateId = row.dataset.messageTemplate;
            const template = document.getElementById(templateId);

            if (!template || !detailPanel) return;

            rows.forEach(function (candidate) {
                const isSelected = candidate === row;
                candidate.classList.toggle('is-selected', isSelected);
                candidate.setAttribute('aria-selected', isSelected ? 'true' : 'false');
            });

            detailPanel.replaceChildren(template.content.cloneNode(true));

            if (window.matchMedia('(max-width: 767px)').matches) {
                const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
                detailPanel.scrollIntoView({
                    behavior: reduceMotion ? 'auto' : 'smooth',
                    block: 'start'
                });
            }
        }

        rows.forEach(function (row) {
            row.addEventListener('click', function (event) {
                if (event.target.closest('form, a')) return;
                selectMessage(row);
            });

            row.addEventListener('keydown', function (event) {
                if ((event.key === 'Enter' || event.key === ' ') && event.target === row) {
                    event.preventDefault();
                    selectMessage(row);
                }
            });
        });

        searchInput.addEventListener('input', updateFilters);
        statusFilter.addEventListener('change', updateFilters);
        priorityFilter.addEventListener('change', updateFilters);
        updateFilters();
    }

    document.addEventListener('DOMContentLoaded', function () {
        document.querySelectorAll('[data-message-center]').forEach(initMessageCenter);
    });
}());
