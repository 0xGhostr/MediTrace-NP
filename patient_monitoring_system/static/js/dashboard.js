/**
 * Admin dashboard Chart.js — real DB data with professional tooltips.
 */
const dashboardI18n = (window.MediTraceI18n && window.MediTraceI18n.messages) || {};
const dashboardT = (key) => dashboardI18n[key] || key;
const chartTooltip = {
    enabled: true,
    backgroundColor: 'rgba(15, 23, 42, 0.96)',
    titleFont: { size: 13, weight: 'bold' },
    bodyFont: { size: 12 },
    padding: 12,
    cornerRadius: 10,
    displayColors: true,
};

const compactChartOptions = {
    responsive: true,
    maintainAspectRatio: true,
    plugins: {
        legend: { display: true, position: 'bottom', labels: { color: '#64748b', boxWidth: 10, usePointStyle: true, font: { family: 'Inter', size: 11 } } },
        tooltip: chartTooltip,
    },
};

document.addEventListener('DOMContentLoaded', function () {
    const accessCanvas = document.getElementById('accessChart');
    const alertCanvas = document.getElementById('alertChart');
    const regCanvas = document.getElementById('registrationChart');

    if (accessCanvas) {
        fetch('/api/charts/access-timeline')
            .then(r => r.json())
            .then(data => {
                new Chart(accessCanvas, {
                    type: 'bar',
                    data: {
                        labels: data.labels,
                        datasets: [{
                            label: dashboardT('Access Events'),
                            data: data.data,
                            backgroundColor: 'rgba(37, 99, 235, 0.78)',
                            borderColor: '#1d4ed8',
                            borderWidth: 1,
                        }],
                    },
                    options: {
                        ...compactChartOptions,
                        plugins: {
                            ...compactChartOptions.plugins,
                            legend: { display: false },
                            tooltip: {
                                ...chartTooltip,
                                callbacks: {
                                    label: (ctx) => ' ' + dashboardT('{count} access event(s) on {date}')
                                        .replace('{count}', ctx.parsed.y).replace('{date}', ctx.label),
                                },
                            },
                        },
                        scales: {
                            y: { beginAtZero: true, ticks: { stepSize: 1 } },
                            x: { ticks: { maxRotation: 45, minRotation: 45, font: { size: 10 } } },
                        },
                    },
                });
            })
            .catch(err => console.error('Access chart error:', err));
    }

    if (alertCanvas) {
        fetch('/api/charts/alerts-by-severity')
            .then(r => r.json())
            .then(data => {
                const total = data.data.reduce((a, b) => a + b, 0);
                new Chart(alertCanvas, {
                    type: 'pie',
                    data: {
                        labels: data.labels.map(dashboardT),
                        datasets: [{
                            data: data.data,
                            backgroundColor: ['#f59e0b', '#f97316', '#dc2626'],
                            borderWidth: 1,
                            borderColor: '#fff',
                        }],
                    },
                    options: {
                        ...compactChartOptions,
                        plugins: {
                            ...compactChartOptions.plugins,
                            tooltip: {
                                ...chartTooltip,
                                callbacks: {
                                    label: (ctx) => {
                                        const v = ctx.parsed;
                                        const pct = total ? ((v / total) * 100).toFixed(1) : 0;
                                        return ` ${ctx.label}: ${v} ${dashboardT('alert(s)')} (${pct}%)`;
                                    },
                                },
                            },
                        },
                    },
                });
            })
            .catch(err => console.error('Alert chart error:', err));
    }

    if (regCanvas) {
        fetch('/api/charts/user-registrations')
            .then(r => r.json())
            .then(data => {
                document.getElementById('monthRegTotal').textContent = data.month_total;
                new Chart(regCanvas, {
                    type: 'bar',
                    data: {
                        labels: data.labels_7d,
                        datasets: [
                            {
                                label: dashboardT('Last 7 days'),
                                data: data.data_7d,
                                backgroundColor: 'rgba(22, 163, 74, 0.76)',
                                borderColor: '#15803d',
                                borderWidth: 1,
                            },
                        ],
                    },
                    options: {
                        ...compactChartOptions,
                        plugins: {
                            ...compactChartOptions.plugins,
                            legend: { display: false },
                            tooltip: {
                                ...chartTooltip,
                                callbacks: {
                                    afterTitle: () => dashboardT('Month total registrations: {count}')
                                        .replace('{count}', data.month_total),
                                    label: (ctx) => ` ${ctx.parsed.y} ${dashboardT('new user(s) registered')}`,
                                },
                            },
                        },
                        scales: {
                            y: { beginAtZero: true, ticks: { stepSize: 1 } },
                            x: { ticks: { font: { size: 10 } } },
                        },
                    },
                });
            })
            .catch(err => console.error('Registration chart error:', err));
    }
});
