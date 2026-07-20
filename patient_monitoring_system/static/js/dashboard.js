/**
 * Admin dashboard Chart.js — real DB data with professional tooltips.
 */
const dashboardI18n = (window.MediTraceI18n && window.MediTraceI18n.messages) || {};
const dashboardT = (key) => dashboardI18n[key] || key;
const dashboardCharts = [];

function dashboardChartPalette() {
    const dark = document.documentElement.getAttribute('data-theme') === 'dark';
    return {
        text: dark ? '#cbd5e1' : '#64748b',
        axisText: dark ? '#cbd5e1' : '#666666',
        grid: dark ? 'rgba(148, 163, 184, 0.18)' : 'rgba(0, 0, 0, 0.1)',
        tooltipBackground: dark ? 'rgba(2, 6, 23, 0.98)' : 'rgba(15, 23, 42, 0.96)',
        tooltipText: '#f8fafc',
        pieBorder: dark ? '#111827' : '#ffffff',
    };
}

function chartTooltip() {
    const palette = dashboardChartPalette();
    return {
        enabled: true,
        backgroundColor: palette.tooltipBackground,
        titleColor: palette.tooltipText,
        bodyColor: palette.tooltipText,
        titleFont: { size: 13, weight: 'bold' },
        bodyFont: { size: 12 },
        padding: 12,
        cornerRadius: 10,
        displayColors: true,
    };
}

function compactChartOptions() {
    return {
        responsive: true,
        maintainAspectRatio: true,
        plugins: {
            legend: {
                display: true,
                position: 'bottom',
                labels: {
                    color: dashboardChartPalette().text,
                    boxWidth: 10,
                    usePointStyle: true,
                    font: { family: 'Inter', size: 11 },
                },
            },
            tooltip: chartTooltip(),
        },
    };
}

function themedScales(overrides) {
    const palette = dashboardChartPalette();
    const scales = {};
    Object.keys(overrides).forEach((axisName) => {
        const axis = overrides[axisName];
        scales[axisName] = {
            ...axis,
            ticks: { color: palette.axisText, ...(axis.ticks || {}) },
            grid: { color: palette.grid, ...(axis.grid || {}) },
            border: { color: palette.grid, ...(axis.border || {}) },
        };
    });
    return scales;
}

function alertSeverityLegendLabels(chart) {
    const dataset = chart.data.datasets[0];
    const colorAt = (color, index) => Array.isArray(color) ? color[index] : color;
    return chart.data.labels.map((label, index) => {
        const count = Number(dataset.data[index]) || 0;
        return {
            text: `${label}: ${count}`,
            fillStyle: colorAt(dataset.backgroundColor, index),
            strokeStyle: colorAt(dataset.borderColor, index),
            lineWidth: dataset.borderWidth || 0,
            hidden: !chart.getDataVisibility(index),
            pointStyle: 'circle',
            index,
        };
    });
}

function refreshDashboardChartTheme() {
    const palette = dashboardChartPalette();
    dashboardCharts.forEach((chart) => {
        const plugins = chart.options.plugins || {};
        if (plugins.legend && plugins.legend.labels) plugins.legend.labels.color = palette.text;
        if (plugins.tooltip) {
            plugins.tooltip.backgroundColor = palette.tooltipBackground;
            plugins.tooltip.titleColor = palette.tooltipText;
            plugins.tooltip.bodyColor = palette.tooltipText;
        }
        Object.values(chart.options.scales || {}).forEach((scale) => {
            if (scale.ticks) scale.ticks.color = palette.axisText;
            if (scale.grid) scale.grid.color = palette.grid;
            if (scale.border) scale.border.color = palette.grid;
        });
        if (chart.config.type === 'pie' && chart.data.datasets[0]) {
            chart.data.datasets[0].borderColor = palette.pieBorder;
        }
        chart.update('none');
    });
}

document.addEventListener('meditrace:themechange', refreshDashboardChartTheme);

document.addEventListener('DOMContentLoaded', function () {
    const accessCanvas = document.getElementById('accessChart');
    const alertCanvas = document.getElementById('alertChart');
    const regCanvas = document.getElementById('registrationChart');

    if (accessCanvas) {
        fetch('/api/charts/access-timeline')
            .then(r => r.json())
            .then(data => {
                const chart = new Chart(accessCanvas, {
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
                        ...compactChartOptions(),
                        plugins: {
                            ...compactChartOptions().plugins,
                            legend: { display: false },
                            tooltip: {
                                ...chartTooltip(),
                                callbacks: {
                                    label: (ctx) => ' ' + dashboardT('{count} access event(s) on {date}')
                                        .replace('{count}', ctx.parsed.y).replace('{date}', ctx.label),
                                },
                            },
                        },
                        scales: themedScales({
                            y: { beginAtZero: true, ticks: { stepSize: 1 } },
                            x: { ticks: { maxRotation: 45, minRotation: 45, font: { size: 10 } } },
                        }),
                    },
                });
                dashboardCharts.push(chart);
            })
            .catch(err => console.error('Access chart error:', err));
    }

    if (alertCanvas) {
        try {
            const payload = JSON.parse(document.getElementById('alertSeverityTodayData').textContent);
            const labelByKey = {
                medium: alertCanvas.dataset.labelMedium,
                high: alertCanvas.dataset.labelHigh,
                critical: alertCanvas.dataset.labelCritical,
            };
            const items = payload.items.filter(item => Object.hasOwn(labelByKey, item.key));
            const values = items.map(item => Number(item.count) || 0);
            const total = Number(payload.total) || 0;
            const noAlertDataPlugin = {
                id: 'noAlertData',
                afterDraw(chart) {
                    if (total !== 0) return;
                    const { ctx, chartArea } = chart;
                    ctx.save();
                    ctx.fillStyle = dashboardChartPalette().text;
                    ctx.font = '500 13px Inter';
                    ctx.textAlign = 'center';
                    ctx.textBaseline = 'middle';
                    ctx.fillText(
                        alertCanvas.dataset.noAlertsLabel,
                        (chartArea.left + chartArea.right) / 2,
                        (chartArea.top + chartArea.bottom) / 2,
                    );
                    ctx.restore();
                },
            };
            const chart = new Chart(alertCanvas, {
                type: 'pie',
                data: {
                    labels: items.map(item => labelByKey[item.key]),
                    datasets: [{
                        data: values,
                        backgroundColor: ['#f59e0b', '#f97316', '#dc2626'],
                        borderWidth: 1,
                        borderColor: dashboardChartPalette().pieBorder,
                    }],
                },
                plugins: [noAlertDataPlugin],
                options: {
                    ...compactChartOptions(),
                    plugins: {
                        ...compactChartOptions().plugins,
                        legend: {
                            ...compactChartOptions().plugins.legend,
                            labels: {
                                ...compactChartOptions().plugins.legend.labels,
                                generateLabels: alertSeverityLegendLabels,
                            },
                        },
                        tooltip: {
                            ...chartTooltip(),
                            callbacks: {
                                label: (ctx) => {
                                    const value = ctx.parsed;
                                    const percentage = total
                                        ? ((value / total) * 100).toFixed(1)
                                        : '0.0';
                                    const alertCount = alertCanvas.dataset.alertCountTemplate
                                        .replace('{count}', value);
                                    return ` ${ctx.label}: ${alertCount} (${percentage}%)`;
                                },
                            },
                        },
                    },
                },
            });
            dashboardCharts.push(chart);
        } catch (err) {
            console.error('Alert chart error:', err);
        }
    }

    if (regCanvas) {
        fetch('/api/charts/user-registrations')
            .then(r => r.json())
            .then(data => {
                document.getElementById('monthRegTotal').textContent = data.month_total;
                const chart = new Chart(regCanvas, {
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
                        ...compactChartOptions(),
                        plugins: {
                            ...compactChartOptions().plugins,
                            legend: { display: false },
                            tooltip: {
                                ...chartTooltip(),
                                callbacks: {
                                    afterTitle: () => dashboardT('Month total registrations: {count}')
                                        .replace('{count}', data.month_total),
                                    label: (ctx) => ` ${ctx.parsed.y} ${dashboardT('new user(s) registered')}`,
                                },
                            },
                        },
                        scales: themedScales({
                            y: { beginAtZero: true, ticks: { stepSize: 1 } },
                            x: { ticks: { font: { size: 10 } } },
                        }),
                    },
                });
                dashboardCharts.push(chart);
            })
            .catch(err => console.error('Registration chart error:', err));
    }
});
