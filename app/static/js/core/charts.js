/* ==========================================================================
   charts.js — Chart.js defaults + factory so every chart in the app
   shares one visual language (grid, tooltip, font, palette).
   ========================================================================== */

   (function () {
    if (typeof Chart === "undefined") return;
  
    const styles = getComputedStyle(document.documentElement);
    const cvar = (name) => styles.getPropertyValue(name).trim();
  
    Chart.defaults.font.family = "'Inter', sans-serif";
    Chart.defaults.font.size = 12;
    Chart.defaults.color = cvar('--text-muted') || '#94A3B8';
    Chart.defaults.borderColor = cvar('--border-subtle') || '#26313F';
    Chart.defaults.plugins.legend.labels.usePointStyle = true;
    Chart.defaults.plugins.legend.labels.boxWidth = 8;
    Chart.defaults.plugins.legend.labels.boxHeight = 8;
    Chart.defaults.plugins.tooltip.backgroundColor = cvar('--bg-elevated') || '#0F172A';
    Chart.defaults.plugins.tooltip.titleColor = cvar('--text') || '#F8FAFC';
    Chart.defaults.plugins.tooltip.bodyColor = cvar('--text-muted') || '#94A3B8';
    Chart.defaults.plugins.tooltip.borderColor = cvar('--border') || '#374151';
    Chart.defaults.plugins.tooltip.borderWidth = 1;
    Chart.defaults.plugins.tooltip.padding = 10;
    Chart.defaults.plugins.tooltip.cornerRadius = 8;
    Chart.defaults.plugins.tooltip.displayColors = true;
    Chart.defaults.plugins.tooltip.boxPadding = 4;
  
    // Palettes: severity (risk charts) vs activity (neutral volume/traffic charts)
    window.XDR_PALETTE = {
      severity: {
        critical: cvar('--sev-critical') || '#EF4444',
        high: cvar('--sev-high') || '#F97316',
        medium: cvar('--sev-medium') || '#F59E0B',
        low: cvar('--sev-low') || '#22C55E',
        info: cvar('--sev-info') || '#06B6D4',
      },
      activity: [
        cvar('--chart-blue') || '#3B82F6',
        cvar('--chart-cyan') || '#22D3EE',
        cvar('--chart-violet') || '#8B5CF6',
        cvar('--chart-slate') || '#64748B',
      ],
    };
  
    function baseGrid() {
      return { color: cvar('--border-subtle') || '#26313F', drawTicks: false };
    }
  
    window.XDR_CHART_DEFAULTS = {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: 'index', intersect: false },
      scales: {
        x: { grid: { display: false }, ticks: { color: cvar('--text-muted') } },
        y: { grid: baseGrid(), ticks: { color: cvar('--text-muted') }, beginAtZero: true },
      },
      plugins: { legend: { display: false } },
    };
  
    // Helper to create a soft area-fill gradient for line/area charts
    window.xdrGradient = function (ctx, hexColor, alpha = 0.25) {
      const g = ctx.createLinearGradient(0, 0, 0, 220);
      g.addColorStop(0, hexColor + Math.round(alpha * 255).toString(16).padStart(2, '0'));
      g.addColorStop(1, hexColor + '00');
      return g;
    };
  })();
  