/**
 * ISEA — Shared JavaScript utilities
 * Used across all pages for common behavior.
 */

// ------------------------------------------------------------------ //
// Risk / classification color helpers
// ------------------------------------------------------------------ //

const RISK_COLORS = {
  CRITICAL:  { bg: 'bg-red-100',    text: 'text-red-700' },
  PROBABLE:  { bg: 'bg-orange-100', text: 'text-orange-700' },
  POSSIBLE:  { bg: 'bg-amber-100',  text: 'text-amber-700' },
  MINIMAL:   { bg: 'bg-green-100',  text: 'text-green-700' },
};

const CLASSIFICATION_COLORS = {
  secure_erase:     '#ef4444',
  intentional_wipe: '#f97316',
  os_clear:         '#eab308',
  natural_residual: '#22c55e',
};

function getRiskClasses(risk) {
  return RISK_COLORS[risk] || { bg: 'bg-slate-100', text: 'text-slate-600' };
}

// ------------------------------------------------------------------ //
// Score gauge SVG update
// Used on results page to animate the score arc.
// ------------------------------------------------------------------ //

function updateScoreGauge(elementId, score) {
  const el = document.getElementById(elementId);
  if (!el) return;
  const circumference = 301.6; // 2π * 48
  const offset = circumference * (1 - Math.max(0, Math.min(100, score)) / 100);
  el.style.strokeDashoffset = offset;

  // Update color
  let color;
  if (score >= 75) color = '#dc2626';
  else if (score >= 50) color = '#f97316';
  else if (score >= 25) color = '#f59e0b';
  else color = '#22c55e';
  el.setAttribute('stroke', color);
}

// ------------------------------------------------------------------ //
// Format helpers
// ------------------------------------------------------------------ //

function formatBytes(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
}

function formatNumber(n) {
  return n.toLocaleString();
}

// ------------------------------------------------------------------ //
// Auto-dismiss alerts
// ------------------------------------------------------------------ //

function autoDismiss(id, ms = 4000) {
  setTimeout(() => {
    const el = document.getElementById(id);
    if (el) {
      el.style.opacity = '0';
      el.style.transition = 'opacity 0.4s';
      setTimeout(() => el.remove(), 400);
    }
  }, ms);
}
