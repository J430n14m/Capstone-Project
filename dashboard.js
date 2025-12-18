// dashboard.js

// Connect to Socket.IO
const socket = io();

// ---- Live Sensor Values ----
socket.on('sensor_update', (data) => {
  console.log('Sensor update:', data);

  const tempEl = document.getElementById('temp-value');
  const humEl = document.getElementById('humidity-value');
  const lightEl = document.getElementById('light-value');

  if (tempEl) {
    tempEl.innerText = data.temperature != null
      ? `${data.temperature.toFixed(2)} °C`
      : '--';
  }

  if (humEl) {
    humEl.innerText = data.humidity != null
      ? `${data.humidity.toFixed(2)} %`
      : '--';
  }

  if (lightEl) {
    lightEl.innerText = data.light != null
      ? data.light.toFixed(0)
      : '--';
  }
});

// ---- System Stats + Risk Score ----
socket.on('stats_update', (stats) => {
  console.log('Stats update:', stats);

  const totalPacketsEl = document.getElementById('total-packets');
  const totalThreatsEl = document.getElementById('total-threats');
  const avgTimeEl = document.getElementById('avg-time');
  const riskScoreEl = document.getElementById('risk-score');

  if (totalPacketsEl) {
    totalPacketsEl.textContent = stats.total_packets_analyzed ?? 0;
  }
  if (totalThreatsEl) {
    totalThreatsEl.textContent = stats.total_threats_blocked ?? 0;
  }
  if (avgTimeEl) {
    const v = stats.avg_detection_time_ms ?? 0;
    avgTimeEl.textContent = v.toFixed(2) + ' ms';
  }
  if (riskScoreEl) {
    const r = stats.risk_score ?? 0;
    riskScoreEl.textContent = r.toFixed(2);
  }
});

// ---- Alerts (Recent Alerts table + Alert Log) ----

// Helper to show/hide "no alerts" placeholder
function updateNoAlertsPlaceholder() {
  const tbody = document.getElementById('alerts-table-body');
  const placeholder = document.getElementById('no-alerts-placeholder');

  if (!tbody || !placeholder) return;

  const hasRows = tbody.rows.length > 0;
  placeholder.style.display = hasRows ? 'none' : 'block';
}

socket.on('alert_update', (alert) => {
  console.log('Alert:', alert);

  // Recent Alerts table
  const tbody = document.getElementById('alerts-table-body');
  if (tbody) {
    const row = tbody.insertRow(0); // newest at top
    row.innerHTML = `
      <td>${alert.timestamp}</td>
      <td>${(alert.type || '').toUpperCase()}</td>
      <td class="severity-${alert.severity || ''}">
        ${(alert.severity || '').toUpperCase()}
      </td>
      <td>${alert.message || ''}</td>
    `;
  }

  // Alert Log list
  const logList = document.getElementById('alert-log-list');
  if (logList) {
    const li = document.createElement('li');
    li.textContent = `[${(alert.severity || '').toUpperCase()}] ${alert.type}: ${alert.message}`;
    logList.prepend(li);
  }

  // Update "no alerts" message
  updateNoAlertsPlaceholder();
});

// When first connected, show "no alerts" message until something arrives
socket.on('connect', () => {
  console.log('Connected to Flask-SocketIO');
  updateNoAlertsPlaceholder();
});
