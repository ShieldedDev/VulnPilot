// Scan page — live progress and AJAX polling

var currentScanId = null;
var pollInterval = null;
var pollCount = 0;
var renderedProgressCount = 0;

document.addEventListener('DOMContentLoaded', function () {

    var launchBtn = document.getElementById('launchBtn');
    if (launchBtn) {
        launchBtn.addEventListener('click', handleLaunch);
    }

    var viewResultsBtn = document.getElementById('viewResultsBtn');
    if (viewResultsBtn) {
        viewResultsBtn.addEventListener('click', function () {
            if (currentScanId) {
                window.location.href = '/scan/' + currentScanId + '/results';
            }
        });
    }
});

function handleLaunch() {
    var target = document.getElementById('target').value.trim();
    var scanType = document.getElementById('scan_type').value;
    var wordlist = document.getElementById('wordlist').value;
    var consent = document.getElementById('consent').checked;

    if (!target) {
        showError('Please enter a target URL or IP address.');
        return;
    }

    if (!consent) {
        showError('You must confirm you have legal authorization to scan this target.');
        return;
    }

    startScan(target, scanType, wordlist);
}
function startScan(target, scanType, wordlist) {
    var launchBtn = document.getElementById('launchBtn');
    launchBtn.disabled = true;
    launchBtn.textContent = 'Starting assessment...';
    renderedProgressCount = 0;
    document.getElementById('logOutput').replaceChildren();

    fetch('/scan/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: target, scan_type: scanType, wordlist: wordlist })
    })
    .then(function (resp) { return resp.json(); })
    .then(function (data) {
        if (data.error) {
            showError(data.error);
            launchBtn.disabled = false;
            launchBtn.textContent = 'Launch Scan';
            return;
        }
        currentScanId = data.scan_id;
        showProgressPanel();
        beginPolling(currentScanId);
    })
    .catch(function (err) {
        showError('Failed to start scan. Please try again.');
        launchBtn.disabled = false;
        launchBtn.textContent = 'Launch Scan';
    });
}

function showProgressPanel() {
    var panel = document.getElementById('progressPanel');
    panel.style.display = 'block';
    panel.classList.add('is-visible', 'scan-progress-active');
    panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function beginPolling(scanId) {
    pollCount = 0;
    pollInterval = setInterval(function () {
        pollScanStatus(scanId);
        pollCount++;
        if (pollCount > 600) {
            clearInterval(pollInterval);
            updateStatus('Scan timed out. Check scan history.', false);
        }
    }, 2000);
}

function pollScanStatus(scanId) {
    fetch('/scan/' + scanId + '/status')
    .then(function (resp) { return resp.json(); })
    .then(function (data) {
        updateProgress(data);
        if (data.status === 'completed') {
            clearInterval(pollInterval);
            onScanComplete(data);
        }
    })
    .catch(function () {
        // silently retry
    });
}

var phaseMap = {
    'init':     { id: null, pct: 5 },
    'recon':    { id: 'phase-recon', pct: 25 },
    'enum':     { id: 'phase-enum', pct: 50 },
    'vuln':     { id: 'phase-vuln', pct: 75 },
    'analysis': { id: 'phase-analysis', pct: 85 },
    'report':   { id: 'phase-report', pct: 95 },
    'complete': { id: null, pct: 100 }
};

var lastPhase = null;

function updateProgress(data) {
    var progress = data.progress || [];
    var logOutput = document.getElementById('logOutput');
    var lastProgress = progress[progress.length - 1];

    if (lastProgress) {
        var phase = lastProgress.phase || 'init';
        var phaseInfo = phaseMap[phase] || { id: null, pct: 10 };

        // Update progress bar
        var pct = phaseInfo.pct;
        if (progress.length > 1) {
            var basePct = phaseInfo.pct - 5;
            pct = Math.min(phaseInfo.pct, basePct + (progress.length % 5));
        }
        setProgress(pct);

        // Update phase indicators
        if (phase !== lastPhase) {
            updatePhaseIndicators(phase);
            lastPhase = phase;
        }

        // Update status badge
        var statusText = lastProgress.message || 'Running...';
        document.getElementById('statusBadge').textContent = statusText;
    }

    if (progress.length > renderedProgressCount) {
        progress.slice(renderedProgressCount).forEach(function (entry) {
            var line = document.createElement('span');
            line.className = 'log-line log-line--' + (entry.phase || 'init');
            if (entry.time) {
                var timestamp = document.createElement('span');
                timestamp.className = 'log-timestamp';
                timestamp.textContent = '[' + entry.time + '] ';
                line.appendChild(timestamp);
            }
            line.appendChild(document.createTextNode('> ' + (entry.message || '')));
            logOutput.appendChild(line);
        });
        renderedProgressCount = progress.length;
        logOutput.scrollTop = logOutput.scrollHeight;
    }
}

function setProgress(pct) {
    document.getElementById('progressFill').style.width = pct + '%';
    document.getElementById('progressPercent').textContent = pct + '%';
    document.getElementById('progressTrack').setAttribute('aria-valuenow', pct);
}

function updatePhaseIndicators(currentPhase) {
    var order = ['recon', 'enum', 'vuln', 'analysis', 'report'];
    var currentIdx = order.indexOf(currentPhase);

    order.forEach(function (phase, idx) {
        var el = document.getElementById('phase-' + phase);
        if (!el) return;

        if (idx < currentIdx) {
            el.className = 'phase-indicator done';
        } else if (idx === currentIdx) {
            el.className = 'phase-indicator active';
        } else {
            el.className = 'phase-indicator';
        }
    });
}

function onScanComplete(data) {
    setProgress(100);
    updatePhaseIndicators('complete');

    // Mark all phases done
    var phases = ['recon', 'enum', 'vuln', 'analysis', 'report'];
    phases.forEach(function (p) {
        var el = document.getElementById('phase-' + p);
        if (el) el.className = 'phase-indicator done';
    });

    var badge = document.getElementById('statusBadge');
    badge.textContent = 'Completed';
    badge.classList.add('scan-status-complete');
    document.getElementById('progressPanel').classList.remove('scan-progress-active');

    document.getElementById('scanCompleteActions').style.display = 'block';

    // Add completion log line
    var logOutput = document.getElementById('logOutput');
    var completeLine = document.createElement('span');
    completeLine.className = 'log-line log-line--complete';
    completeLine.textContent = 'SCAN COMPLETED — Reports ready for download.';
    logOutput.appendChild(completeLine);
    logOutput.scrollTop = logOutput.scrollHeight;
}

function updateStatus(message, running) {
    var badge = document.getElementById('statusBadge');
    if (badge) badge.textContent = message;
}

function showError(message) {
    var existing = document.querySelector('.alert');
    if (existing) existing.remove();

    var alert = document.createElement('div');
    alert.className = 'alert alert-error';
    alert.textContent = message;

    var configPanel = document.getElementById('configPanel');
    configPanel.insertBefore(alert, configPanel.querySelector('.panel-header').nextSibling);

    setTimeout(function () {
        alert.style.opacity = '0';
        alert.style.transition = 'opacity 0.5s';
        setTimeout(function () { alert.remove(); }, 500);
    }, 4000);
}
