console.log("Script loaded");

// Settings Modal Logic
// Defined globally to ensure availability
window.openSettings = async (event) => {
  if (event) event.preventDefault();
  console.log("openSettings called");

  const modal = document.getElementById('settingsModal');
  if (!modal) {
    console.error("Settings modal not found!");
    alert("Error: Settings modal not found. Please refresh.");
    return;
  }
  modal.style.display = 'block';

  // Fetch current settings
  try {
    const res = await fetch('/api/settings/alerts');
    if (res.ok) {
      const config = await res.json();
      if (document.getElementById('slackEnabled')) document.getElementById('slackEnabled').checked = config.slack_enabled;
      if (document.getElementById('slackWebhook')) document.getElementById('slackWebhook').value = config.slack_webhook || '';
      if (document.getElementById('emailEnabled')) document.getElementById('emailEnabled').checked = config.email_enabled;
      if (document.getElementById('emailRecipient')) document.getElementById('emailRecipient').value = config.email_recipient || '';
      if (document.getElementById('smtpUser')) document.getElementById('smtpUser').value = config.smtp_user || '';
      if (document.getElementById('smtpPassword')) document.getElementById('smtpPassword').value = config.smtp_password || '';
    }
  } catch (e) {
    console.error("Failed to fetch settings:", e);
  }
};

window.closeSettings = () => {
  const modal = document.getElementById('settingsModal');
  if (modal) modal.style.display = 'none';
};

window.saveSettings = async () => {
  const config = {
    slack_enabled: document.getElementById('slackEnabled') ? document.getElementById('slackEnabled').checked : false,
    slack_webhook: document.getElementById('slackWebhook') ? document.getElementById('slackWebhook').value : '',
    email_enabled: document.getElementById('emailEnabled') ? document.getElementById('emailEnabled').checked : false,
    email_recipient: document.getElementById('emailRecipient') ? document.getElementById('emailRecipient').value : '',
    smtp_user: document.getElementById('smtpUser') ? document.getElementById('smtpUser').value : '',
    smtp_password: document.getElementById('smtpPassword') ? document.getElementById('smtpPassword').value : ''
  };

  try {
    const res = await fetch('/api/settings/alerts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(config)
    });

    if (res.ok) {
      alert("Settings saved successfully!");
      closeSettings();
    } else {
      alert("Failed to save settings.");
    }
  } catch (e) {
    alert("Error saving settings: " + e);
  }
};

// Close modal when clicking outside
window.onclick = (event) => {
  const settingsModal = document.getElementById('settingsModal');
  if (settingsModal && event.target == settingsModal) {
    closeSettings();
  }
  const honeypotModal = document.getElementById('honeypotModal');
  if (honeypotModal && event.target == honeypotModal) {
    honeypotModal.style.display = "none";
  }
  const detailsModal = document.getElementById('detailsModal');
  if (detailsModal && event.target == detailsModal) {
    detailsModal.style.display = "none";
  }
};

document.addEventListener("DOMContentLoaded", function () {
  // Navigation
  document.querySelectorAll('.nav-link').forEach(link => {
    link.addEventListener('click', (e) => {
      // Only prevent default if it's an anchor link on the same page
      const href = link.getAttribute('href');
      if (href.startsWith('#') || href === '#') {
        e.preventDefault();
        document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
        e.target.classList.add('active');

        const id = e.target.id;
        if (id === 'nav-dashboard') {
          // If on scanner page, this might need different handling or be a link to /
          if (window.location.pathname === '/scanner') {
            // Already on scanner, maybe scroll top?
            window.scrollTo({ top: 0, behavior: 'smooth' });
          }
        } else if (id === 'nav-scanner') {
          if (document.getElementById('showScanFormBtn')) {
            document.getElementById('showScanFormBtn').scrollIntoView({ behavior: 'smooth' });
          }
        } else if (id === 'nav-reports') {
          if (document.querySelector('.findings-section')) {
            document.querySelector('.findings-section').scrollIntoView({ behavior: 'smooth' });
          }
        } else if (href.startsWith('#')) {
          const target = document.querySelector(href);
          if (target) target.scrollIntoView({ behavior: 'smooth' });
        }
      }
    });
  });

  // Scanner Page Logic
  const scanFormBtn = document.getElementById('showScanFormBtn');
  if (scanFormBtn) {
    const modal = document.getElementById('scanModal');
    const closeModal = document.querySelector('.close-modal');

    // Show scanner modal
    scanFormBtn.onclick = () => {
      modal.style.display = 'block';
    };

    // Close modal
    if (closeModal) {
      closeModal.onclick = () => {
        modal.style.display = 'none';
      }
    }

    // Close modal when clicking outside
    window.onclick = (event) => {
      if (event.target == modal) {
        modal.style.display = 'none';
      }
    }

    // Demo Scan
    const demoBtn = document.getElementById('demoScanBtn');
    if (demoBtn) {
      demoBtn.onclick = async () => {
        document.getElementById('findingsList').innerHTML = "<div class='finding-item'><span>Running Demo Scan...</span></div>";
        try {
          const res = await fetch('/demo-scan', { method: 'POST' });
          if (!res.ok) throw new Error(res.statusText);
          const data = await res.json();
          renderDashboardStats(data);
          window.currentFindings = data.findings || []; // Store for filtering
          renderFindings(window.currentFindings);
          document.getElementById('lastUpdated').textContent = "Last Updated: just now (Demo)";

          // Scroll to findings
          document.querySelector('.findings-section').scrollIntoView({ behavior: 'smooth' });
        } catch (err) {
          document.getElementById('findingsList').innerHTML = "<div class='finding-item critical'>Error running demo scan: " + err + "</div>";
        }
      };
    }

    // Scanner form AJAX
    const scanForm = document.getElementById('awsScanForm');
    if (scanForm) {
      scanForm.addEventListener('submit', async function (e) {
        e.preventDefault();
        const accessKeyId = document.getElementById('accessKeyId').value;
        const secretAccessKey = document.getElementById('secretAccessKey').value;
        document.getElementById('findingsList').innerHTML = "<div class='finding-item'><span>Scanning…</span></div>";
        modal.style.display = 'none';
        try {
          const res = await fetch('/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ accessKeyId, secretAccessKey })
          });
          if (!res.ok) {
            document.getElementById('findingsList').innerHTML = "<div class='finding-item critical'>Error: " + res.statusText + "</div>";
            return;
          }
          const data = await res.json();
          renderDashboardStats(data);
          window.currentFindings = data.findings || [];
          renderFindings(window.currentFindings);
          document.getElementById('lastUpdated').textContent = "Last Updated: just now";
        } catch (err) {
          document.getElementById('findingsList').innerHTML = "<div class='finding-item critical'>Error running scan: " + err + "</div>";
        }
      });
    }

    // View Critical Issues
    const criticalBtn = document.getElementById('viewCriticalBtn');
    if (criticalBtn) {
      criticalBtn.onclick = () => {
        if (!window.currentFindings) return;
        const critical = window.currentFindings.filter(f => f.severity === 'CRITICAL');
        renderFindings(critical);
        document.querySelector('.findings-section').scrollIntoView({ behavior: 'smooth' });
      };
    }

    // Export Report
    const exportBtn = document.getElementById('exportReportBtn');
    if (exportBtn) {
      exportBtn.onclick = () => {
        window.location.href = '/download-report';
      };
    }

    // Clear Findings
    const clearBtn = document.getElementById('clearFindingsBtn');
    if (clearBtn) {
      clearBtn.onclick = () => {
        window.currentFindings = [];
        renderFindings([]);
        document.getElementById('lastUpdated').textContent = "Last Updated: -";
        // Reset stats
        document.getElementById('lastScanTime').textContent = '-';
        document.getElementById('criticalIssues').textContent = '-';
        document.getElementById('resourcesScanned').textContent = '-';
        document.getElementById('securityScore').textContent = '-';
      };
    }
  }

  // Honeypot Page Logic
  const deployHoneypotBtn = document.getElementById('deployHoneypotBtn');
  if (deployHoneypotBtn) {
    const modal = document.getElementById('honeypotModal');
    const closeModal = document.querySelector('.close-modal');
    const form = document.getElementById('honeypotForm');

    // Details Modal
    const detailsModal = document.getElementById('detailsModal');
    const closeDetails = document.getElementById('closeDetails');
    const terminateBtn = document.getElementById('terminateHoneypotBtn');
    let selectedHoneypotId = null;

    // State
    window.activeHoneypots = [];

    // Fetch Active Honeypots
    async function fetchHoneypots() {
      try {
        const res = await fetch('/api/honeypots');
        if (res.ok) {
          window.activeHoneypots = await res.json();
          renderHoneypots();
        }
      } catch (err) {
        console.error("Failed to fetch honeypots:", err);
      }
    }

    // Initial Fetch
    fetchHoneypots();

    // Render Honeypots
    function renderHoneypots() {
      const list = document.getElementById('honeypotList');
      const count = document.getElementById('activeCount');

      count.textContent = `${window.activeHoneypots.length} Active`;

      if (window.activeHoneypots.length === 0) {
        list.innerHTML = '<div class="empty-state">No honeypots deployed.</div>';
        return;
      }

      list.innerHTML = window.activeHoneypots.map(hp => `
        <div class="honeypot-card" onclick="openHoneypotDetails('${hp.id}')">
          <div class="hp-info">
            <h4>${hp.name || hp.type.toUpperCase()}</h4>
            <div class="hp-meta">${hp.region} • ${hp.ip || 'Pending'}</div>
          </div>
          <div class="hp-status" style="background: ${hp.status === 'Active' ? '#00ff88' : '#ffaa00'}; box-shadow: 0 0 10px ${hp.status === 'Active' ? '#00ff88' : '#ffaa00'}"></div>
        </div>
      `).join('');
    }

    // Open Details
    window.openHoneypotDetails = (id) => {
      const hp = window.activeHoneypots.find(h => h.id === id);
      if (!hp) return;

      selectedHoneypotId = id;
      const content = document.getElementById('honeypotDetailsContent');
      content.innerHTML = `
        <h3>${hp.name || hp.type.toUpperCase()}</h3>
        <p><strong>Type:</strong> ${hp.type}</p>
        <p><strong>Region:</strong> ${hp.region}</p>
        <p><strong>Resource ID:</strong> ${hp.resource_id}</p>
        <p><strong>IP Address:</strong> ${hp.ip || 'Provisioning...'}</p>
        <p><strong>Status:</strong> <span style="color:${hp.status === 'Active' ? '#00ff88' : '#ffaa00'}">${hp.status}</span></p>
        <p><strong>Deployed:</strong> ${new Date(hp.deployedAt).toLocaleString()}</p>
      `;

      // Ask for credentials again for termination (security measure)
      content.innerHTML += `
        <div style="margin-top: 15px; border-top: 1px solid #1e3a5f; padding-top: 15px;">
          <button class="btn btn-primary" id="simulateAttackBtn" style="margin-bottom: 15px; width: 100%; background: #ff0055; border-color: #ff0055;">⚡ Simulate Attack</button>
          
          <label style="display:block; margin-bottom:5px; color:#87a8c8; font-size:0.9rem;">Confirm Credentials to Terminate:</label>
          <input type="text" id="termAccessKey" placeholder="Access Key ID" class="form-input" style="margin-bottom:5px;">
          <input type="password" id="termSecretKey" placeholder="Secret Access Key" class="form-input">
        </div>
      `;

      detailsModal.style.display = 'block';

      // Show Honeytoken Link (for S3)
      // Note: 'hp' is already defined at the top of openHoneypotDetails
      if (hp.type === 's3') {
        const htLink = `https://${hp.resource_id}.s3.amazonaws.com/confidential-dashboard.html`;
        content.innerHTML += `
            <div style="margin-top: 15px; padding: 10px; background: #2a1a1a; border: 1px solid #ff4444; border-radius: 5px;">
                <strong style="color: #ff4444;">🔥 Honeytoken (Instant Alert):</strong><br>
                <a href="${htLink}" target="_blank" style="color: #ff8888; word-break: break-all;">${htLink}</a>
                <div style="font-size: 0.8rem; color: #aaa; margin-top: 5px;">Clicking this link will trigger an INSTANT alert in the feed.</div>
            </div>
          `;
      }

      // Simulate Attack Handler
      const simBtn = document.getElementById('simulateAttackBtn');
      if (simBtn) {
        simBtn.onclick = async () => {
          simBtn.textContent = "Simulating Attack...";
          simBtn.disabled = true;

          try {
            const res = await fetch('/api/honeypots/simulate-attack', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ id: selectedHoneypotId })
            });

            const result = await res.json();

            if (result.success) {
              addLog('ALERT', result.message, 'attack');
              alert(`Attack Simulated!\nType: ${result.alert_type}\nSeverity: ${result.severity}`);
            } else {
              addLog('ERROR', `Simulation failed: ${result.error}`, 'system');
              alert("Simulation Failed: " + result.error);
            }
          } catch (err) {
            alert("Error: " + err);
          } finally {
            simBtn.textContent = "⚡ Simulate Attack";
            simBtn.disabled = false;
          }
        };
      }
    };

    // Poll for Alerts (Simple implementation)
    setInterval(async () => {
      try {
        const res = await fetch('/api/alerts');
        if (res.ok) {
          const alerts = await res.json();
          // console.log("Polling alerts:", alerts); // Debugging

          alerts.forEach(alert => {
            // Simple dedup check (in-memory)
            if (!window.shownAlerts) window.shownAlerts = new Set();
            if (!window.shownAlerts.has(alert.id)) {
              console.log("New alert found:", alert);
              // Include the description which contains the IP
              addLog('ALERT', `Honeytoken Triggered: ${alert.resource_id}. ${alert.description}`, 'attack');
              window.shownAlerts.add(alert.id);
            }
          });
        }
      } catch (e) {
        console.error("Polling error:", e);
      }
    }, 2000);

    // Terminate Honeypot
    if (terminateBtn) {
      terminateBtn.onclick = async () => {
        if (!selectedHoneypotId) return;

        const accessKeyId = document.getElementById('termAccessKey').value;
        const secretAccessKey = document.getElementById('termSecretKey').value;

        if (!accessKeyId || !secretAccessKey) {
          alert("Please provide credentials to terminate resources.");
          return;
        }

        terminateBtn.textContent = "Terminating...";
        terminateBtn.disabled = true;

        try {
          const res = await fetch('/api/honeypots/terminate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id: selectedHoneypotId, accessKeyId, secretAccessKey })
          });

          if (res.ok) {
            addLog('SYSTEM', `Honeypot ${selectedHoneypotId} terminated successfully.`, 'system');
            await fetchHoneypots();
            detailsModal.style.display = 'none';
          } else {
            const err = await res.json();
            alert("Termination failed: " + err.error);
          }
        } catch (err) {
          alert("Error: " + err);
        } finally {
          terminateBtn.textContent = "Terminate Honeypot";
          terminateBtn.disabled = false;
        }
      };
    }

    // Add Log Helper
    function addLog(source, message, type = 'system') {
      const logs = document.getElementById('honeypotLogs');
      const entry = document.createElement('div');
      entry.className = `log-entry ${type}`;
      entry.innerHTML = `[${new Date().toLocaleTimeString()}] <strong>${source}:</strong> ${message}`;
      logs.prepend(entry);
    }

    // Deploy Modal Handlers
    deployHoneypotBtn.onclick = () => { modal.style.display = 'block'; };
    if (closeModal) closeModal.onclick = () => { modal.style.display = 'none'; };
    if (closeDetails) closeDetails.onclick = () => { detailsModal.style.display = 'none'; };

    window.onclick = (event) => {
      if (event.target == modal) modal.style.display = 'none';
      if (event.target == detailsModal) detailsModal.style.display = 'none';
    }

    if (form) {
      form.onsubmit = async (e) => {
        e.preventDefault();
        const type = document.getElementById('honeypotType').value;
        const region = document.getElementById('region').value;
        const name = document.getElementById('honeypotName').value;
        const accessKeyId = document.getElementById('hpAccessKeyId').value;
        const secretAccessKey = document.getElementById('hpSecretAccessKey').value;

        const submitBtn = form.querySelector('button[type="submit"]');
        submitBtn.textContent = "Deploying (this may take a minute)...";
        submitBtn.disabled = true;

        try {
          const res = await fetch('/api/honeypots/deploy', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ type, region, name, accessKeyId, secretAccessKey })
          });

          if (res.ok) {
            const newHoneypot = await res.json();
            addLog('SYSTEM', `Deployed new ${type} honeypot: ${newHoneypot.resource_id}`, 'system');
            await fetchHoneypots();
            modal.style.display = 'none';
            form.reset();
          } else {
            const err = await res.json();
            addLog('ERROR', `Deployment failed: ${err.error}`, 'attack');
            alert("Deployment failed: " + err.error);
          }
        } catch (err) {
          addLog('ERROR', `Deployment error: ${err}`, 'attack');
          alert("Error: " + err);
        } finally {
          submitBtn.textContent = "Deploy Decoy";
          submitBtn.disabled = false;
        }
      };
    }
  }

  // View All Findings
  window.viewAllFindings = function () {
    if (!window.currentFindings) return;
    renderFindings(window.currentFindings);
  };

  function renderDashboardStats(data) {
    const lastScanTime = document.getElementById('lastScanTime');
    if (lastScanTime) lastScanTime.textContent = data.scan_metadata ? new Date(data.scan_metadata.timestamp).toLocaleString() : '-';

    const criticalIssues = document.getElementById('criticalIssues');
    if (criticalIssues) criticalIssues.textContent = (data.findings || []).filter(f => f.severity === 'CRITICAL').length;

    const resourcesScanned = document.getElementById('resourcesScanned');
    if (resourcesScanned) resourcesScanned.textContent = data.scan_metadata ? data.scan_metadata.total_findings : '-';

    const securityScore = document.getElementById('securityScore');
    if (securityScore) {
      let score = 100;
      const findings = data.findings || [];

      findings.forEach(f => {
        switch (f.severity) {
          case 'CRITICAL': score -= 20; break;
          case 'HIGH': score -= 10; break;
          case 'MEDIUM': score -= 5; break;
          case 'LOW': score -= 1; break;
        }
      });

      if (score < 0) score = 0;
      securityScore.textContent = `${score}%`;

      // Color coding
      securityScore.className = 'status-value'; // reset
      if (score >= 80) securityScore.style.color = '#00ff9d'; // Green
      else if (score >= 50) securityScore.style.color = '#ffaa00'; // Orange
      else securityScore.style.color = '#ff0055'; // Red
    }
  }

  function renderFindings(findings) {
    // Sort by severity: CRITICAL > HIGH > MEDIUM > LOW
    const priority = { CRITICAL: 1, HIGH: 2, MEDIUM: 3, LOW: 4 };
    findings.sort((a, b) => (priority[a.severity] || 99) - (priority[b.severity] || 99));
    const findingsEl = document.getElementById('findingsList');
    if (!findingsEl) return;

    if (findings.length === 0) {
      findingsEl.innerHTML = "<div class='finding-item'>No findings to display.</div>";
      return;
    }

    findingsEl.innerHTML = findings.map((f, index) => `
      <div class="finding-item ${f.severity && f.severity.toLowerCase()}">
        <div class="finding-header" onclick="toggleFinding(${index})">
          <div class="finding-title-group">
            <span class="severity-badge ${f.severity && f.severity.toLowerCase()}">${f.severity}</span>
            <span class="finding-title">${f.title}</span>
          </div>
          <div class="finding-meta-group">
            <span class="service-tag">${f.service || 'AWS'}</span>
            <span class="expand-icon">▼</span>
          </div>
        </div>
        <div id="finding-body-${index}" class="finding-body" style="display: none;">
          <div class="finding-details-grid">
            <div class="detail-row">
              <span class="label">Resource ID:</span>
              <span class="value mono">${f.resource_id || 'N/A'}</span>
            </div>
            <div class="detail-row">
              <span class="label">Resource Type:</span>
              <span class="value">${f.resource_type || 'N/A'}</span>
            </div>
            <div class="detail-row">
              <span class="label">Region:</span>
              <span class="value">${f.region || 'Global'}</span>
            </div>
             <div class="detail-row">
              <span class="label">Account:</span>
              <span class="value">${f.account_id || 'N/A'}</span>
            </div>
          </div>
          
          <div class="finding-description">
            <strong>Description:</strong> ${f.description || 'No description available.'}
          </div>
          <div class="finding-meta">
             <span class="timestamp">Detected: ${f.timestamp || 'Just now'}</span>
          </div>
          ${f.recommendation ?
        `<div class="recommendation">
            <span class="recommendation-text"><strong>Recommendation:</strong> ${f.recommendation}</span>
            ${(f.id && (f.id.includes('s3-public') || f.id.includes('s3-versioning') || f.id.includes('ec2-sg-open') || f.id.includes('iam-no-mfa'))) ?
          `<button class="btn btn-primary" style="margin-left: 10px; padding: 4px 10px; font-size: 0.8rem; background: #0cecff; color: #000;" onclick="remediateFinding('${f.id}', '${f.resource_id}', '${f.id.includes('s3-public') ? 'S3_PUBLIC_ACCESS' :
            f.id.includes('s3-versioning') ? 'S3_VERSIONING' :
              f.id.includes('ec2-sg-open') ? 'EC2_OPEN_SECURITY_GROUP' :
                'IAM_NO_MFA'
          }')">✨ Auto-Fix</button>`
          : ''}
          </div>` : ''
      }
      </div>
    `).join('');
  }
});

// Toggle Finding Accordion
window.toggleFinding = (index) => {
  const body = document.getElementById(`finding-body-${index}`);
  const icon = body.parentElement.querySelector('.expand-icon');

  if (body.style.display === 'none') {
    body.style.display = 'block';
    icon.style.transform = 'rotate(180deg)';
  } else {
    body.style.display = 'none';
    icon.style.transform = 'rotate(0deg)';
  }
};

// Chat Widget Logic
window.toggleChat = () => {
  const chatWindow = document.getElementById('chat-window');
  if (chatWindow.style.display === 'flex') {
    chatWindow.style.display = 'none';
  } else {
    chatWindow.style.display = 'flex';
    document.getElementById('chat-input').focus();
  }
};

window.handleChatInput = (event) => {
  if (event.key === 'Enter') {
    sendMessage();
  }
};

window.sendMessage = async () => {
  const input = document.getElementById('chat-input');
  const message = input.value.trim();
  if (!message) return;

  // Add user message
  appendMessage('user', message);
  input.value = '';

  // Show typing indicator (optional, skipping for simplicity)

  try {
    const res = await fetch('/api/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message })
    });
    const data = await res.json();
    appendMessage('bot', data.response);
  } catch (err) {
    appendMessage('bot', "Sorry, I'm having trouble connecting to the server.");
  }
};

function appendMessage(sender, text) {
  const messagesDiv = document.getElementById('chat-messages');
  const msgDiv = document.createElement('div');
  msgDiv.className = `message ${sender}`;
  msgDiv.innerText = text;
  messagesDiv.appendChild(msgDiv);
  messagesDiv.scrollTop = messagesDiv.scrollHeight;
}

// Remediation Logic
window.remediateFinding = async (findingId, resourceId, issueType) => {
  if (!confirm(`Are you sure you want to auto-fix ${issueType} on ${resourceId}?`)) return;

  // We need credentials. For now, prompt the user.
  // In a real app, we might cache them or use a session.
  const accessKeyId = prompt("Enter AWS Access Key ID:");
  if (!accessKeyId) return;
  const secretAccessKey = prompt("Enter AWS Secret Access Key:");
  if (!secretAccessKey) return;

  try {
    const res = await fetch('/api/remediate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        accessKeyId,
        secretAccessKey,
        finding_id: findingId,
        resource_id: resourceId,
        issue_type: issueType
      })
    });

    const result = await res.json();

    if (result.success) {
      alert(`✅ Success!\n\nAI Explanation:\n${result.explanation.what}\n\n${result.message}`);
      // Ideally refresh scan results here
    } else {
      alert(`❌ Failed: ${result.message}`);
    }
  } catch (e) {
    alert("Error: " + e);
  }
};

