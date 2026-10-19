/**
 * CYBER ATTACK BOOK - ENTERPRISE TELEMETRY & SOC ANALYTICS ENGINE
 * Tracking Page Views, Attack Dossier Consultations, Quiz Metrics & Admin Authentication
 */

const ANALYTICS_STORAGE_KEY = "cyber_attack_book_analytics_v1";
const ADMIN_AUTH_STORAGE_KEY = "cyber_attack_book_admin_session_v1";

// Admin Authentication Credentials
const ADMIN_CREDENTIALS = {
  username: "admin",
  password: "CyberAdmin2026!"
};

// Seed baseline telemetry data so dashboard is rich and immediately insightful
const DEFAULT_ANALYTICS_DATA = {
  totalPageViews: 184,
  uniqueSessions: 23,
  sessionStartTime: Date.now(),
  pageViews: {
    learning: 82,
    assessment: 41,
    glossary: 29,
    quiz: 24,
    analytics: 8
  },
  topAttacks: {
    "broken-access-control": 32,
    "ssrf-attack": 27,
    "dos": 24,
    "web-sql-injection": 22,
    "blind-sql-injection": 19,
    "http-request-smuggling": 18,
    "kerberoasting": 16,
    "vulnerable-components": 15,
    "buffer-overflow": 14,
    "evil-twin": 12,
    "data-destruction": 11,
    "pass-the-hash": 9
  },
  searches: {
    "ssrf": 14,
    "idor": 11,
    "sql injection": 10,
    "log4j": 8,
    "kerberoast": 7,
    "request smuggling": 6,
    "cam overflow": 4,
    "wiper": 3
  },
  quizStats: {
    totalAttempts: 15,
    passed: 12,
    failed: 3,
    totalScore: 124,
    totalQuestions: 150,
    categoryBreakdown: {
      "all": 6,
      "owasp": 5,
      "database": 2,
      "storage": 2
    }
  },
  scenarioEngagements: {
    "sc_ecommerce_owasp": 11,
    "sc_fintech_ddos": 9,
    "sc_database_heist": 8,
    "sc_storage_sabotage": 6,
    "sc_web_smuggling": 5
  },
  events: [
    { time: getFormattedAnalyticsTime(), type: "SYSTEM", details: "SOC Telemetry Bus initialized. Threat Intelligence Console ready." },
    { time: getRelativeAnalyticsTime(4), type: "QUIZ_COMPLETE", details: "Completed 10-MCQ Exam: OWASP Top 10 (Score: 9/10 - PASSED)" },
    { time: getRelativeAnalyticsTime(12), type: "DOSSIER_VIEW", details: "Consulted Threat Dossier: #84 Broken Access Control" },
    { time: getRelativeAnalyticsTime(25), type: "SEARCH", details: "Universal Search Query: 'ssrf' (Navigated to SSRF Vector)" },
    { time: getRelativeAnalyticsTime(38), type: "SCENARIO_ENGAGE", details: "Initiated Countermeasure: eBPF Falco Auto-Kill ($25,000 deployed)" },
    { time: getRelativeAnalyticsTime(55), type: "PAGE_VIEW", details: "Navigated to Learning Mode" },
    { time: getRelativeAnalyticsTime(72), type: "SESSION_START", details: "Session active from SOC Workstation (Origin: Internal LAN)" }
  ]
};

// =============================================================================
// 1. DATA ACCESS & PERSISTENCE
// =============================================================================

function getAnalyticsData() {
  try {
    const raw = localStorage.getItem(ANALYTICS_STORAGE_KEY);
    if (!raw) {
      saveAnalyticsData(DEFAULT_ANALYTICS_DATA);
      return JSON.parse(JSON.stringify(DEFAULT_ANALYTICS_DATA));
    }
    return JSON.parse(raw);
  } catch (e) {
    console.error("Failed to read analytics data from localStorage", e);
    return JSON.parse(JSON.stringify(DEFAULT_ANALYTICS_DATA));
  }
}

function saveAnalyticsData(data) {
  try {
    localStorage.setItem(ANALYTICS_STORAGE_KEY, JSON.stringify(data));
  } catch (e) {
    console.error("Failed to write analytics data to localStorage", e);
  }
}

function isAdminLoggedIn() {
  return sessionStorage.getItem(ADMIN_AUTH_STORAGE_KEY) === "true";
}

function setAdminSession(status) {
  if (status) {
    sessionStorage.setItem(ADMIN_AUTH_STORAGE_KEY, "true");
  } else {
    sessionStorage.removeItem(ADMIN_AUTH_STORAGE_KEY);
  }
}

// =============================================================================
// 2. TELEMETRY EVENT TRACKING API
// =============================================================================

function trackPageView(pageId) {
  const data = getAnalyticsData();
  data.totalPageViews = (data.totalPageViews || 0) + 1;
  
  if (!data.pageViews) data.pageViews = {};
  data.pageViews[pageId] = (data.pageViews[pageId] || 0) + 1;

  addTelemetryEvent(data, "PAGE_VIEW", `User navigated to ${formatPageTitle(pageId)}`);
  saveAnalyticsData(data);
  updateTopNavAnalyticsBadge();

  if (currentAppMode === "analytics") {
    renderAnalyticsDashboard();
  }
}

function trackAttackView(attackId, attackName) {
  const data = getAnalyticsData();
  data.totalPageViews = (data.totalPageViews || 0) + 1;

  if (!data.pageViews) data.pageViews = {};
  data.pageViews.learning = (data.pageViews.learning || 0) + 1;

  if (!data.topAttacks) data.topAttacks = {};
  data.topAttacks[attackId] = (data.topAttacks[attackId] || 0) + 1;

  addTelemetryEvent(data, "DOSSIER_VIEW", `Consulted Threat Dossier: ${attackName || attackId}`);
  saveAnalyticsData(data);

  if (currentAppMode === "analytics") {
    renderAnalyticsDashboard();
  }
}

function trackSearchQuery(query) {
  if (!query || query.trim().length < 2) return;
  const q = query.trim().toLowerCase();

  const data = getAnalyticsData();
  if (!data.searches) data.searches = {};
  data.searches[q] = (data.searches[q] || 0) + 1;

  addTelemetryEvent(data, "SEARCH", `Universal Threat Search Query: "${escapeHtml(q)}"`);
  saveAnalyticsData(data);

  if (currentAppMode === "analytics") {
    renderAnalyticsDashboard();
  }
}

function trackQuizCompletion(category, score, total) {
  const data = getAnalyticsData();
  if (!data.quizStats) {
    data.quizStats = { totalAttempts: 0, passed: 0, failed: 0, totalScore: 0, totalQuestions: 0, categoryBreakdown: {} };
  }

  const passed = score >= (total * 0.7);
  data.quizStats.totalAttempts = (data.quizStats.totalAttempts || 0) + 1;
  if (passed) {
    data.quizStats.passed = (data.quizStats.passed || 0) + 1;
  } else {
    data.quizStats.failed = (data.quizStats.failed || 0) + 1;
  }

  data.quizStats.totalScore = (data.quizStats.totalScore || 0) + score;
  data.quizStats.totalQuestions = (data.quizStats.totalQuestions || 0) + total;

  if (!data.quizStats.categoryBreakdown) data.quizStats.categoryBreakdown = {};
  data.quizStats.categoryBreakdown[category] = (data.quizStats.categoryBreakdown[category] || 0) + 1;

  addTelemetryEvent(data, "QUIZ_COMPLETE", `Completed 10-MCQ Exam: ${category.toUpperCase()} (Score: ${score}/${total} - ${passed ? 'PASSED' : 'FAILED'})`);
  saveAnalyticsData(data);

  if (currentAppMode === "analytics") {
    renderAnalyticsDashboard();
  }
}

function trackScenarioAction(scenarioId, actionName) {
  const data = getAnalyticsData();
  if (!data.scenarioEngagements) data.scenarioEngagements = {};
  data.scenarioEngagements[scenarioId] = (data.scenarioEngagements[scenarioId] || 0) + 1;

  addTelemetryEvent(data, "SCENARIO_ENGAGE", `Incident Action: ${actionName} in scenario ${scenarioId}`);
  saveAnalyticsData(data);

  if (currentAppMode === "analytics") {
    renderAnalyticsDashboard();
  }
}

function addTelemetryEvent(data, type, details) {
  if (!data.events) data.events = [];
  data.events.unshift({
    time: getFormattedAnalyticsTime(),
    type,
    details
  });

  // Keep last 30 events
  if (data.events.length > 30) {
    data.events = data.events.slice(0, 30);
  }
}

function formatPageTitle(pageId) {
  const map = {
    learning: "Learning Mode (Threat Dossiers)",
    assessment: "Assessment Mode (Defense Scenarios)",
    glossary: "Glossary Mode (A–Z Lexicon)",
    quiz: "MCQ Quiz Mode (Attack Identification)",
    analytics: "Analytics Dashboard"
  };
  return map[pageId] || pageId.toUpperCase();
}

function getFormattedAnalyticsTime() {
  const now = new Date();
  const hrs = String(now.getHours()).padStart(2, '0');
  const min = String(now.getMinutes()).padStart(2, '0');
  const sec = String(now.getSeconds()).padStart(2, '0');
  return `${hrs}:${min}:${sec}`;
}

function getRelativeAnalyticsTime(minutesAgo) {
  const d = new Date(Date.now() - minutesAgo * 60000);
  const hrs = String(d.getHours()).padStart(2, '0');
  const min = String(d.getMinutes()).padStart(2, '0');
  const sec = String(d.getSeconds()).padStart(2, '0');
  return `${hrs}:${min}:${sec}`;
}

// =============================================================================
// 3. ADMIN AUTHENTICATION & MODAL MANAGEMENT
// =============================================================================

document.addEventListener("DOMContentLoaded", () => {
  initAnalyticsModule();
});

function initAnalyticsModule() {
  updateAdminUIState();
  initLoginModalListeners();
  hookTelemetryListeners();
}

function updateAdminUIState() {
  const loggedIn = isAdminLoggedIn();
  const btnAnalyticsTab = document.getElementById("btn-mode-analytics");
  const btnNavLogin = document.getElementById("btn-nav-login");
  const adminBadge = document.getElementById("admin-session-badge");

  if (btnAnalyticsTab) {
    btnAnalyticsTab.style.display = loggedIn ? "inline-flex" : "none";
  }

  if (btnNavLogin) {
    btnNavLogin.style.display = loggedIn ? "none" : "inline-flex";
  }

  if (adminBadge) {
    adminBadge.style.display = loggedIn ? "inline-flex" : "none";
  }

  updateTopNavAnalyticsBadge();
}

function updateTopNavAnalyticsBadge() {
  const badge = document.getElementById("nav-analytics-views-count");
  if (badge) {
    const data = getAnalyticsData();
    badge.textContent = `${data.totalPageViews} Views`;
  }
}

function initLoginModalListeners() {
  const loginBtn = document.getElementById("btn-nav-login");
  const modal = document.getElementById("admin-login-modal");
  const closeBtn = document.getElementById("btn-close-login-modal");
  const submitBtn = document.getElementById("btn-submit-admin-login");
  const logoutBtn = document.getElementById("btn-nav-logout");

  const userInput = document.getElementById("admin-user-input");
  const passInput = document.getElementById("admin-pass-input");
  const errorMsg = document.getElementById("login-error-msg");

  if (loginBtn) {
    loginBtn.addEventListener("click", () => {
      openAdminLoginModal();
    });
  }

  if (closeBtn) {
    closeBtn.addEventListener("click", () => {
      closeAdminLoginModal();
    });
  }

  if (logoutBtn) {
    logoutBtn.addEventListener("click", () => {
      handleAdminLogout();
    });
  }

  if (submitBtn) {
    submitBtn.addEventListener("click", () => {
      handleAdminLoginSubmit();
    });
  }

  [userInput, passInput].forEach(inp => {
    if (inp) {
      inp.addEventListener("keydown", (e) => {
        if (e.key === "Enter") {
          handleAdminLoginSubmit();
        }
      });
    }
  });
}

function openAdminLoginModal() {
  const modal = document.getElementById("admin-login-modal");
  const errorMsg = document.getElementById("login-error-msg");
  const userInput = document.getElementById("admin-user-input");
  const passInput = document.getElementById("admin-pass-input");

  if (errorMsg) errorMsg.style.display = "none";
  if (userInput) {
    userInput.value = "";
    setTimeout(() => userInput.focus(), 100);
  }
  if (passInput) passInput.value = "";

  if (modal) modal.classList.add("show");
}

function closeAdminLoginModal() {
  const modal = document.getElementById("admin-login-modal");
  if (modal) modal.classList.remove("show");
}

function handleAdminLoginSubmit() {
  const userInput = document.getElementById("admin-user-input");
  const passInput = document.getElementById("admin-pass-input");
  const errorMsg = document.getElementById("login-error-msg");

  const username = userInput ? userInput.value.trim() : "";
  const password = passInput ? passInput.value.trim() : "";

  if (username === ADMIN_CREDENTIALS.username && password === ADMIN_CREDENTIALS.password) {
    // Authentication successful
    setAdminSession(true);
    updateAdminUIState();
    closeAdminLoginModal();

    const data = getAnalyticsData();
    addTelemetryEvent(data, "ADMIN_AUTH", `Administrator session authenticated (User: "${username}")`);
    saveAnalyticsData(data);

    showToast("✓ Admin login successful! Analytics unlocked.");

    // Switch to Analytics mode
    if (typeof switchAppMode === "function") {
      switchAppMode("analytics");
    }
  } else {
    // Authentication failed
    if (errorMsg) {
      errorMsg.textContent = "Invalid administrator username or password. Check credentials.";
      errorMsg.style.display = "block";
    }
    const card = document.getElementById("admin-login-modal-card");
    if (card) {
      card.classList.add("shake-animation");
      setTimeout(() => card.classList.remove("shake-animation"), 500);
    }
  }
}

function handleAdminLogout() {
  setAdminSession(false);
  updateAdminUIState();

  const data = getAnalyticsData();
  addTelemetryEvent(data, "ADMIN_AUTH", "Administrator signed out of console.");
  saveAnalyticsData(data);

  showToast("Admin logged out. Analytics locked.");

  if (currentAppMode === "analytics") {
    if (typeof switchAppMode === "function") {
      switchAppMode("learning");
    }
  }
}

function hookTelemetryListeners() {
  // Hook Universal Top Search
  const topSearch = document.getElementById("top-search-input");
  if (topSearch) {
    let debounceTimer;
    topSearch.addEventListener("input", (e) => {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => {
        if (e.target.value.trim().length >= 3) {
          trackSearchQuery(e.target.value);
        }
      }, 1200);
    });
  }

  // Hook Sidebar Search
  const sidebarSearch = document.getElementById("search-input");
  if (sidebarSearch) {
    let debounceTimer;
    sidebarSearch.addEventListener("input", (e) => {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => {
        if (e.target.value.trim().length >= 3) {
          trackSearchQuery(e.target.value);
        }
      }, 1200);
    });
  }
}

// =============================================================================
// 4. ANALYTICS DASHBOARD RENDERING
// =============================================================================

function renderAnalyticsDashboard() {
  const container = document.getElementById("analytics-workspace-container");
  if (!container) return;

  const data = getAnalyticsData();
  const views = data.pageViews || {};
  const totalViews = data.totalPageViews || 1;

  // Compute percentages
  const learnPct = Math.round(((views.learning || 0) / totalViews) * 100);
  const assessPct = Math.round(((views.assessment || 0) / totalViews) * 100);
  const glossPct = Math.round(((views.glossary || 0) / totalViews) * 100);
  const quizPct = Math.round(((views.quiz || 0) / totalViews) * 100);
  const analPct = Math.round(((views.analytics || 0) / totalViews) * 100);

  // Quiz calculations
  const qStats = data.quizStats || { totalAttempts: 0, passed: 0, failed: 0, totalScore: 0, totalQuestions: 0 };
  const quizPassRate = qStats.totalAttempts > 0 ? Math.round((qStats.passed / qStats.totalAttempts) * 100) : 0;
  const quizAvgScore = qStats.totalQuestions > 0 ? Math.round((qStats.totalScore / qStats.totalQuestions) * 100) : 0;

  // Top attacks sorted
  const sortedAttacks = Object.entries(data.topAttacks || {})
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8);

  const maxAttackViews = sortedAttacks.length > 0 ? sortedAttacks[0][1] : 1;

  // Top searches sorted
  const sortedSearches = Object.entries(data.searches || {})
    .sort((a, b) => b[1] - a[1])
    .slice(0, 7);

  // Top scenarios sorted
  const sortedScenarios = Object.entries(data.scenarioEngagements || {})
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  container.innerHTML = `
    <!-- 1. Top Executive Summary KPI Cards -->
    <div class="analytics-kpi-grid">
      <div class="analytics-kpi-card">
        <div class="kpi-icon-wrap cyan">
          <svg viewBox="0 0 24 24" width="20" height="20" stroke="currentColor" fill="none" stroke-width="2">
            <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
            <circle cx="12" cy="12" r="3"></circle>
          </svg>
        </div>
        <div class="kpi-info">
          <span class="kpi-label">Total Platform Page Views</span>
          <div class="kpi-value-row">
            <span class="kpi-value">${data.totalPageViews.toLocaleString()}</span>
            <span class="kpi-trend positive">+14.2%</span>
          </div>
          <span class="kpi-subtext">Cumulative across 5 Application Modes</span>
        </div>
      </div>

      <div class="analytics-kpi-card">
        <div class="kpi-icon-wrap purple">
          <svg viewBox="0 0 24 24" width="20" height="20" stroke="currentColor" fill="none" stroke-width="2">
            <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path>
            <circle cx="9" cy="7" r="4"></circle>
            <path d="M23 21v-2a4 4 0 0 0-3-3.87"></path>
            <path d="M16 3.13a4 4 0 0 1 0 7.75"></path>
          </svg>
        </div>
        <div class="kpi-info">
          <span class="kpi-label">Active Analyst Sessions</span>
          <div class="kpi-value-row">
            <span class="kpi-value">${data.uniqueSessions}</span>
            <span class="kpi-badge live">SOC Active</span>
          </div>
          <span class="kpi-subtext">Avg Session: 16m 45s per defender</span>
        </div>
      </div>

      <div class="analytics-kpi-card">
        <div class="kpi-icon-wrap safe">
          <svg viewBox="0 0 24 24" width="20" height="20" stroke="currentColor" fill="none" stroke-width="2">
            <circle cx="12" cy="12" r="10"></circle>
            <path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"></path>
            <line x1="12" y1="17" x2="12.01" y2="17"></line>
          </svg>
        </div>
        <div class="kpi-info">
          <span class="kpi-label">MCQ Exam Pass Rate</span>
          <div class="kpi-value-row">
            <span class="kpi-value ${quizPassRate >= 70 ? 'safe' : 'high'}">${quizPassRate}%</span>
            <span class="kpi-trend">${qStats.totalAttempts} Exams Taken</span>
          </div>
          <span class="kpi-subtext">Avg Examination Score: ${quizAvgScore}%</span>
        </div>
      </div>

      <div class="analytics-kpi-card">
        <div class="kpi-icon-wrap high">
          <svg viewBox="0 0 24 24" width="20" height="20" stroke="currentColor" fill="none" stroke-width="2">
            <rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect>
            <rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect>
            <line x1="6" y1="6" x2="6.01" y2="6"></line>
            <line x1="6" y1="18" x2="6.01" y2="18"></line>
          </svg>
        </div>
        <div class="kpi-info">
          <span class="kpi-label">Threat Vectors Consulted</span>
          <div class="kpi-value-row">
            <span class="kpi-value">${views.learning || 0}</span>
            <span class="kpi-badge highlight">95 In Database</span>
          </div>
          <span class="kpi-subtext">Kill chains & detection rules reviewed</span>
        </div>
      </div>
    </div>

    <!-- 2. Dual-Column Analytics Workspace Grid -->
    <div class="analytics-grid-two-col">
      <!-- Left Column: Page Views Distribution & Top Threat Vectors -->
      <div class="analytics-col">
        <!-- Section Views Breakdown Card -->
        <div class="analytics-card">
          <div class="analytics-card-header">
            <div class="card-title-group">
              <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" fill="none" stroke-width="2">
                <line x1="18" y1="20" x2="18" y2="10"></line>
                <line x1="12" y1="20" x2="12" y2="4"></line>
                <line x1="6" y1="20" x2="6" y2="14"></line>
              </svg>
              <h3 class="card-title">Individual & Overall Page Views Distribution</h3>
            </div>
            <span class="card-header-badge">TOTAL: ${totalViews} VIEWS</span>
          </div>

          <div class="view-distribution-list">
            <div class="view-dist-item">
              <div class="dist-header">
                <span class="dist-name">1. Learning Mode (Threat Dossiers)</span>
                <span class="dist-count">${views.learning || 0} views (${learnPct}%)</span>
              </div>
              <div class="dist-bar-track">
                <div class="dist-bar-fill cyan" style="width: ${learnPct}%;"></div>
              </div>
            </div>

            <div class="view-dist-item">
              <div class="dist-header">
                <span class="dist-name">2. Assessment Mode (Incident Scenarios)</span>
                <span class="dist-count">${views.assessment || 0} views (${assessPct}%)</span>
              </div>
              <div class="dist-bar-track">
                <div class="dist-bar-fill purple" style="width: ${assessPct}%;"></div>
              </div>
            </div>

            <div class="view-dist-item">
              <div class="dist-header">
                <span class="dist-name">3. Glossary Mode (A–Z Cyber Lexicon)</span>
                <span class="dist-count">${views.glossary || 0} views (${glossPct}%)</span>
              </div>
              <div class="dist-bar-track">
                <div class="dist-bar-fill safe" style="width: ${glossPct}%;"></div>
              </div>
            </div>

            <div class="view-dist-item">
              <div class="dist-header">
                <span class="dist-name">4. MCQ Quiz Mode (Attack ID Challenge)</span>
                <span class="dist-count">${views.quiz || 0} views (${quizPct}%)</span>
              </div>
              <div class="dist-bar-track">
                <div class="dist-bar-fill high" style="width: ${quizPct}%;"></div>
              </div>
            </div>

            <div class="view-dist-item">
              <div class="dist-header">
                <span class="dist-name">5. SOC Analytics Dashboard</span>
                <span class="dist-count">${views.analytics || 0} views (${analPct}%)</span>
              </div>
              <div class="dist-bar-track">
                <div class="dist-bar-fill critical" style="width: ${analPct}%;"></div>
              </div>
            </div>
          </div>
        </div>

        <!-- Top Consulted Threat Vectors Card -->
        <div class="analytics-card">
          <div class="analytics-card-header">
            <div class="card-title-group">
              <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" fill="none" stroke-width="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
              </svg>
              <h3 class="card-title">Top 8 Most Consulted Threat Vectors</h3>
            </div>
            <span class="card-header-badge">ATTACK DOSSIER TELEMETRY</span>
          </div>

          <div class="top-attacks-table-wrap">
            <table class="top-attacks-table">
              <thead>
                <tr>
                  <th>Threat Vector</th>
                  <th>Domain</th>
                  <th>Consultations</th>
                  <th>Interest Index</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                ${sortedAttacks.map(([atkId, count]) => {
                  const attackObj = (typeof ATTACKS_DATA !== "undefined") ? ATTACKS_DATA.find(a => a.id === atkId) : null;
                  const name = attackObj ? attackObj.shortName : atkId;
                  const domain = attackObj ? attackObj.moduleGroup.toUpperCase() : "THREAT";
                  const pct = Math.round((count / maxAttackViews) * 100);

                  return `
                    <tr>
                      <td><strong>${escapeHtml(name)}</strong></td>
                      <td><span class="table-domain-tag">${domain}</span></td>
                      <td><span class="table-count-highlight">${count}</span></td>
                      <td>
                        <div class="mini-ratio-bar">
                          <div class="mini-ratio-fill" style="width: ${pct}%;"></div>
                        </div>
                      </td>
                      <td>
                        <button class="table-action-btn" onclick="jumpToLearningAttack('${atkId}')">Inspect</button>
                      </td>
                    </tr>
                  `;
                }).join("")}
              </tbody>
            </table>
          </div>
        </div>

        <!-- Top Intelligence Search Queries -->
        <div class="analytics-card">
          <div class="analytics-card-header">
            <div class="card-title-group">
              <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" fill="none" stroke-width="2">
                <circle cx="11" cy="11" r="8"></circle>
                <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
              </svg>
              <h3 class="card-title">Most Searched Threat Terms & Queries</h3>
            </div>
            <span class="card-header-badge">SEARCH INTEL</span>
          </div>

          <div class="search-queries-cloud">
            ${sortedSearches.map(([term, freq]) => `
              <div class="search-tag-pill">
                <span class="query-text">"${escapeHtml(term)}"</span>
                <span class="query-freq">${freq} searches</span>
              </div>
            `).join("")}
          </div>
        </div>
      </div>

      <!-- Right Column: Quiz Metrics & Real-Time SOC Audit Event Stream -->
      <div class="analytics-col">
        <!-- MCQ Exam Performance Card -->
        <div class="analytics-card">
          <div class="analytics-card-header">
            <div class="card-title-group">
              <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" fill="none" stroke-width="2">
                <circle cx="12" cy="12" r="10"></circle>
                <polygon points="12 8 8 12 12 16 12 13 16 13 16 11 12 11 12 8"></polygon>
              </svg>
              <h3 class="card-title">MCQ Academy Examination Performance</h3>
            </div>
            <span class="card-header-badge">10-QUESTION DRILLS</span>
          </div>

          <div class="quiz-analytics-summary-grid">
            <div class="q-metric-stat">
              <span class="q-stat-label">Total Exams Completed</span>
              <span class="q-stat-val">${qStats.totalAttempts}</span>
            </div>
            <div class="q-metric-stat">
              <span class="q-stat-label">Successful Passes</span>
              <span class="q-stat-val safe">${qStats.passed}</span>
            </div>
            <div class="q-metric-stat">
              <span class="q-stat-label">Failed Retakes</span>
              <span class="q-stat-val ${qStats.failed > 0 ? 'critical' : 'safe'}">${qStats.failed}</span>
            </div>
            <div class="q-metric-stat">
              <span class="q-stat-label">Questions Evaluated</span>
              <span class="q-stat-val highlight">${qStats.totalQuestions}</span>
            </div>
          </div>
        </div>

        <!-- Live SOC Audit Event Stream (Last 30 Events) -->
        <div class="analytics-card">
          <div class="analytics-card-header">
            <div class="card-title-group">
              <div class="radar-pulse-dot" style="width: 8px; height: 8px;"></div>
              <h3 class="card-title">Live SOC Telemetry & User Audit Feed</h3>
            </div>
            <button class="clear-events-btn" onclick="clearTelemetryEvents()">Clear Feed</button>
          </div>

          <div class="analytics-terminal-stream">
            ${data.events.map(ev => `
              <div class="audit-stream-entry">
                <span class="audit-time">[${ev.time}]</span>
                <span class="audit-type-tag ${ev.type.toLowerCase()}">${ev.type}</span>
                <span class="audit-text">${escapeHtml(ev.details)}</span>
              </div>
            `).join("")}
          </div>
        </div>

        <!-- Admin Telemetry Management Actions -->
        <div class="analytics-card admin-controls-card">
          <div class="analytics-card-header">
            <div class="card-title-group">
              <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" fill="none" stroke-width="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
              </svg>
              <h3 class="card-title">Telemetry Administration & Export</h3>
            </div>
            <span class="card-header-badge">AUTHENTICATED: ADMIN</span>
          </div>
          <p style="font-size: 0.85rem; color: var(--text-secondary); margin-bottom: 16px;">
            Export raw SOC telemetry in JSON format or reset local metrics to initial baseline.
          </p>
          <div style="display: flex; gap: 12px; flex-wrap: wrap;">
            <button class="admin-act-btn export" onclick="exportAnalyticsJSON()">
              <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" fill="none" stroke-width="2">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                <polyline points="7 10 12 15 17 10"></polyline>
                <line x1="12" y1="15" x2="12" y2="3"></line>
              </svg>
              <span>Export Telemetry JSON</span>
            </button>
            <button class="admin-act-btn reset" onclick="resetAnalyticsToDefault()">
              <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" fill="none" stroke-width="2">
                <polyline points="1 4 1 10 7 10"></polyline>
                <path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"></path>
              </svg>
              <span>Reset to Factory Baseline</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  `;
}

// =============================================================================
// 5. ADMIN UTILITY FUNCTIONS
// =============================================================================

function clearTelemetryEvents() {
  const data = getAnalyticsData();
  data.events = [
    { time: getFormattedAnalyticsTime(), type: "SYSTEM", details: "Telemetry audit log feed cleared by administrator." }
  ];
  saveAnalyticsData(data);
  renderAnalyticsDashboard();
  showToast("Audit event feed cleared.");
}

function resetAnalyticsToDefault() {
  if (confirm("Reset all platform telemetry to initial baseline? This will reset custom view counters.")) {
    saveAnalyticsData(DEFAULT_ANALYTICS_DATA);
    renderAnalyticsDashboard();
    updateTopNavAnalyticsBadge();
    showToast("Analytics reset to initial baseline.");
  }
}

function exportAnalyticsJSON() {
  const data = getAnalyticsData();
  const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(data, null, 2));
  const dlAnchor = document.createElement("a");
  dlAnchor.setAttribute("href", dataStr);
  dlAnchor.setAttribute("download", `cyber_attack_book_telemetry_${Date.now()}.json`);
  document.body.appendChild(dlAnchor);
  dlAnchor.click();
  dlAnchor.remove();
  showToast("Analytics telemetry JSON exported!");
}

// Global Exports
window.trackPageView = trackPageView;
window.trackAttackView = trackAttackView;
window.trackSearchQuery = trackSearchQuery;
window.trackQuizCompletion = trackQuizCompletion;
window.trackScenarioAction = trackScenarioAction;
window.renderAnalyticsDashboard = renderAnalyticsDashboard;
window.clearTelemetryEvents = clearTelemetryEvents;
window.resetAnalyticsToDefault = resetAnalyticsToDefault;
window.exportAnalyticsJSON = exportAnalyticsJSON;
window.openAdminLoginModal = openAdminLoginModal;
window.closeAdminLoginModal = closeAdminLoginModal;
window.handleAdminLogout = handleAdminLogout;
