# PowerShell script to inject enterprise portfolio calculations and UI into assessment.js
$assessmentJsPath = 'C:/Users/SubbulakshmiT/.gemini/antigravity-ide/scratch/cyber-attack-book/assessment.js'
$content = [System.IO.File]::ReadAllText($assessmentJsPath)

$enterpriseCode = @'
// =============================================================================
// OVERALL ENTERPRISE PORTFOLIO CALCULATIONS (All Scenarios)
// =============================================================================

function calculateEnterpriseBudget() {
  let totalBudget = 0;
  let totalSpent = 0;

  SCENARIOS_DATA.forEach(sc => {
    totalBudget += sc.budget;
    totalSpent += calculateSpentBudget(sc);
  });

  const totalRemaining = totalBudget - totalSpent;
  const budgetRatioRemaining = Math.max(0, Math.round((totalRemaining / totalBudget) * 100));

  return { totalBudget, totalSpent, totalRemaining, budgetRatioRemaining };
}

function calculateEnterpriseMitigation() {
  let totalMitigation = 0;
  SCENARIOS_DATA.forEach(sc => {
    totalMitigation += calculateOverallMitigation(sc);
  });
  return Math.round(totalMitigation / SCENARIOS_DATA.length);
}

function calculateEnterpriseAvertedLoss() {
  let totalPotential = 0;
  let totalAverted = 0;

  SCENARIOS_DATA.forEach(sc => {
    totalPotential += sc.potentialDamage;
    totalAverted += calculateAvertedLoss(sc);
  });

  return { totalPotential, totalAverted, totalResidual: totalPotential - totalAverted };
}

function calculateScenarioScore(scenario) {
  const spent = calculateSpentBudget(scenario);
  const remaining = scenario.budget - spent;
  const overallMitigation = calculateOverallMitigation(scenario);
  const state = getScenarioState(scenario.id);

  const budgetRatio = Math.max(0, Math.min(1, remaining / scenario.budget));
  const activeTiers = new Set();
  scenario.defenses.forEach(def => {
    if (state.activeDefenses.has(def.id)) {
      activeTiers.add(def.tier);
    }
  });
  const tierDiversityScore = Math.min(1, activeTiers.size / 3);

  let score = Math.round((overallMitigation * 0.65) + (budgetRatio * 100 * 0.20) + (tierDiversityScore * 100 * 0.15));
  if (remaining < 0) score = Math.max(0, score - 30);

  let grade = "F";
  let gradeClass = "rank-f";
  if (score >= 95) { grade = "S"; gradeClass = "rank-s"; }
  else if (score >= 85) { grade = "A"; gradeClass = "rank-a"; }
  else if (score >= 70) { grade = "B"; gradeClass = "rank-b"; }
  else if (score >= 50) { grade = "C"; gradeClass = "rank-c"; }

  return { score, grade, gradeClass, spent, remaining, overallMitigation };
}

function calculateEnterpriseScore() {
  let totalScore = 0;
  const scenarioScores = [];

  SCENARIOS_DATA.forEach(sc => {
    const scData = calculateScenarioScore(sc);
    scenarioScores.push({ scenario: sc, ...scData });
    totalScore += scData.score;
  });

  const avgScore = Math.round(totalScore / SCENARIOS_DATA.length);

  let grade = "F";
  let gradeClass = "grade-f";
  let statusText = "Critical Enterprise Exposure";

  if (avgScore >= 95) {
    grade = "S";
    gradeClass = "grade-s";
    statusText = "Elite Resilient Enterprise Defense";
  } else if (avgScore >= 85) {
    grade = "A";
    gradeClass = "grade-a";
    statusText = "Hardened Enterprise Defense Posture";
  } else if (avgScore >= 70) {
    grade = "B";
    gradeClass = "grade-b";
    statusText = "Adequate Defense with Residual Exposure";
  } else if (avgScore >= 50) {
    grade = "C";
    gradeClass = "grade-c";
    statusText = "Under-Funded & Vulnerable Enterprise Estate";
  }

  return {
    score: avgScore,
    grade,
    gradeClass,
    statusText,
    scenarioScores
  };
}

function renderEnterprisePortfolioSummary() {
  const container = document.getElementById("enterprise-portfolio-summary");
  if (!container) return;

  const entBudget = calculateEnterpriseBudget();
  const entMitigation = calculateEnterpriseMitigation();
  const entAverted = calculateEnterpriseAvertedLoss();
  const entScore = calculateEnterpriseScore();

  container.innerHTML = `
    <div class="portfolio-header-row">
      <div class="portfolio-title-group">
        <span class="portfolio-badge-pill">GLOBAL DEFENSE COMMAND</span>
        <h3 class="portfolio-heading">ENTERPRISE PORTFOLIO POSTURE (${SCENARIOS_DATA.length} INCIDENT SCENARIOS)</h3>
      </div>
      <div style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap;">
        <div class="portfolio-score-badge ${entScore.gradeClass}">
          <span>OVERALL GRADE ${entScore.grade}</span>
          <span>•</span>
          <span>${entScore.score} / 100</span>
        </div>
        <button class="portfolio-audit-btn" id="btn-open-portfolio-modal" title="View Detailed Multi-Scenario Audit">
          <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" fill="none" stroke-width="2">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
            <polyline points="14 2 14 8 20 8"></polyline>
          </svg>
          <span>All-Scenarios Scorecard</span>
        </button>
      </div>
    </div>

    <div class="portfolio-stats-grid">
      <div class="portfolio-stat-card">
        <span class="portfolio-stat-label">Total Enterprise Budget</span>
        <span class="portfolio-stat-val">$${(entBudget.totalBudget / 1000).toFixed(0)}k</span>
      </div>
      <div class="portfolio-stat-card">
        <span class="portfolio-stat-label">Total Expended Capital</span>
        <span class="portfolio-stat-val spent">-$${(entBudget.totalSpent / 1000).toFixed(0)}k</span>
      </div>
      <div class="portfolio-stat-card">
        <span class="portfolio-stat-label">Deployable Capital</span>
        <span class="portfolio-stat-val ${entBudget.totalRemaining < 200000 ? 'critical' : 'safe'}">$${(entBudget.totalRemaining / 1000).toFixed(0)}k</span>
      </div>
      <div class="portfolio-stat-card">
        <span class="portfolio-stat-label">Enterprise Mitigation</span>
        <span class="portfolio-stat-val highlight">${entMitigation}%</span>
      </div>
      <div class="portfolio-stat-card">
        <span class="portfolio-stat-label">Damages Prevented</span>
        <span class="portfolio-stat-val safe">$${(entAverted.totalAverted / 1000000).toFixed(1)}M</span>
      </div>
      <div class="portfolio-stat-card">
        <span class="portfolio-stat-label">Residual Exposure Risk</span>
        <span class="portfolio-stat-val ${entAverted.totalResidual > 15000000 ? 'critical' : 'safe'}">$${(entAverted.totalResidual / 1000000).toFixed(1)}M</span>
      </div>
    </div>

    <div class="portfolio-dual-tracks">
      <div class="portfolio-track-box">
        <div class="portfolio-track-label">
          <span>Enterprise Capital Liquidity (${entBudget.budgetRatioRemaining}% Available)</span>
          <span>$${entBudget.totalRemaining.toLocaleString()} remaining</span>
        </div>
        <div class="portfolio-track-bar">
          <div class="portfolio-fill-budget" style="width: ${entBudget.budgetRatioRemaining}%;"></div>
        </div>
      </div>
      <div class="portfolio-track-box">
        <div class="portfolio-track-label">
          <span>Global Threat Neutralization (${entMitigation}% Hardened)</span>
          <span>${entMitigation >= 80 ? 'DEFENSE SECURED' : 'ELEVATED RISK'}</span>
        </div>
        <div class="portfolio-track-bar">
          <div class="portfolio-fill-mitigation" style="width: ${entMitigation}%;"></div>
        </div>
      </div>
    </div>
  `;

  const auditBtn = document.getElementById("btn-open-portfolio-modal");
  if (auditBtn) {
    auditBtn.addEventListener("click", openPortfolioScorecardModal);
  }
}

function openPortfolioScorecardModal() {
  const modal = document.getElementById("portfolio-modal");
  const modalBody = document.getElementById("portfolio-modal-body");
  if (!modal || !modalBody) return;

  const entBudget = calculateEnterpriseBudget();
  const entMitigation = calculateEnterpriseMitigation();
  const entAverted = calculateEnterpriseAvertedLoss();
  const entScore = calculateEnterpriseScore();

  modalBody.innerHTML = `
    <div class="scorecard-container">
      <div class="scorecard-badge-row">
        <div class="rank-shield rank-${entScore.grade.toLowerCase()}">
          <span class="rank-letter">${entScore.grade}</span>
          <span class="rank-sub">ENTERPRISE</span>
        </div>
        <div class="scorecard-title-block">
          <span class="scorecard-kicker">EXECUTIVE CISO ENTERPRISE DEFENSE AUDIT</span>
          <h3 class="scorecard-heading">${entScore.statusText}</h3>
          <p class="scorecard-meta">Global Enterprise Score: <strong>${entScore.score} / 100</strong> • Scenarios Audited: <strong>${SCENARIOS_DATA.length}</strong> • Budget Status: <strong>$${(entBudget.totalSpent / 1000).toFixed(0)}k spent of $${(entBudget.totalBudget / 1000).toFixed(0)}k</strong></p>
        </div>
      </div>

      <div class="scorecard-stats-grid">
        <div class="score-card-stat">
          <span class="sc-label">Enterprise Mitigation</span>
          <span class="sc-num ${entMitigation >= 80 ? 'good' : 'bad'}">${entMitigation}%</span>
          <span class="sc-sub">Average across 10 Scenarios</span>
        </div>
        <div class="score-card-stat">
          <span class="sc-label">Total Capital Expended</span>
          <span class="sc-num">$${(entBudget.totalSpent / 1000).toFixed(0)}k</span>
          <span class="sc-sub">of $${(entBudget.totalBudget / 1000).toFixed(0)}k Allocated</span>
        </div>
        <div class="score-card-stat">
          <span class="sc-label">Total Damages Averted</span>
          <span class="sc-num good">$${(entAverted.totalAverted / 1000000).toFixed(1)}M</span>
          <span class="sc-sub">of $${(entAverted.totalPotential / 1000000).toFixed(1)}M Total Risk</span>
        </div>
        <div class="score-card-stat">
          <span class="sc-label">Remaining Deployable Funds</span>
          <span class="sc-num ${entBudget.totalRemaining > 0 ? 'good' : 'bad'}">$${(entBudget.totalRemaining / 1000).toFixed(0)}k</span>
          <span class="sc-sub">${entBudget.totalRemaining >= 0 ? 'Solvent Enterprise Budget' : 'Deficit'}</span>
        </div>
      </div>

      <div class="scorecard-debrief">
        <h4>Executive SOC Multi-Incident Evaluation</h4>
        <p>
          Comprehensive enterprise-wide security posture across all 10 high-stakes cyber incident scenarios: Banking Core DDoS, Hospital Ransomware, Cloud Microservices Breach, SCADA Grid Infiltration, Rogue AP Wiretapping, Container Breakout, OWASP Top 10 API Infiltration, Critical Database Blind SQLi, Storage Ransom-Wiper Sabotage, and HTTP Request Smuggling.
        </p>
      </div>

      <div class="portfolio-table-wrap">
        <table class="portfolio-table">
          <thead>
            <tr>
              <th>#</th>
              <th>Scenario</th>
              <th>Domain</th>
              <th>Difficulty</th>
              <th>Budget</th>
              <th>Spent</th>
              <th>Mitigation</th>
              <th>Score</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            ${entScore.scenarioScores.map((item, idx) => `
              <tr>
                <td><strong>0${idx + 1}</strong></td>
                <td><strong>${item.scenario.shortTitle}</strong></td>
                <td><span class="sc-domain-badge ${item.scenario.domainTag}">${item.scenario.domainTag.toUpperCase()}</span></td>
                <td><span class="sc-diff-badge ${item.scenario.difficulty.toLowerCase()}">${item.scenario.difficulty}</span></td>
                <td>$${(item.scenario.budget / 1000).toFixed(0)}k</td>
                <td style="color: var(--color-high);">-$${(item.spent / 1000).toFixed(0)}k</td>
                <td><span style="font-weight: 700; color: ${item.overallMitigation >= 80 ? 'var(--color-safe)' : (item.overallMitigation >= 40 ? 'var(--color-high)' : 'var(--color-critical)')};">${item.overallMitigation}%</span></td>
                <td><span style="font-weight: 800; color: var(--color-cyan);">${item.score}/100 (${item.grade})</span></td>
                <td>
                  <button class="sc-link-btn" onclick="switchScenarioFromModal('${item.scenario.id}')">Switch</button>
                </td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      </div>

      <div class="scorecard-modal-footer" style="margin-top: 20px;">
        <button class="modal-btn close-btn" id="btn-close-portfolio-modal">Close Portfolio Audit</button>
      </div>
    </div>
  `;

  modal.classList.add("show");

  const closeBtn = document.getElementById("btn-close-portfolio-modal");
  if (closeBtn) {
    closeBtn.addEventListener("click", () => {
      modal.classList.remove("show");
    });
  }
}

function switchScenarioFromModal(scenarioId) {
  const modal = document.getElementById("portfolio-modal");
  if (modal) modal.classList.remove("show");
  loadScenario(scenarioId);
}
window.switchScenarioFromModal = switchScenarioFromModal;
window.openPortfolioScorecardModal = openPortfolioScorecardModal;
'@

# Target insertion before // RENDER FINANCIAL COMMAND BAR
$targetMarker = "// =============================================================================`r`n// RENDER FINANCIAL COMMAND BAR"
if (-not $content.Contains($targetMarker)) {
    $targetMarker = "// =============================================================================`n// RENDER FINANCIAL COMMAND BAR"
}

$markerIdx = $content.IndexOf($targetMarker)
if ($markerIdx -lt 0) {
    Write-Host "ERROR: Financial command bar marker not found!"
    exit 1
}

$before = $content.Substring(0, $markerIdx)
$after = $content.Substring($markerIdx)

$newContent = $before + $enterpriseCode + "`r`n`r`n" + $after

# Update loadScenario to call renderEnterprisePortfolioSummary()
$newContent = $newContent.Replace(
    "  renderScenarioDossierHeader(scenario);",
    "  renderEnterprisePortfolioSummary();`r`n  renderScenarioDossierHeader(scenario);"
)

# Update toggleDefenseCountermeasure to call renderEnterprisePortfolioSummary()
$newContent = $newContent.Replace(
    "  renderFinancialCommandBar(scenario);`r`n  renderAttacksList(scenario);",
    "  renderEnterprisePortfolioSummary();`r`n  renderFinancialCommandBar(scenario);`r`n  renderAttacksList(scenario);"
)

# Update updateTopNavAssessmentMetrics to update portfolio score pill
$oldNavMetrics = @"
function updateTopNavAssessmentMetrics(scenario) {
  const remainingEl = document.getElementById("nav-assessment-remaining-budget");
  const mitigationEl = document.getElementById("nav-assessment-mitigation");

  if (remainingEl) {
    const spent = calculateSpentBudget(scenario);
    const rem = scenario.budget - spent;
    remainingEl.textContent = `$`{rem.toLocaleString()}`;
    remainingEl.className = `metric-val `${rem < 20000 ? 'critical' : 'highlight'}`;
  }

  if (mitigationEl) {
    const overall = calculateOverallMitigation(scenario);
    mitigationEl.textContent = `$`{overall}%`;
  }
}
"@

$newNavMetrics = @'
function updateTopNavAssessmentMetrics(scenario) {
  const remainingEl = document.getElementById("nav-assessment-remaining-budget");
  const mitigationEl = document.getElementById("nav-assessment-mitigation");
  const portfolioScorePill = document.getElementById("nav-portfolio-score-pill");

  if (remainingEl) {
    const spent = calculateSpentBudget(scenario);
    const rem = scenario.budget - spent;
    remainingEl.textContent = `$${rem.toLocaleString()}`;
    remainingEl.className = `metric-val ${rem < 20000 ? 'critical' : 'highlight'}`;
  }

  if (mitigationEl) {
    const overall = calculateOverallMitigation(scenario);
    mitigationEl.textContent = `${overall}%`;
  }

  if (portfolioScorePill) {
    const entScore = calculateEnterpriseScore();
    portfolioScorePill.textContent = `${entScore.score}/100 (${entScore.grade})`;
  }

  const navPortfolioBtn = document.getElementById("btn-nav-portfolio-scorecard");
  if (navPortfolioBtn && !navPortfolioBtn.hasAttribute("data-bound")) {
    navPortfolioBtn.setAttribute("data-bound", "true");
    navPortfolioBtn.addEventListener("click", openPortfolioScorecardModal);
  }
}
'@

# Replace updateTopNavAssessmentMetrics using IndexOf
$navFuncMarker = "function updateTopNavAssessmentMetrics(scenario) {"
$navFuncIdx = $newContent.IndexOf($navFuncMarker)
if ($navFuncIdx -ge 0) {
    $navFuncEnd = $newContent.IndexOf("function escapeHtml", $navFuncIdx)
    if ($navFuncEnd -ge 0) {
        $beforeNav = $newContent.Substring(0, $navFuncIdx)
        $afterNav = $newContent.Substring($navFuncEnd)
        $newContent = $beforeNav + $newNavMetrics + "`r`n`r`n" + $afterNav
        Write-Host "Replaced updateTopNavAssessmentMetrics successfully!"
    }
}

[System.IO.File]::WriteAllText($assessmentJsPath, $newContent, [System.Text.Encoding]::UTF8)
Write-Host "SUCCESS: Updated assessment.js with Enterprise Portfolio calculations! New length: $($newContent.Length)"
