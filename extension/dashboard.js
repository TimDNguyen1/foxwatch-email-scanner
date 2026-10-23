const analyzerToggle = document.getElementById("analyzerToggle");
const analyzerStatus = document.getElementById("analyzerStatus");

const currentEmail = document.getElementById("currentEmail");

const riskIndicator = document.getElementById("riskIndicator");
const riskLevel = document.getElementById("riskLevel");
const riskScore = document.getElementById("riskScore");

const totalScanned = document.getElementById("totalScanned");
const badCount = document.getElementById("badCount");
const mediumCount = document.getElementById("mediumCount");
const safeCount = document.getElementById("safeCount");


// =========================
// LOAD DASHBOARD DATA
// =========================
// - Osman
// Loads saved analyzer, email, risk, and scan statistics
// from Chrome storage when the FoxWatch dashboard opens.

chrome.storage.local.get(
    [
        "analyzerEnabled",
        "currentEmail",
        "riskLevel",
        "riskScore",
        "totalScanned",
        "badCount",
        "mediumCount",
        "safeCount"
    ],

    (data) => {

        // Analyzer
        const enabled =
            data.analyzerEnabled !== false;

        analyzerToggle.checked = enabled;

        updateAnalyzerStatus(enabled);


        // Current email
        if (data.currentEmail) {
            currentEmail.textContent = data.currentEmail;
        }


        // Risk
        if (data.riskLevel) {
            updateRisk(
                data.riskLevel,
                data.riskScore ?? 0
            );
        }


        // Statistics
        totalScanned.textContent =
            data.totalScanned ?? 0;

        badCount.textContent =
            data.badCount ?? 0;

        mediumCount.textContent =
            data.mediumCount ?? 0;

        safeCount.textContent =
            data.safeCount ?? 0;
    }
);


// =========================
// ANALYZER ON/OFF
// =========================
// - Osman
// Controls the FoxWatch analyzer ON/OFF switch
// and saves the user's setting to Chrome storage.

analyzerToggle.addEventListener("change", () => {

    const enabled = analyzerToggle.checked;

    chrome.storage.local.set({
        analyzerEnabled: enabled
    });

    updateAnalyzerStatus(enabled);
});


function updateAnalyzerStatus(enabled) {

    if (enabled) {

        analyzerStatus.textContent = "ON";

        analyzerStatus.style.color = "#2196f3";

    } else {

        analyzerStatus.textContent = "OFF";

        analyzerStatus.style.color = "#6b7280";
    }
}


// =========================
// RISK DISPLAY
// =========================
// - Osman
// Updates the risk level, score, and indicator color
// based on the email's analysis result.

function updateRisk(level, score) {

    riskLevel.textContent =
        level.toUpperCase();

    riskScore.textContent =
        score;

    riskIndicator.className =
        "risk-dot";


    const normalized =
        level.toLowerCase();


    if (
        normalized === "high" ||
        normalized === "bad" ||
        normalized === "malicious"
    ) {

        riskIndicator.classList.add("bad");

    } else if (
        normalized === "medium" ||
        normalized === "suspicious"
    ) {

        riskIndicator.classList.add("medium");

    } else {

        riskIndicator.classList.add("safe");
    }
}

// - Osman
// Displays VirusTotal URL scan results saved by content.js.

function displayLatestScan(data) {

    if (!data.latestScanResults) {
        return;
    }

    currentEmail.textContent =
        data.latestScanEmail || "Unknown email";

    const results = data.latestScanResults;

    if (results.length === 0) {

        riskLevel.textContent = "NO LINKS";
        riskScore.textContent = "N/A";

        riskIndicator.className = "risk-dot";
        riskIndicator.classList.add("medium");

        return;
    }

    const successfulScans = results.filter(
        item => item.result && item.result.ok
    );

    if (successfulScans.length === 0) {

        riskLevel.textContent = "SCAN FAILED";
        riskScore.textContent = "N/A";

        riskIndicator.className = "risk-dot";
        riskIndicator.classList.add("medium");

        return;
    }

    const malicious = successfulScans.reduce(
        (total, item) =>
            total + (item.result.malicious || 0),
        0
    );

    const suspicious = successfulScans.reduce(
        (total, item) =>
            total + (item.result.suspicious || 0),
        0
    );

    let level;

    if (malicious > 0) {

        level = "malicious";

    } else if (suspicious > 0) {

        level = "suspicious";

    } else {

        level = "safe";
    }

    updateRisk(level, malicious + suspicious);

    // Update scan statistics
    totalScanned.textContent = successfulScans.length;
    badCount.textContent = malicious;
    mediumCount.textContent = suspicious;
    safeCount.textContent = successfulScans.filter(
        item =>
            (item.result.malicious || 0) === 0 &&
            (item.result.suspicious || 0) === 0
    ).length;
}


// Loads the latest scan results when the dashboard opens.
chrome.storage.local.get(
    ["latestScanResults", "latestScanEmail"],
    displayLatestScan
);


// - Osman
// Refreshes the dashboard when new scan results are saved.
chrome.storage.onChanged.addListener((changes, areaName) => {

    if (
        areaName === "local" &&
        (changes.latestScanResults || changes.latestScanEmail)
    ) {

        chrome.storage.local.get(
            ["latestScanResults", "latestScanEmail"],
            displayLatestScan
        );
    }
});

// View Details page navigation
const viewDetailsButton = document.getElementById("viewDetailsButton");
const backButton = document.getElementById("backButton");
const mainView = document.getElementById("mainView");
const detailsView = document.getElementById("detailsView");

if (viewDetailsButton && backButton && mainView && detailsView) {
    viewDetailsButton.addEventListener("click", () => {
        mainView.hidden = true;
        detailsView.hidden = false;
    });

    backButton.addEventListener("click", () => {
        detailsView.hidden = true;
        mainView.hidden = false;
    });
}