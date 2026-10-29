const analyzerToggle = document.getElementById("analyzerToggle");
const analyzerStatus = document.getElementById("analyzerStatus");

const currentEmail = document.getElementById("currentEmail");
const emailSender = document.getElementById("emailSender");
const riskIndicator = document.getElementById("riskIndicator");
const riskLevel = document.getElementById("riskLevel");
const riskScore = document.getElementById("riskScore");

const detailsEmail = document.getElementById("detailsEmail");
const openAIDetails = document.getElementById("openAIDetails");
const virusTotalDetails = document.getElementById("virusTotalDetails");

const totalScanned = document.getElementById("totalScanned");
const badCount = document.getElementById("badCount");
const mediumCount = document.getElementById("mediumCount");
const safeCount = document.getElementById("safeCount");
const clearStatisticsButton = document.getElementById("clearStatisticsButton");

const mainView = document.getElementById("mainView");
const detailsView = document.getElementById("detailsView");
const categoryView = document.getElementById("categoryView");

const categoryTitle = document.getElementById("categoryTitle");
const categoryEmailList = document.getElementById("categoryEmailList");

function showView(view) {
    mainView.hidden = view !== "main";
    detailsView.hidden = view !== "details";
    categoryView.hidden = view !== "category";
}

function updateAnalyzerStatus(enabled) {
    analyzerStatus.textContent = enabled ? "ON" : "OFF";
    analyzerStatus.style.color = enabled ? "#2196f3" : "#6b7280";
}

function updateRisk(level, score) {
    const normalized = (level || "unknown").toLowerCase();

    riskIndicator.className = "risk-dot";

    // While the email is still being analyzed, show LOADING and hide the dot.
    if (normalized === "loading") {
        riskLevel.textContent = "LOADING...";
        riskScore.textContent = "...";
        riskIndicator.style.display = "none";
        return;
    }

    riskIndicator.style.display = "";
    riskLevel.textContent = normalized.toUpperCase();
    riskScore.textContent = score;

    if (["high", "bad", "malicious"].includes(normalized)) {
        riskIndicator.classList.add("bad");
    } else if (["medium", "suspicious"].includes(normalized)) {
        riskIndicator.classList.add("medium");
    } else {
        riskIndicator.classList.add("safe");
    }
}

// Loads the current email and dashboard information.
async function loadDashboard() {
    const data = await chrome.storage.local.get([
        "analyzerEnabled",
        "currentEmail",
        "emailSender",
        "emailSubject",
        "emailAnalysis",
        "riskLevel",
        "riskScore"
    ]);

    const enabled = data.analyzerEnabled !== false;

    analyzerToggle.checked = enabled;
    updateAnalyzerStatus(enabled);

    currentEmail.textContent =
        data.emailSubject || data.currentEmail || "No email detected";

    emailSender.textContent =
        data.emailSender || "No sender detected";

    if (data.emailAnalysis) {
        updateRisk(
            data.emailAnalysis.risk_level,
            data.emailAnalysis.risk_score ?? "N/A"
        );

        openAIDetails.textContent =
            data.emailAnalysis.explanation || "No explanation available.";
    } else {
        updateRisk(data.riskLevel || "unknown", data.riskScore ?? "N/A");
    }

    await updateStatistics();
}

// Counts only email IDs recorded since the last Clear.
async function updateStatistics() {
    const data = await chrome.storage.local.get("countedEmailIds");
    const countedIds = data.countedEmailIds || [];
    const allData = await chrome.storage.local.get(null);

    let total = 0;
    let bad = 0;
    let medium = 0;
    let safe = 0;

    for (const messageId of countedIds) {
        const record = allData[`foxwatch_${messageId}`];

        if (!record?.data?.aiAnalysis) {
            continue;
        }

        const level =
            (record.data.aiAnalysis.risk_level || "").toLowerCase();

        total++;

        if (["high", "bad", "malicious"].includes(level)) {
            bad++;
        } else if (["medium", "suspicious"].includes(level)) {
            medium++;
        } else if (["low", "safe"].includes(level)) {
            safe++;
        }
    }

    totalScanned.textContent = total;
    badCount.textContent = bad;
    mediumCount.textContent = medium;
    safeCount.textContent = safe;
}

// Updates the current email and counts when Gmail changes storage.
// Counting itself now happens in content.js, which is always running on Gmail.
chrome.storage.onChanged.addListener(async (changes, areaName) => {
    if (areaName !== "local") {
        return;
    }

    if (changes.emailSubject || changes.currentEmail) {
        const data = await chrome.storage.local.get([
            "emailSubject",
            "currentEmail"
        ]);

        currentEmail.textContent =
            data.emailSubject || data.currentEmail || "No email detected";
    }

    if (changes.emailSender) {
        emailSender.textContent =
            changes.emailSender.newValue || "No sender detected";
    }

    if (changes.emailAnalysis) {
        const analysis = changes.emailAnalysis.newValue;

        if (analysis) {
            updateRisk(
                analysis.risk_level || "unknown",
                analysis.risk_score ?? "N/A"
            );

            openAIDetails.textContent =
                analysis.explanation || "No explanation available.";
        }
    }

    // Show LOADING when there's no AI result yet.
    if (changes.riskLevel || changes.riskScore) {
        const data = await chrome.storage.local.get([
            "emailAnalysis",
            "riskLevel",
            "riskScore"
        ]);

        if (!data.emailAnalysis) {
            updateRisk(data.riskLevel, data.riskScore ?? "N/A");
        }
    }

    // Restore the cached analysis for the selected email.
    if (changes.currentMessageId?.newValue) {
        const messageId = changes.currentMessageId.newValue;
        const saved = await chrome.storage.local.get(`foxwatch_${messageId}`);
        const record = saved[`foxwatch_${messageId}`];

        if (record?.data?.aiAnalysis) {
            const analysis = record.data.aiAnalysis;

            updateRisk(
                analysis.risk_level || "unknown",
                analysis.risk_score ?? "N/A"
            );

            openAIDetails.textContent =
                analysis.explanation || "No explanation available.";
        }
    }

    if (
        changes.emailAnalysis ||
        changes.currentMessageId ||
        changes.countedEmailIds ||
        changes.emailOpenedAt ||
        Object.keys(changes).some(key => key.startsWith("foxwatch_"))
    ) {
        await updateStatistics();
    }
});

// Analyzer ON/OFF.
analyzerToggle.addEventListener("change", () => {
    const enabled = analyzerToggle.checked;

    chrome.storage.local.set({ analyzerEnabled: enabled });
    updateAnalyzerStatus(enabled);
});

// Opens Scan Details.
document.getElementById("viewDetailsButton").addEventListener("click", async () => {
    const data = await chrome.storage.local.get([
        "currentEmail",
        "emailSubject",
        "emailAnalysis",
        "currentMessageId"
    ]);

    detailsEmail.textContent =
        data.emailSubject || data.currentEmail || "No email selected";

    openAIDetails.textContent =
        data.emailAnalysis?.explanation || "No saved OpenAI results available.";

    const saved = data.currentMessageId
        ? await chrome.storage.local.get(`foxwatch_${data.currentMessageId}`)
        : {};

    const record = data.currentMessageId
        ? saved[`foxwatch_${data.currentMessageId}`]
        : null;

    const linkScans = record?.data?.linkScans;

    if (!Array.isArray(linkScans)) {
        virusTotalDetails.textContent = "No saved VirusTotal results available.";
    } else if (linkScans.length === 0) {
        virusTotalDetails.textContent = "No links were found in this email to scan.";
    } else {
        virusTotalDetails.textContent = linkScans.map(scan => {
            const url = scan.url || "Unknown URL";
            const result = scan.result;

            return `${url}\n${JSON.stringify(result, null, 2)}`;
        }).join("\n\n");
    }

    showView("details");
});

document.getElementById("backButton").addEventListener("click", () => {
    showView("main");
});

// Displays emails in the selected risk category.
// Only shows emails counted since the last Clear, so it matches the stats.
async function showCategory(category) {
    const allData = await chrome.storage.local.get(null);
    const countedIds = allData.countedEmailIds || [];
    const emails = [];

    for (const messageId of countedIds) {
        const record = allData[`foxwatch_${messageId}`];

        if (!record?.data?.aiAnalysis) {
            continue;
        }

        const savedData = record.data;
        const analysis = savedData.aiAnalysis;
        const level = (analysis.risk_level || "").toLowerCase();

        let matches = false;

        if (category === "Bad") {
            matches = ["high", "bad", "malicious"].includes(level);
        } else if (category === "Medium") {
            matches = ["medium", "suspicious"].includes(level);
        } else if (category === "Safe") {
            matches = ["low", "safe"].includes(level);
        }

        if (matches) {
            emails.push({
                subject: savedData.emailSubject || savedData.subject || "Unknown subject",
                sender: savedData.emailSender || savedData.sender || "Unknown sender",
                score: analysis.risk_score ?? "N/A"
            });
        }
    }

    categoryTitle.textContent = category + " Emails";
    categoryEmailList.replaceChildren();

    if (emails.length === 0) {
        categoryEmailList.textContent = "No emails in this category yet.";
    } else {
        emails.forEach(email => {
            const item = document.createElement("div");
            item.className = "category-email-item";

            const subject = document.createElement("strong");
            subject.textContent = email.subject;

            const sender = document.createElement("div");
            sender.textContent = "From: " + email.sender;

            const score = document.createElement("div");
            score.textContent = "Risk score: " + email.score;

            item.append(subject, sender, score);
            categoryEmailList.appendChild(item);
        });
    }

    showView("category");
}

document.getElementById("badCategoryButton").addEventListener("click", () => {
    showCategory("Bad");
});

document.getElementById("mediumCategoryButton").addEventListener("click", () => {
    showCategory("Medium");
});

document.getElementById("safeCategoryButton").addEventListener("click", () => {
    showCategory("Safe");
});

document.getElementById("categoryBackButton").addEventListener("click", () => {
    showView("main");
});

// Clears statistics without deleting saved email analyses.
clearStatisticsButton.addEventListener("click", async () => {
    await chrome.storage.local.set({
        countedEmailIds: [],
        emailOpenedAt: null
    });

    totalScanned.textContent = "0";
    badCount.textContent = "0";
    mediumCount.textContent = "0";
    safeCount.textContent = "0";
});

loadDashboard();