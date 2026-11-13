// Cynthia - trusted contact section for the FoxWatch banner.
// Loaded before content.js (see manifest), so content.js can call addTrustedContactSection().

const TC_SCAM_TYPES = [
    "none", "account_verification", "payment_or_invoice",
    "pretending_to_be_someone_you_know", "prize_or_lottery",
    "tech_support", "job_or_investment", "other"
];
const tcPendingAlerts = new Map();

function tcMessageId() {
    const match = window.location.hash.match(/#.+\/(.+)/);
    return match ? match[1] : null;
}

function tcFriendlyError(errorText) {
    const text = String(errorText || "");
    if (text.startsWith("503")) return "Alerts aren't set up on the FoxWatch server yet.";
    if (text.startsWith("429")) return "Too many alerts to this contact. Try again later.";
    if (text.startsWith("422")) return "That contact email doesn't look right. Check your settings.";
    return "Couldn't send the alert. Make sure the FoxWatch server is running.";
}

function tcButton(label, onClick) {
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = label;
    button.style.cssText =
        "margin:6px 8px 0 0;padding:6px 12px;border:none;border-radius:4px;" +
        "background:#1a73e8;color:#fff;font-size:13px;cursor:pointer;";
    button.addEventListener("click", onClick);
    return button;
}

async function tcSendAlert(contact, analysis, messageId) {
    const subject = (document.querySelector("h2.hP")?.innerText || "").slice(0, 500);
    const scamType = TC_SCAM_TYPES.includes(analysis.scam_type) ? analysis.scam_type : "other";

    try {
        const response = await chrome.runtime.sendMessage({
            type: "NOTIFY_CONTACT",
            payload: {
                user_name: contact.userName || "",
                contact_name: contact.contactName || "",
                contact_email: contact.contactEmail,
                risk_level: analysis.risk_level,
                scam_type: scamType,
                subject: subject
            }
        });
        if (!response || !response.success) {
            return { ok: false, error: response?.error || "No response" };
        }
        if (messageId) {
            await chrome.storage.local.set({ [`alertSent_${messageId}`]: Date.now() });
        }
        return { ok: true };
    } catch (error) {
        return { ok: false, error: String(error.message || error) };
    }
}

async function addTrustedContactSection(banner, analysis) {
    try {
        if (!banner || !analysis) return;
        const level = analysis.risk_level;
        if (level !== "medium" && level !== "high") return;

        const messageId = tcMessageId();
        const { trustedContact } = await chrome.storage.local.get("trustedContact");
        const hasContact = Boolean(trustedContact && trustedContact.contactEmail);
        const sentKey = messageId ? `alertSent_${messageId}` : null;
        const sentInfo = sentKey ? (await chrome.storage.local.get(sentKey))[sentKey] : null;

        const section = document.createElement("div");
        section.style.cssText =
            "margin-top:10px;padding-top:8px;border-top:1px solid rgba(0,0,0,0.15);font-size:13px;";
        const status = document.createElement("div");
        const actions = document.createElement("div");
        section.append(status, actions);
        banner.appendChild(section);

        // No contact saved yet: offer to set one up
        if (!hasContact) {
            status.textContent = level === "high"
                ? "This email is high risk. Set up a trusted contact so someone you trust can be told about emails like this."
                : "Want someone you trust to be told about emails like this?";
            actions.appendChild(tcButton(
                level === "high" ? "Set up a trusted contact" : "Notify a trusted contact (set one up)",
                () => chrome.runtime.sendMessage({ type: "OPEN_SETUP" })
            ));
            return;
        }

        const name = trustedContact.contactName || trustedContact.contactEmail;

        // Already alerted about this email: never send twice
        if (sentInfo) {
            status.style.color = "#137333";
            status.textContent = `\u2713 ${name} was notified about this email.`;
            return;
        }

        const runSend = async () => {
            actions.replaceChildren();
            status.style.color = "";
            status.textContent = `Sending an alert to ${name}...`;

            const key = messageId || "no-id";
            let promise = tcPendingAlerts.get(key);
            if (!promise) {
                promise = tcSendAlert(trustedContact, analysis, messageId);
                tcPendingAlerts.set(key, promise);
                promise.finally(() => tcPendingAlerts.delete(key));
            }

            const result = await promise;
            if (result.ok) {
                status.style.color = "#137333";
                status.textContent = `\u2713 ${name} was notified about this email.`;
            } else {
                status.style.color = "#c5221f";
                status.textContent = tcFriendlyError(result.error);
                actions.appendChild(tcButton("Try again", runSend));
            }
        };

        const autoSend = level === "high" && trustedContact.enabled !== false && messageId;
        if (autoSend) {
            runSend();
        } else {
            actions.appendChild(tcButton(`Let ${name} know`, runSend));
        }
    } catch (error) {
        console.error("Trusted contact section failed:", error);
    }
}