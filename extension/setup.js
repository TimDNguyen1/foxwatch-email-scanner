const userNameInput = document.getElementById("userName");
const contactNameInput = document.getElementById("contactName");
const contactEmailInput = document.getElementById("contactEmail");
const autoAlertInput = document.getElementById("autoAlert");
const previewText = document.getElementById("previewText");
const messageBox = document.getElementById("message");
const removeButton = document.getElementById("removeButton");

const EMAIL_PATTERN = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/;

function showMessage(text, kind) {
    messageBox.textContent = text;
    messageBox.className = kind || "";
}

function updatePreview() {
    const user = userNameInput.value.trim() || "[your name]";
    const contact = contactNameInput.value.trim() || "there";
    previewText.textContent =
        `Subject: FoxWatch alert: ${user} may have received a scam email\n\n` +
        `Hi ${contact},\n\n` +
        `FoxWatch, a Gmail safety tool that ${user} uses, flagged an email they received as HIGH risk.\n\n` +
        `What it looks like: (the type of scam)\n` +
        `Subject line (links removed): "(the email's subject)"\n\n` +
        `What you can do: check in with ${user}. A phone call is best, using a number you already have, not one from the email.\n\n` +
        `The alert never includes the email's body, the sender, or any links.`;
}

async function loadSettings() {
    const { trustedContact } = await chrome.storage.local.get("trustedContact");
    if (trustedContact) {
        userNameInput.value = trustedContact.userName || "";
        contactNameInput.value = trustedContact.contactName || "";
        contactEmailInput.value = trustedContact.contactEmail || "";
        autoAlertInput.checked = trustedContact.enabled !== false;
        removeButton.hidden = false;
    }
    updatePreview();
}

document.getElementById("saveButton").addEventListener("click", async () => {
    const userName = userNameInput.value.trim();
    const contactName = contactNameInput.value.trim();
    const contactEmail = contactEmailInput.value.trim();

    if (!userName) {
        showMessage("Please enter your name so your contact knows who the alert is about.", "error");
        return;
    }
    if (!EMAIL_PATTERN.test(contactEmail)) {
        showMessage("That email address doesn't look right.", "error");
        return;
    }

    await chrome.storage.local.set({
        trustedContact: { userName, contactName, contactEmail, enabled: autoAlertInput.checked },
        setupComplete: true
    });
    removeButton.hidden = false;
    showMessage(
        autoAlertInput.checked
            ? "Saved. High-risk emails will alert your contact automatically."
            : "Saved. Alerts are paused, so you'll use the banner button to notify your contact.",
        "ok"
    );
});

document.getElementById("skipButton").addEventListener("click", async () => {
    await chrome.storage.local.set({ setupComplete: true });
    showMessage("Skipped. You can set this up later from the gear icon in the FoxWatch popup.", "ok");
});

removeButton.addEventListener("click", async () => {
    await chrome.storage.local.remove("trustedContact");
    userNameInput.value = "";
    contactNameInput.value = "";
    contactEmailInput.value = "";
    autoAlertInput.checked = true;
    removeButton.hidden = true;
    updatePreview();
    showMessage("Trusted contact removed.", "ok");
});

[userNameInput, contactNameInput].forEach(input => input.addEventListener("input", updatePreview));

loadSettings();