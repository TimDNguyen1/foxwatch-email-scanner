// Cynthia - trusted contact: opens the setup page and sends alerts to the backend.

chrome.runtime.onInstalled.addListener(async () => {
    const { setupComplete } = await chrome.storage.local.get("setupComplete");
    if (!setupComplete) {
        chrome.runtime.openOptionsPage();
    }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "OPEN_SETUP") {
        chrome.runtime.openOptionsPage();
        return;
    }
    if (message.type !== "NOTIFY_CONTACT") return;

    fetch("http://127.0.0.1:8000/notify-contact", {
        method: "POST",
        headers: { "content-type": "application/json", "accept": "application/json" },
        body: JSON.stringify(message.payload)
    })
        .then(async (response) => {
            if (!response.ok) {
                let detail = "";
                try { detail = (await response.json()).detail || ""; } catch (e) { /* no JSON body */ }
                throw new Error(`${response.status}|${detail}`);
            }
            return response.json();
        })
        .then((data) => sendResponse({ success: true, data }))
        .catch((error) => sendResponse({ success: false, error: error.message }));

    return true; // keeps the channel open for the async response
});