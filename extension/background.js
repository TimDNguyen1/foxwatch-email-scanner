// Receives scan requests from content.js and talks to the local backend.
// Runs in the extension's background context, so Gmail's page restrictions don't apply.
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type !== "SCAN_URL") return;

    fetch("http://localhost:3000/scan-url", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: message.url })
    })
        .then(async (response) => {
            if (!response.ok) {
                throw new Error(`Server responded with status ${response.status}`);
            }
            return response.json();
        })
        .then((data) => sendResponse({ success: true, data }))
        .catch((error) => sendResponse({ success: false, error: error.message }));

    return true; // keeps the message channel open for the async response
});