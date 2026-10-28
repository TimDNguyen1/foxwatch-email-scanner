// Receives scan requests from content.js and talks to the local backend.
// Runs in the extension's background context, so Gmail's page restrictions don't apply.
async function postJson(endpoint, payload) {
   const response = await fetch(`http://127.0.0.1:8000${endpoint}`, {
       method: "POST",
       headers: {
           "content-type": "application/json",
           "accept": "application/json"
       },
       body: JSON.stringify(payload)
   });
   if (!response.ok) {
       throw new Error(`Server responded with status ${response.status}`);
   }
   return response.json();
}

//Dang - Modified the handlers to use the new endpoints for scanning URLs and analyzing email bodies.
const handlers = {
   SCAN_URL: (m) => postJson("/scan-url", { url: m.url }),
   CHECK_EMAIL_BODY: (m) => postJson("/analyze-email", { body: m.text })
};

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
   const handler = handlers[message.type];
   if (!handler) return;

   handler(message)
       .then((data) => sendResponse({ success: true, data }))
       .catch((error) => sendResponse({ success: false, error: error.message }));

    return true; // keeps the message channel open for the async response
});
// Cynthia - Sends the open email to the backend for OpenAI analysis
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type !== "ANALYZE_EMAIL") return;

    fetch("http://127.0.0.1:8000/analyze-email", {
        method: "POST",
        headers: { "content-type": "application/json", "accept": "application/json" },
        body: JSON.stringify(message.email)
    })
        .then(async (response) => {
            if (!response.ok) {
                throw new Error(`Server responded with status ${response.status}`);
            }
            return response.json();
        })
        .then((data) => sendResponse({ success: true, data }))
        .catch((error) => sendResponse({ success: false, error: error.message }));

    return true; // keeps the channel open for the async response
});