// Receives requests from content.js and talks to the local backend.
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

// Dang - handlers map each message type from content.js to a backend endpoint.
// Cynthia - ANALYZE_EMAIL replaces CHECK_EMAIL_BODY so each email makes one OpenAI call.
const handlers = {
   SCAN_URL: (m) => postJson("/scan-url", { url: m.url }),
   ANALYZE_EMAIL: (m) => postJson("/analyze-email", m.email)
};

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
   const handler = handlers[message.type];
   if (!handler) return;

   handler(message)
       .then((data) => sendResponse({ success: true, data }))
       .catch((error) => sendResponse({ success: false, error: error.message }));

   return true; // keeps the message channel open for the async response
});