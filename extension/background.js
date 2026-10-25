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
//The SCAN_URL handler sends a POST request to /scan-url with the URL to be scanned, while the CHECK_EMAIL_BODY handler sends a POST request to /analyze-email with the email body to be analyzed. 
//Both handlers return a promise that resolves with the server's response or rejects with an error message if the request fails.   
const handlers = {
   SCAN_URL: (m) => postJson("/scan-url", { url: m.url }),
   CHECK_EMAIL_BODY: (m) => postJson("/analyze-email", { body: m.body })
};

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
   const handler = handlers[message.type];
   if (!handler) return;

   handler(message)
       .then((data) => sendResponse({ success: true, data }))
       .catch((error) => sendResponse({ success: false, error: error.message }));

   return true;
});