console.log("FoxWatch extension loaded on Gmail.");

let analyzerEnabled = true;

chrome.storage.local.get(["analyzerEnabled"], (result) => {
    analyzerEnabled = result.analyzerEnabled !== false;
});

chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName === "local" && changes.analyzerEnabled) {
        analyzerEnabled = changes.analyzerEnabled.newValue !== false;
        lastEmail = "";

        console.log(
            "FoxWatch Analyzer:",
            analyzerEnabled ? "ON" : "OFF"
        );
    }
});

function unwrapGoogleUrl(rawUrl) {
    try {
        const parsed = new URL(rawUrl);
        if (parsed.hostname === "www.google.com" && parsed.pathname === "/url") {
            return parsed.searchParams.get("q") || rawUrl;
        }
    } catch (e) {
        // not a valid URL, fall through
    }
    return rawUrl;
}

function getCurrentEmail() {
    const subjectElement = document.querySelector("h2.hP");
    const senderElement = document.querySelector(".gD");
    const bodyElement = document.querySelector(".a3s");

    if (!subjectElement || !senderElement || !bodyElement) {
        return null;
    }


    //gets links in body of email into an array - Dang
    const linkElements = bodyElement.querySelectorAll("a");

    // unwrap Gmail's google.com/url redirects, then remove duplicates
    const links = [...new Set(
        Array.from(linkElements)
            .map(link => {
                // Prefer the real destination if Gmail wrapped/redirected it
                const safeUrl = link.getAttribute("data-saferedirecturl");
                return unwrapGoogleUrl(safeUrl || link.getAttribute("href"));
            })
            //filters out any elements that are not URLs
            .filter(href => href && !href.startsWith("#") && !href.startsWith("javascript:"))
    )];

    return {
        subject: subjectElement.innerText,
        sender: senderElement.getAttribute("email"),
        body: bodyElement.innerText,
        links: links
    };
}

//actually checks whether an email is open or not
function isEmailOpenByHash() {
    return /#.+\/.+/.test(window.location.hash);
}

// NEW: pulls the actual message ID out of the hash - tim
function getCurrentMessageId() {
    const match = window.location.hash.match(/#.+\/(.+)/);
    return match ? match[1] : null;
}

// NEW: cache read/write helpers - tim
async function getCachedResult(messageId) {
    const key = `foxwatch_${messageId}`;
    const stored = await chrome.storage.local.get(key);
    return stored[key] || null;
}

async function cacheResult(messageId, data) {
    const key = `foxwatch_${messageId}`;
    await chrome.storage.local.set({
        [key]: { data, checkedAt: Date.now() }
    });
}


let lastEmail = "";
let debounceTimer = null;
const inFlight = new Set();

function handleMutation() {

    if (!analyzerEnabled) {
        return;
    }

    clearTimeout(debounceTimer);
    debounceTimer = setTimeout( async() => {
        if (!isEmailOpenByHash()) {
            // Explicitly closed — reset state so a re-open of the
            // same email is treated as new next time.
            if (lastEmail !== "") {
                console.log("Email closed — resetting state");
                lastEmail = "";
            }
            return;
        }


        const email = getCurrentEmail();
        if (!email) return;

        const emailIdentifier = email.sender + email.subject + email.body;

        if (emailIdentifier === lastEmail) {
            return; // true duplicate, ignore
        }

        lastEmail = emailIdentifier;

        // - Osman
        // Saves the subject of the newly detected email
        // so the FoxWatch dashboard can display the current email.
        chrome.storage.local.set({
            currentEmail: email.subject
        });


        const messageId = getCurrentMessageId();

        if (messageId && inFlight.has(messageId)) {
            console.log("⏳ Scan already in progress for:", messageId);
            return;
        }
        if (messageId) inFlight.add(messageId);

        //check cache before treating this as something to analyze - tim
        try {
            const cached = messageId ? await getCachedResult(messageId) : null;
            if (cached) {
                console.log("✅ CACHE HIT for message:", messageId, cached.data);
                return;
            }

            console.log("❌ CACHE MISS — analyzing message:", messageId);

            const linkScans = await scanUrlList(email.links);
            const result = {linkScans};

            const allSucceeded = linkScans.length === email.links.length;
            if (messageId && allSucceeded) {
                await cacheResult(messageId, result);
            }

            console.log("NEW EMAIL ANALYZED:", result);
        } finally {
            // Always release the lock, even if the scan failed
            if (messageId) inFlight.delete(messageId);
        }
    }, 150); // debounce rapid-fire mutations during DOM transitions
}

const observer = new MutationObserver(handleMutation);

observer.observe(document.body, {
    childList: true,
    subtree: true
});

// Also catch navigation that doesn't trigger a body mutation
window.addEventListener("hashchange", handleMutation);

// Dang - sends a URL to the backend (via the background script) for VirusTotal scanning
async function sendVirusTotalUrl(selectedUrl) {
    const response = await chrome.runtime.sendMessage({
        type: "SCAN_URL",
        url: selectedUrl
    });

    if (!response || !response.success) {
        throw new Error(response?.error || "No response from background script");
    }
    if (!response.data.ok) {
        throw new Error(response.data.error || "Scan failed");
    }
    return response.data;
}

// Function to scan a list of URLs and store the results
async function scanUrlList(urlList) {
    const scanResults = [];

    for (let i = 0; i < urlList.length; i++) {
        const url = urlList[i];
        try {
            const result = await sendVirusTotalUrl(url);
            scanResults.push({ url, result });
            console.log(`Scanned URL: ${url}`, result);
        } catch (error) {
            console.error(`Failed to scan URL: ${url}`, error);
        }

        // Actually pause between scans (skip after the last one)
        if (i < urlList.length - 1) {
            await new Promise(resolve => setTimeout(resolve, 15000));
        }
    }
    return scanResults;
}



