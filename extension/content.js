console.log("FoxWatch extension loaded on Gmail.");

function getCurrentEmail() {
    const subjectElement = document.querySelector("h2.hP");
    const senderElement = document.querySelector(".gD");
    const bodyElement = document.querySelector(".a3s");

    if (!subjectElement || !senderElement || !bodyElement) {
        return null;
    }


    //gets links in body of email into an array - Dang
    const linkElements = bodyElement.querySelectorAll("a");

    const links = Array.from(linkElements)
        .map(link => {
            // Prefer the real destination if Gmail wrapped/redirected it
            const safeUrl = link.getAttribute("data-saferedirecturl");
            if (safeUrl) return safeUrl;

            // Fall back to the raw href attribute
            //this will resolve blank links in extraction
            return link.getAttribute("href");
        })
        //filters out any elements that are not URLs
        .filter(href => href && !href.startsWith("#") && !href.startsWith("javascript:"));

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

//TODO: replace with real backend call once it's ready. This is a fake test
//Simulates "analysis" taking a moment, and returns a fake score/reason
//so we can verify the cache round-trip works end to end.
async function fakeAnalyzeEmail(email) {
    console.log("Running FAKE analysis (no backend yet)...");
    await new Promise(resolve => setTimeout(resolve, 500)); // simulate delay
    return {
        score: Math.floor(Math.random() * 10) + 1, // random 1-10 so you can see it's "fresh" each time cache is empty
        reasons: ["This is a stubbed result for testing caching only"]
    };
}


let lastEmail = "";
let debounceTimer = null;

function handleMutation() {
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

        // NEW: check cache before treating this as something to analyze - tim
        const messageId = getCurrentMessageId();
        const cached = messageId ? await getCachedResult(messageId) : null;

        if (cached) {
            console.log("✅ CACHE HIT for message:", messageId, cached.data);
            return;
        }

        console.log("❌ CACHE MISS — analyzing message:", messageId);

        // Stand-in for real backend call
        const result = await fakeAnalyzeEmail(email);

        if (messageId) {
            await cacheResult(messageId, result);
        }
        console.log("NEW EMAIL ANALYZED, ", result);
        console.log(email);

        //TODO later: actually call your backend/analysis here, then:
        // if (messageId) await cacheResult(messageId, analysisResult);
    }, 150); // debounce rapid-fire mutations during DOM transitions
}

const observer = new MutationObserver(handleMutation);

observer.observe(document.body, {
    childList: true,
    subtree: true
});

// Also catch navigation that doesn't trigger a body mutation
window.addEventListener("hashchange", handleMutation);