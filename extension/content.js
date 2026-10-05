console.log("FoxWatch extension loaded on Gmail.");

let analyzerEnabled = true;

chrome.storage.local.get(["analyzerEnabled"], (result) => {
    analyzerEnabled = result.analyzerEnabled !== false;
});

chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName === "local" && changes.analyzerEnabled) {
        analyzerEnabled = changes.analyzerEnabled.newValue !== false;

        console.log(
            "FoxWatch Analyzer:",
            analyzerEnabled ? "ON" : "OFF"
        );
    }
});

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

let lastEmail = "";
let debounceTimer = null;

function handleMutation() {

    if (!analyzerEnabled) {
        return;
    }

    clearTimeout(debounceTimer);

    debounceTimer = setTimeout(() => {
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
        console.log("NEW EMAIL DETECTED:");
        console.log(email);


        // - Osman
        // Saves the subject of the newly detected email
        // so the FoxWatch dashboard can display the current email.
        chrome.storage.local.set({
            currentEmail: email.subject
        });

    }, 150); // debounce rapid-fire mutations during DOM transitions
}

const observer = new MutationObserver(handleMutation);

observer.observe(document.body, {
    childList: true,
    subtree: true
});

// Also catch navigation that doesn't trigger a body mutation
window.addEventListener("hashchange", handleMutation);