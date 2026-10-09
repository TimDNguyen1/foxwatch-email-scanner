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

let lastEmail = "";
let debounceTimer = null;

function handleMutation() {
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
        scanUrlList(email.links); // Dang - scan links in email body
        if (!email) return;

        const emailIdentifier = email.sender + email.subject + email.body;

        if (emailIdentifier === lastEmail) {
            return; // true duplicate, ignore
        }

        lastEmail = emailIdentifier;
        console.log("NEW EMAIL DETECTED:");
        console.log(email);
    }, 150); // debounce rapid-fire mutations during DOM transitions
}

const observer = new MutationObserver(handleMutation);

observer.observe(document.body, {
    childList: true,
    subtree: true
});

// Also catch navigation that doesn't trigger a body mutation
window.addEventListener("hashchange", handleMutation);

//Dang - Functions to run virustotal scan
const VT_API_Key = "f821ba9e12df3003de6f0b1c878bf5a52b05a67240d710adb1e7f2957a09ea5e";
const VT_endpoint = "https://www.virustotal.com/api/v3/urls";

async function sendVirusTotalUrl(selectedUrl) {
    const formData = new URLSearchParams();
    formData.append("url", selectedUrl);

    const response = await fetch(VT_endpoint, {
        method: "POST",
        headers: {
            "x-apikey": VT_API_Key,
            "Content-Type": "application/x-www-form-urlencoded"
        },
        body: formData.toString()
    });

    if (!response.ok) {
        throw new Error(`VirusTotal API request failed with status ${response.status}`);
    }

    const data = await response.json();
    return data.data.id; // Return the ID of the submitted URL for tracking
}

async function scanUrlList(urlList) {
    for (const url of urlList) {
        try {
            const submittingLink = await sendVirusTotalUrl(url);

            scanResults.push({
                url: url,
                status: 'submitted',
                submittedLink: submittingLink
            });
        }
        catch (error) {
            scanResults.push({
                url: url,
                status: 'error',
                error: error.message
            });
        }
    }
    return scanResults;
}


