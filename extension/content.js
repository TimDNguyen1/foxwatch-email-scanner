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
        virusTotalScan(email.links); //Dang - call virustotal scan function with links in email
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

//Dang - Function to run virustotal scan
function virusTotalScan (urlList) {
    const VT_API_Key = "f821ba9e12df3003de6f0b1c878bf5a52b05a67240d710adb1e7f2957a09ea5e";
    const VT_endpoint = "https://www.virustotal.com/api/v3/urls";

    async function sendVirusTotalUrl(selectedUrl) {
        try {
            const response = await fetch(VT_endpoint, {
                method: 'POST',
                headers: {
                    accept: 'applications/json',
                    'x-apikey': 'VT_API_Key',
                    'content-type': 'application/x-www-form-urlencoded' 
                },
                body: 'url=${encodeURIComponent(selectedUrl))}'
            });

            const data = await response.json();
            if (response.ok) {
                console.log('VirusTotal scan submitted successfully:', data);
            } 
            else {
                console.error('Error submitting VirusTotal scan:', data);
            }

        }

        catch (error) {
            console.error('Error submitting VirusTotal scan:', error);
        }
    }

    async function scanUrlList(urlList) {
        for (const url of urlList) {
            await sendVirusTotalUrl(url);
            await new Promise(resolve => setTimeout(resolve, 15000)); //Wait for 15 seconds before the next request, 4 requests per minute limit
        }
    }
}

