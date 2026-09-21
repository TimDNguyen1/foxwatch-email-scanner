console.log("FoxWatch extension loaded on Gmail.");

//get email content: sender, subject, content
function getCurrentEmail() {
    const subjectElement = document.querySelector("h2.hP");
    const senderElement = document.querySelector(".gD");
    const bodyElement = document.querySelector(".a3s");
    //Added const for links - Dang
    const linkElement = document.querySelector("a");

    //Added !linkElement - Dang
    if (!subjectElement || !senderElement || !bodyElement || !linkElement) {
        return null;
    }

    return {
        subject: subjectElement.innerText,
        sender: senderElement.getAttribute("email"),
        body: bodyElement.innerText
    };
}

let lastEmail = "";

//this block checks when different email is opened
const observer = new MutationObserver(() => {
    const email = getCurrentEmail();

    if (!email) {
        return;
    }

    const emailIdentifier =
        email.sender + email.subject + email.body;

    if (emailIdentifier === lastEmail) {
        return;
    }

    lastEmail = emailIdentifier;

    console.log("Email detected:");
    console.log(email);
});

observer.observe(document.body, {
    childList: true,
    subtree: true
});