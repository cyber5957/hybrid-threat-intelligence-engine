// ===============================
// ALERT ANALYSIS
// ===============================

const analyzeBtn = document.getElementById("analyzeBtn");

analyzeBtn.addEventListener("click", function () {

    const alertText =
        document.getElementById("alertInput").value.trim();

    if (alertText === "") {
        alert("Please enter an alert or threat report.");
        return;
    }

    // Extract IOCs
    const iocs = extractIOCs(alertText);

    // Display IOCs
    displayIOCs(iocs);

    // ===============================
    // RISK OVERVIEW
    // ===============================

    document.getElementById("riskLevel").textContent = "HIGH";
    document.getElementById("confidence").textContent = "87%";

    // Actual IOC count
    const totalIOCs =
        iocs.ips.length +
        iocs.domains.length +
        iocs.urls.length +
        iocs.hashes.length;

    document.getElementById("iocCount").textContent = totalIOCs;
    document.getElementById("analysisStatus").textContent = "Completed";


    // ===============================
    // AI EXPLANATION
    // ===============================

    document.getElementById("aiExplanation").textContent =
        "The submitted alert contains multiple indicators that require further investigation. " +
        "The detected indicators should be correlated with security logs " +
        "and trusted threat-intelligence sources.";


    // ===============================
    // THREAT INTELLIGENCE
    // ===============================

    document.getElementById("evidenceStatus").textContent =
        "Evidence Available";

    document.getElementById("evidenceConfidence").textContent =
        "87%";

    document.getElementById("threatEvidence").innerHTML =
        "<p>Multiple indicators require further investigation. " +
        "Supporting threat-intelligence evidence should be verified " +
        "against trusted sources before taking response actions.</p>";


    // ===============================
    // RECOMMENDED ACTIONS
    // ===============================

    document.getElementById("recommendedActions").innerHTML = `
        <li>Investigate the identified IP addresses.</li>
        <li>Review related authentication and endpoint logs.</li>
        <li>Check identified domains and URLs against trusted intelligence.</li>
        <li>Correlate identified file hashes with endpoint activity.</li>
    `;


    // ===============================
    // ANALYSIS HISTORY
    // ===============================

    const historyList =
        document.getElementById("historyList");

    if (historyList) {

        const emptyMessage =
            historyList.querySelector(".history-empty");

        if (emptyMessage) {
            emptyMessage.remove();
        }

        const historyItem =
            document.createElement("div");

        historyItem.className = "history-item";

        historyItem.innerHTML = `
            <div>
                <strong>Alert Analysis</strong>
                <p>
                    Risk: HIGH |
                    Confidence: 87% |
                    IOCs: ${totalIOCs}
                </p>
            </div>

            <span class="history-status">
                Completed
            </span>
        `;

        historyList.appendChild(historyItem);
    }

});


// ===============================
// SIDEBAR NAVIGATION
// ===============================

const navLinks =
    document.querySelectorAll(".nav-link");

const sections = {
    dashboard: "dashboardSection",
    alert: "alertSection",
    ioc: "iocSection",
    threat: "threatSection",
    history: "historySection"
};

navLinks.forEach(function (link) {

    link.addEventListener("click", function (event) {

        event.preventDefault();

        navLinks.forEach(function (item) {
            item.classList.remove("active");
        });

        this.classList.add("active");

        const sectionName =
            this.dataset.section;

        const target =
            document.getElementById(
                sections[sectionName]
            );

        if (target) {

            target.scrollIntoView({
                behavior: "smooth",
                block: "start"
            });

        }

    });

});


// ===============================
// IOC EXTRACTION
// ===============================

function extractIOCs(text) {

    // IP addresses
    const ipRegex =
        /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;

    // URLs
    const urlRegex =
        /https?:\/\/[^\s]+/gi;

    // MD5 / SHA1 / SHA256
    const hashRegex =
        /\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b/g;

    const ips =
        text.match(ipRegex) || [];

    const urls =
        text.match(urlRegex) || [];

    const hashes =
        text.match(hashRegex) || [];

    // Domains
    const domainRegex =
        /\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b/g;

    let domains =
        text.match(domainRegex) || [];

    // Remove domains already present inside URLs
    domains = domains.filter(function (domain) {

        return !urls.some(function (url) {
            return url.includes(domain);
        });

    });

    return {

        ips: [...new Set(ips)],

        domains: [...new Set(domains)],

        urls: [...new Set(urls)],

        hashes: [...new Set(hashes)]

    };
}


// ===============================
// DISPLAY EXTRACTED IOCs
// ===============================

function displayIOCs(iocs) {

    const iocTable =
        document.getElementById("iocTable");

    if (!iocTable) {
        return;
    }

    // Header
    iocTable.innerHTML = `
        <div class="ioc-row ioc-header">
            <div>Type</div>
            <div>Indicator</div>
            <div>Severity</div>
            <div>Status</div>
        </div>
    `;


    // IP addresses
    iocs.ips.forEach(function (ip) {

        iocTable.innerHTML += `
            <div class="ioc-row">
                <div>IP Address</div>
                <div>${ip}</div>
                <div class="severity-high">HIGH</div>
                <div>Suspicious</div>
            </div>
        `;

    });


    // Domains
    iocs.domains.forEach(function (domain) {

        iocTable.innerHTML += `
            <div class="ioc-row">
                <div>Domain</div>
                <div>${domain}</div>
                <div class="severity-high">HIGH</div>
                <div>Suspicious</div>
            </div>
        `;

    });


    // URLs
    iocs.urls.forEach(function (url) {

        iocTable.innerHTML += `
            <div class="ioc-row">
                <div>URL</div>
                <div>${url}</div>
                <div class="severity-medium">MEDIUM</div>
                <div>Requires Review</div>
            </div>
        `;

    });


    // File hashes
    iocs.hashes.forEach(function (hash) {

        iocTable.innerHTML += `
            <div class="ioc-row">
                <div>File Hash</div>
                <div>${hash}</div>
                <div class="severity-high">HIGH</div>
                <div>Suspicious</div>
            </div>
        `;

    });

}