
/* =========================
   LINKSHIELD - SCAN ENGINE
   Version 1.0
========================= */

const urlInput = document.getElementById("urlInput");
const scanButton = document.getElementById("scanButton");
const loading = document.getElementById("loading");
const resultSection = document.getElementById("resultSection");

const riskScore = document.getElementById("riskScore");
const riskBadge = document.getElementById("riskBadge");
const resultTitle = document.getElementById("resultTitle");
const resultDescription = document.getElementById("resultDescription");
const displayUrl = document.getElementById("displayUrl");
const indicatorList = document.getElementById("indicatorList");

const historyList = document.getElementById("historyList");
const clearHistory = document.getElementById("clearHistory");

const HISTORY_KEY = "linkshield_history_v1";

// Known URL shortener domains
const shorteners = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly",
    "shorturl.at",
    "ow.ly",
    "rebrand.ly",
    "buff.ly"
];

// Suspicious URL keywords
const suspiciousKeywords = [
    "login",
    "verify",
    "account",
    "password",
    "banking",
    "secure",
    "update",
    "wallet",
    "signin",
    "confirm",
    "payment"
];

// Escape HTML before displaying user input
function escapeHTML(value) {
    return String(value).replace(/[&<>"']/g, function(char) {
        const entities = {
            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": "&#39;"
        };

        return entities[char];
    });
}

// Validate and normalize URL
function validateURL(value) {
    let input = value.trim();

    if (!input) {
        throw new Error("Please enter a URL.");
    }

    if (/[\s\\]/.test(input)) {
        throw new Error("URL contains invalid whitespace or characters.");
    }

    if (!/^https?:\/\//i.test(input)) {
        input = "https://" + input;
    }

    let parsed;

    try {
        parsed = new URL(input);
    } catch (error) {
        throw new Error("Invalid URL format.");
    }

    if (
        !["http:", "https:"].includes(parsed.protocol) ||
        !parsed.hostname ||
        !parsed.hostname.includes(".")
    ) {
        throw new Error("Please enter a valid web URL.");
    }

    if (parsed.username || parsed.password) {
        throw new Error("URLs containing embedded credentials are not accepted.");
    }

    return {
        parsed: parsed,
        original: input
    };
}

// Check IPv4 address
function isIPAddress(hostname) {
    const parts = hostname.split(".");

    if (parts.length !== 4) return false;

    return parts.every(part => {
        return /^\d+$/.test(part) &&
            Number(part) >= 0 &&
            Number(part) <= 255;
    });
}

// Analyze URL characteristics
function analyzeURL(parsed) {

    let score = 0;
    const indicators = [];

    function addRisk(points, title, description) {
        score += points;

        indicators.push({
            title: title,
            description: description
        });
    }

    const hostname = parsed.hostname.toLowerCase();
    const fullURL = parsed.href.toLowerCase();

    // HTTPS check
    if (parsed.protocol === "http:") {
        addRisk(
            10,
            "Unencrypted HTTP",
            "This URL uses HTTP instead of HTTPS."
        );
    }

    // IP address check
    if (isIPAddress(hostname)) {
        addRisk(
            25,
            "IP Address URL",
            "The website uses an IP address instead of a regular domain."
        );
    }

    // URL shortener check
    if (shorteners.includes(hostname)) {
        addRisk(
            15,
            "URL Shortener",
            "This domain is a known URL shortening service. Destination is hidden."
        );
    }

    // @ symbol check
    if (parsed.href.includes("@")) {
        addRisk(
            20,
            "Suspicious @ Symbol",
            "The URL contains an @ character."
        );
    }

    // Punycode check
    if (hostname.includes("xn--")) {
        addRisk(
            20,
            "Punycode Domain",
            "The domain uses internationalized encoding and deserves closer inspection."
        );
    }

    // Excessive subdomains
    const domainParts = hostname.split(".");

    if (domainParts.length > 4) {
        addRisk(
            15,
            "Excessive Subdomains",
            "The URL contains an unusually large number of domain segments."
        );
    }

    // Suspicious keywords
    const matchedKeywords = suspiciousKeywords.filter(keyword =>
        fullURL.includes(keyword)
    );

    if (matchedKeywords.length > 0) {
        addRisk(
            Math.min(matchedKeywords.length * 5, 15),
            "Suspicious Keywords",
            "Found: " + matchedKeywords.join(", ")
        );
    }

    // Suspicious characters
    if (/%40|%2f|%5c|%00/i.test(parsed.pathname + parsed.search)) {
        addRisk(
            15,
            "Encoded Special Characters",
            "The URL contains encoded characters that may require inspection."
        );
    }

    // Unusual port
    if (parsed.port && !["80", "443"].includes(parsed.port)) {
        addRisk(
            10,
            "Unusual Port",
            "The URL uses a non-standard web port."
        );
    }

    // Final score
    score = Math.min(score, 100);

    let level;
    let title;
    let description;

    if (score >= 50) {
        level = "HIGH RISK";
        title = "Multiple Risk Indicators Found";
        description = "Several suspicious URL characteristics were detected.";
    } else if (score >= 25) {
        level = "SUSPICIOUS";
        title = "Potential Warning Signs";
        description = "Some URL characteristics deserve further investigation.";
    } else {
        level = "LOW RISK";
        title = "No Obvious Risk Indicators";
        description = "Few or no suspicious URL characteristics were detected.";
    }

    return {
        score,
        level,
        title,
        description,
        indicators
    };
}

// Display analysis results
function displayResults(url, result) {

    resultSection.classList.remove("hidden");

    riskScore.textContent = result.score;
    riskBadge.textContent = result.level;

    riskBadge.className = "risk-badge";

    if (result.score >= 50) {
        riskBadge.classList.add("high");
    } else if (result.score >= 25) {
        riskBadge.classList.add("medium");
    } else {
        riskBadge.classList.add("low");
    }

    resultTitle.textContent = result.title;
    resultDescription.textContent = result.description;
    displayUrl.textContent = url;

    indicatorList.innerHTML = "";

    if (result.indicators.length === 0) {
        indicatorList.innerHTML =
            '<p class="no-indicators">✓ No obvious suspicious indicators detected.</p>';
    } else {

        result.indicators.forEach(item => {

            const element = document.createElement("div");

            element.className = "indicator-item";

            element.innerHTML =
                "<span>⚠</span><div><strong>" +
                escapeHTML(item.title) +
                "</strong><br>" +
                escapeHTML(item.description) +
                "</div>";

            indicatorList.appendChild(element);
        });
    }
}

// Save scan history
function saveHistory(url, result) {

    let history = getHistory();

    history.unshift({
        url: url,
        score: result.score,
        level: result.level,
        date: new Date().toLocaleString()
    });

    history = history.slice(0, 10);

    try {
        localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
    } catch (error) {
        console.warn("Unable to save scan history.");
    }

    renderHistory();
}

// Get scan history
function getHistory() {

    try {
        const data = JSON.parse(
            localStorage.getItem(HISTORY_KEY) || "[]"
        );

        return Array.isArray(data) ? data : [];
    } catch (error) {
        return [];
    }
}

// Display scan history
function renderHistory() {

    const history = getHistory();

    historyList.innerHTML = "";

    if (history.length === 0) {
        historyList.innerHTML =
            '<p class="empty-message">No scan history yet.</p>';
        return;
    }

    history.forEach(item => {

        const element = document.createElement("div");

        element.className = "history-item";

        const url = document.createElement("strong");
        url.textContent = item.url;

        const details = document.createElement("small");
        details.textContent =
            item.level + " | Score: " +
            item.score + "/100 | " + item.date;

        element.appendChild(url);
        element.appendChild(details);

        historyList.appendChild(element);
    });
}

// Main scan function
function scanURL() {

    const input = urlInput.value;

    resultSection.classList.add("hidden");

    try {

        const validated = validateURL(input);

        scanButton.disabled = true;
        loading.classList.remove("hidden");

        setTimeout(() => {

            try {

                const result = analyzeURL(validated.parsed);

                displayResults(validated.original, result);

                saveHistory(validated.original, result);

            } finally {

                loading.classList.add("hidden");
                scanButton.disabled = false;

            }

        }, 600);

    } catch (error) {

        alert(error.message);

        loading.classList.add("hidden");
        scanButton.disabled = false;

    }
}

// Button event
scanButton.addEventListener("click", scanURL);

// Enter key event
urlInput.addEventListener("keydown", function(event) {

    if (event.key === "Enter") {
        scanURL();
    }

});

// Clear history
clearHistory.addEventListener("click", function() {

    if (confirm("Are you sure you want to clear scan history?")) {

        localStorage.removeItem(HISTORY_KEY);

        renderHistory();
    }

});

// Load history on startup
renderHistory();
  
