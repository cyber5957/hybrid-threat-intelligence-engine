const demoAlert = "Suspicious outbound network activity detected. Host 192.0.2.25 connected to 198.51.100.42 and attempted to resolve login-demo.example.com. Additional communication was observed with cdn-update.example.net. Internal DNS traffic was also observed from 192.168.10.25 to 203.0.113.77.";
const input = document.getElementById("alertInput");
const history = [];

document.getElementById("loadDemo").addEventListener("click", () => {
  input.value = demoAlert;
  input.focus();
  document.getElementById("formError").hidden = true;
});

document.getElementById("analyzeBtn").addEventListener("click", analyzeAlert);
input.addEventListener("keydown", (event) => {
  if ((event.ctrlKey || event.metaKey) && event.key === "Enter") analyzeAlert();
});

function extractIOCs(text) {
  const ipCandidates = text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [];
  const ips = [...new Set(ipCandidates)].filter((ip) => ip.split(".").every((octet) => Number(octet) <= 255));
  const domainCandidates = text.match(/\b[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+\b/g) || [];
  const domains = [...new Set(domainCandidates)].filter((domain) => {
    const labels = domain.split(".");
    const isIPv4Candidate = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(domain);
    return !isIPv4Candidate && !labels.some((label) => label.startsWith("-") || label.endsWith("-")) && !/^\d+$/.test(labels.at(-1));
  });
  return { ips, domains, invalidIps: [...new Set(ipCandidates)].length - ips.length };
}

function analyzeAlert() {
  const text = input.value.trim();
  const error = document.getElementById("formError");
  if (!text) {
    error.textContent = "Add alert text before extracting indicators.";
    error.hidden = false;
    input.focus();
    return;
  }
  error.hidden = true;
  const result = extractIOCs(text);
  const indicators = [
    ...result.ips.map((value) => ({ type: "IPv4 address", value, validation: "Valid IPv4", valid: true })),
    ...result.domains.map((value) => ({ type: "Domain", value, validation: "Candidate", valid: false }))
  ];
  renderIndicators(indicators);
  document.getElementById("iocCount").textContent = indicators.length;
  document.getElementById("ipCount").textContent = result.ips.length;
  document.getElementById("domainCount").textContent = result.domains.length;
  document.getElementById("navIocCount").textContent = indicators.length;
  document.getElementById("tableCount").textContent = `${indicators.length} RESULT${indicators.length === 1 ? "" : "S"}`;
  document.getElementById("snapshotCaption").textContent = `${indicators.length} candidate indicator${indicators.length === 1 ? "" : "s"} · browser-side preview`;
  document.getElementById("snapshotTime").textContent = new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit" }).format(new Date()).toUpperCase();
  history.unshift({ count: indicators.length, ips: result.ips.length, domains: result.domains.length, time: new Date() });
  renderHistory();
  document.getElementById("indicators").scrollIntoView({ behavior: "smooth", block: "start" });
}

function renderIndicators(indicators) {
  const table = document.getElementById("iocTable");
  table.replaceChildren();
  if (!indicators.length) {
    const row = document.createElement("tr");
    row.className = "empty-row";
    const cell = document.createElement("td");
    cell.colSpan = 4;
    const icon = document.createElement("span"); icon.className = "empty-icon"; icon.textContent = "⌁";
    const title = document.createElement("b"); title.textContent = "No supported indicators found";
    const detail = document.createElement("small"); detail.textContent = "The preview currently extracts IPv4 addresses and domain candidates.";
    cell.append(icon, title, detail); row.append(cell); table.append(row); return;
  }
  for (const indicator of indicators) {
    const row = document.createElement("tr");
    const type = document.createElement("td");
    const typePill = document.createElement("span"); typePill.className = "type-pill"; typePill.textContent = indicator.type; type.append(typePill);
    const value = document.createElement("td"); value.textContent = indicator.value;
    const validation = document.createElement("td");
    const validationPill = document.createElement("span"); validationPill.className = `validation-pill ${indicator.valid ? "valid" : "candidate"}`; validationPill.textContent = indicator.validation; validation.append(validationPill);
    const verdict = document.createElement("td");
    const unknown = document.createElement("span"); unknown.className = "unknown-pill"; unknown.textContent = "UNKNOWN"; verdict.append(unknown);
    row.append(type, value, validation, verdict); table.append(row);
  }
}

function renderHistory() {
  const list = document.getElementById("historyList");
  list.replaceChildren();
  for (const item of history.slice(0, 5)) {
    const row = document.createElement("div"); row.className = "activity-item";
    const summary = document.createElement("div");
    const title = document.createElement("b"); title.textContent = `${item.count} candidate indicator${item.count === 1 ? "" : "s"}`;
    const detail = document.createElement("small"); detail.textContent = `${item.ips} IPv4 · ${item.domains} domain${item.domains === 1 ? "" : "s"}`;
    summary.append(title, detail);
    const time = document.createElement("time"); time.textContent = new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit" }).format(item.time);
    row.append(summary, time); list.append(row);
  }
}

const navLinks = [...document.querySelectorAll(".nav-link")];
const sectionLinks = new Map(navLinks.map((link) => [link.hash.slice(1), link]));
const observer = new IntersectionObserver((entries) => {
  const visible = entries.filter((entry) => entry.isIntersecting).sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
  if (!visible) return;
  navLinks.forEach((link) => link.classList.toggle("active", link === sectionLinks.get(visible.target.id)));
}, { rootMargin: "-15% 0px -70% 0px", threshold: [0, 0.25, 0.5] });
document.querySelectorAll("main > section[id]").forEach((section) => observer.observe(section));
