// SafeSurf - core security logic (pure functions, no page access)
// Works in the browser and in Node (for testing).

const COMMON_PASSWORDS = [
  "password", "123456", "12345678", "123456789", "qwerty", "abc123", "111111",
  "password1", "iloveyou", "admin", "welcome", "letmein", "monkey", "dragon",
  "football", "login", "princess", "sunshine", "master", "hello", "freedom",
  "whatever", "qazwsx", "trustno1", "654321", "superman", "1234567", "12345",
  "passw0rd", "p@ssw0rd", "india123", "qwerty123", "000000", "1q2w3e4r",
  "admin123", "root", "test", "guest", "changeme", "default"
];

const KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"];

function charPoolSize(pw) {
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/[0-9]/.test(pw)) pool += 10;
  if (/[^A-Za-z0-9]/.test(pw)) pool += 32;
  return pool;
}

function hasSequence(pw) {
  const lower = pw.toLowerCase();
  for (let i = 0; i + 2 < lower.length; i++) {
    const a = lower.charCodeAt(i), b = lower.charCodeAt(i + 1), c = lower.charCodeAt(i + 2);
    if ((b - a === 1 && c - b === 1) || (a - b === 1 && b - c === 1)) return true;
  }
  for (const row of KEYBOARD_ROWS) {
    for (let i = 0; i + 3 <= row.length; i++) {
      const chunk = row.slice(i, i + 3);
      if (lower.includes(chunk) || lower.includes(chunk.split("").reverse().join(""))) return true;
    }
  }
  return false;
}

function formatDuration(seconds) {
  if (!isFinite(seconds)) return "centuries beyond counting";
  if (seconds < 1) return "instantly";
  const units = [
    ["year", 31557600], ["day", 86400], ["hour", 3600], ["minute", 60], ["second", 1]
  ];
  if (seconds >= 31557600 * 1e9) return "billions of years";
  if (seconds >= 31557600 * 1e6) return "millions of years";
  if (seconds >= 31557600 * 1000) return Math.round(seconds / 31557600 / 1000) + " thousand years";
  for (const [name, size] of units) {
    if (seconds >= size) {
      const n = Math.floor(seconds / size);
      return n + " " + name + (n > 1 ? "s" : "");
    }
  }
  return "instantly";
}

// Assumes an attacker with fast hardware: 10 billion guesses per second.
const GUESSES_PER_SECOND = 1e10;

function analyzePassword(pw) {
  const checks = [];
  const isCommon = COMMON_PASSWORDS.includes(pw.toLowerCase());
  const repeats = /(.)\1{2,}/.test(pw);
  const sequence = hasSequence(pw);

  checks.push({ ok: pw.length >= 12, text: "At least 12 characters" });
  checks.push({ ok: /[a-z]/.test(pw), text: "Has lowercase letters" });
  checks.push({ ok: /[A-Z]/.test(pw), text: "Has uppercase letters" });
  checks.push({ ok: /[0-9]/.test(pw), text: "Has numbers" });
  checks.push({ ok: /[^A-Za-z0-9]/.test(pw), text: "Has symbols (!@#$...)" });
  checks.push({ ok: !isCommon, text: "Not a commonly used password" });
  checks.push({ ok: !repeats, text: "No repeated characters (aaa, 111)" });
  checks.push({ ok: !sequence, text: "No simple sequences (abc, 123, qwe)" });

  // "Name@2005" style: one short word followed by digits/symbols (very common, easy to guess)
  const wordPlusNumber = /^[A-Za-z]{3,10}[\W_]*\d{1,6}[\W_]*$/.test(pw);
  checks.push({ ok: !wordPlusNumber, text: "Not just a single word plus numbers (Rahul@2005)" });

  let entropy = pw.length * Math.log2(Math.max(charPoolSize(pw), 1));
  if (repeats) entropy -= 10;
  if (sequence) entropy -= 10;
  if (wordPlusNumber) entropy = Math.min(entropy, 30);
  if (isCommon) entropy = Math.min(entropy, 8);
  entropy = Math.max(0, Math.round(entropy));

  const crackSeconds = Math.pow(2, entropy) / 2 / GUESSES_PER_SECOND;

  let level, label;
  if (pw.length === 0) { level = 0; label = "Type a password"; }
  else if (entropy < 40) { level = 1; label = "Very weak"; }
  else if (entropy < 60) { level = 2; label = "Weak"; }
  else if (entropy < 80) { level = 3; label = "Good"; }
  else { level = 4; label = "Strong"; }

  return { entropy, crackSeconds, crackTime: formatDuration(crackSeconds), level, label, checks, isCommon };
}

function generatePassword(length, useSymbols) {
  const lower = "abcdefghijkmnopqrstuvwxyz";
  const upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
  const digits = "23456789";
  const symbols = "!@#$%^&*-_=+?";
  const groups = [lower, upper, digits];
  if (useSymbols) groups.push(symbols);
  const all = groups.join("");

  function randInt(max) {
    const limit = Math.floor(0x100000000 / max) * max;
    const buf = new Uint32Array(1);
    do { globalThis.crypto.getRandomValues(buf); } while (buf[0] >= limit);
    return buf[0] % max;
  }

  const out = groups.map(g => g[randInt(g.length)]); // one of each type
  while (out.length < length) out.push(all[randInt(all.length)]);
  for (let i = out.length - 1; i > 0; i--) { // shuffle
    const j = randInt(i + 1);
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out.join("");
}

// ---------------- Phishing URL analysis ----------------

const BRANDS = {
  google: ["google.com", "google.co.in"],
  paypal: ["paypal.com"],
  amazon: ["amazon.com", "amazon.in"],
  facebook: ["facebook.com"],
  microsoft: ["microsoft.com", "live.com", "office.com"],
  apple: ["apple.com", "icloud.com"],
  netflix: ["netflix.com"],
  instagram: ["instagram.com"],
  whatsapp: ["whatsapp.com"],
  paytm: ["paytm.com"],
  flipkart: ["flipkart.com"],
  github: ["github.com"],
  linkedin: ["linkedin.com"],
  hdfcbank: ["hdfcbank.com"],
  icicibank: ["icicibank.com"],
  onlinesbi: ["onlinesbi.sbi", "sbi.co.in"]
};

const SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at"];
const RISKY_TLDS = ["zip", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "country", "work", "loan", "icu", "buzz"];
const KEYWORDS = ["login", "signin", "verify", "secure", "update", "account", "confirm", "password", "bank", "wallet", "bonus", "prize", "gift", "free", "suspend", "unlock", "otp", "kyc"];

function registrableDomain(host) {
  const p = host.split(".");
  if (p.length <= 2) return host;
  const secondLevel = ["co", "com", "org", "net", "gov", "ac", "edu"];
  if (p[p.length - 1].length === 2 && secondLevel.includes(p[p.length - 2])) return p.slice(-3).join(".");
  return p.slice(-2).join(".");
}

function levenshtein(a, b) {
  const dp = Array.from({ length: a.length + 1 }, (_, i) => [i]);
  for (let j = 1; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)
      );
    }
  }
  return dp[a.length][b.length];
}

function normalizeLeet(s) {
  return s.replace(/0/g, "o").replace(/1/g, "l").replace(/3/g, "e").replace(/5/g, "s").replace(/@/g, "a").replace(/\$/g, "s");
}

function analyzeUrl(raw) {
  const input = (raw || "").trim();
  if (!input) return null;

  const hasScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(input);
  let url;
  try {
    url = new URL(hasScheme ? input : "http://" + input);
  } catch (e) {
    return { error: "That does not look like a valid URL." };
  }

  const findings = [];
  let score = 0;
  const bad = (pts, text) => { score += pts; findings.push({ level: "bad", text }); };
  const warn = (pts, text) => { score += pts; findings.push({ level: "warn", text }); };
  const ok = text => findings.push({ level: "ok", text });

  const host = url.hostname.toLowerCase();
  const full = (url.hostname + url.pathname + url.search).toLowerCase();
  const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
  const reg = isIp ? host : registrableDomain(host);

  if (url.protocol !== "https:") bad(15, "Does not use HTTPS, so data is not encrypted.");
  else ok("Uses HTTPS (but HTTPS alone does not prove a site is safe).");

  if (isIp) bad(30, "Uses a raw IP address instead of a domain name.");
  if (url.username || url.password) bad(25, "Contains '@' or login info before the host, a trick to hide the real site.");
  if (host.includes("xn--")) bad(25, "Uses punycode (xn--), which can disguise lookalike characters.");
  if (SHORTENERS.includes(host)) warn(20, "Link shortener hides the real destination.");

  const labelCount = host.split(".").length;
  if (labelCount > 4) warn(15, "Too many subdomains (" + labelCount + " parts).");
  if ((host.match(/-/g) || []).length >= 3) warn(10, "Many hyphens in the domain name.");
  if ((host.match(/[0-9]/g) || []).length >= 4 && !/^\d/.test(host)) warn(10, "Many digits in the domain name.");
  if (input.length > 75) warn(10, "Very long URL (" + input.length + " characters).");
  if (url.port && url.port !== "80" && url.port !== "443") warn(10, "Uses an unusual port (" + url.port + ").");

  const tld = host.split(".").pop();
  if (RISKY_TLDS.includes(tld)) warn(15, "Uses a '." + tld + "' ending often seen in scam sites.");

  const foundWords = KEYWORDS.filter(k => full.includes(k));
  if (foundWords.length) {
    warn(Math.min(foundWords.length * 8, 24), "Contains pressure words: " + foundWords.slice(0, 5).join(", ") + ".");
  }

  // Brand impersonation
  let brandFlag = false;
  const baseLabel = reg.split(".")[0];
  const normBase = normalizeLeet(baseLabel);
  for (const brand of Object.keys(BRANDS)) {
    const official = BRANDS[brand].includes(reg);
    if (official) continue;
    if (host.includes(brand)) {
      bad(30, "Mentions '" + brand + "' but the real domain is '" + reg + "'.");
      brandFlag = true;
      break;
    }
    if (!isIp && normalizeLeet(host).includes(brand)) {
      bad(35, "Uses look-alike characters (like 1 for l) to imitate '" + brand + "'.");
      brandFlag = true;
      break;
    }
    if (!isIp && brand.length >= 5 && (normBase === brand || levenshtein(normBase, brand) === 1) && baseLabel !== brand) {
      bad(35, "'" + baseLabel + "' looks like a fake copy of '" + brand + "' (typosquatting).");
      brandFlag = true;
      break;
    }
  }
  if (!brandFlag) ok("No known brand impersonation detected.");

  score = Math.min(score, 100);
  let verdict, color;
  if (score < 25) { verdict = "Low risk"; color = "good"; }
  else if (score < 55) { verdict = "Suspicious"; color = "warn"; }
  else { verdict = "High risk - likely phishing"; color = "bad"; }

  return { score, verdict, color, host, domain: reg, findings };
}

if (typeof module !== "undefined") {
  module.exports = { analyzePassword, analyzeUrl, generatePassword, formatDuration, registrableDomain, levenshtein };
}
