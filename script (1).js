// SafeSurf - page behaviour (uses functions from logic.js)

const $ = id => document.getElementById(id);

function clearNode(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

function addEl(parent, tag, cls, text) {
  const el = document.createElement(tag);
  if (cls) el.className = cls;
  if (text !== undefined) el.textContent = text;
  parent.appendChild(el);
  return el;
}

const COLORS = { 0: "#24314d", 1: "#ef4444", 2: "#f59e0b", 3: "#84cc16", 4: "#22c55e" };

// ---------- Tabs ----------
document.querySelectorAll(".tab").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".panel").forEach(p => p.classList.remove("active"));
    btn.classList.add("active");
    $(btn.dataset.tab).classList.add("active");
  });
});

// ---------- Crypto helpers ----------
const encoder = new TextEncoder();
const decoder = new TextDecoder();

function toHex(buffer) {
  return Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2, "0")).join("");
}

async function digest(algo, data) {
  return toHex(await crypto.subtle.digest(algo, data));
}

function toBase64(bytes) {
  let s = "";
  bytes.forEach(b => { s += String.fromCharCode(b); });
  return btoa(s);
}

function fromBase64(str) {
  const s = atob(str.trim());
  const bytes = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) bytes[i] = s.charCodeAt(i);
  return bytes;
}

function needSecureContext() {
  if (!window.crypto || !crypto.subtle) {
    alert("This feature needs a secure page. Open the https:// GitHub Pages link instead of a local file.");
    return true;
  }
  return false;
}

// ---------- Password tab ----------
function updatePassword() {
  const pw = $("pw").value;
  const r = analyzePassword(pw);
  $("pw-bar").style.width = (pw.length === 0 ? 0 : r.level * 25) + "%";
  $("pw-bar").style.background = COLORS[r.level];
  $("pw-label").textContent = r.label;
  $("pw-entropy").textContent = pw.length ? r.entropy : 0;
  $("pw-crack").textContent = pw.length ? r.crackTime : "-";
  $("breach-result").textContent = "";
  $("breach-result").className = "result";

  const list = $("pw-checks");
  clearNode(list);
  if (pw.length === 0) return;
  r.checks.forEach(c => addEl(list, "li", c.ok ? "ok" : "no", c.text));
}

$("pw").addEventListener("input", updatePassword);

$("pw-toggle").addEventListener("click", () => {
  const input = $("pw");
  const show = input.type === "password";
  input.type = show ? "text" : "password";
  $("pw-toggle").textContent = show ? "Hide" : "Show";
});

$("breach-btn").addEventListener("click", async () => {
  const out = $("breach-result");
  const pw = $("pw").value;
  if (!pw) { out.className = "result warn"; out.textContent = "Type a password first."; return; }
  if (needSecureContext()) return;

  out.className = "result"; out.textContent = "Checking...";
  try {
    const hash = (await digest("SHA-1", encoder.encode(pw))).toUpperCase();
    const prefix = hash.slice(0, 5), suffix = hash.slice(5);
    const res = await fetch("https://api.pwnedpasswords.com/range/" + prefix);
    if (!res.ok) throw new Error("bad response");
    const text = await res.text();
    const line = text.split("\n").find(l => l.split(":")[0].trim() === suffix);
    if (line) {
      const count = Number(line.split(":")[1]).toLocaleString();
      out.className = "result bad";
      out.textContent = "Found in " + count + " known data breaches. Never use this password.";
    } else {
      out.className = "result good";
      out.textContent = "Not found in known breaches. Good sign!";
    }
  } catch (e) {
    out.className = "result warn";
    out.textContent = "Could not reach the breach database. Check your internet and try again.";
  }
});

// Generator
$("gen-len").addEventListener("input", () => { $("gen-len-val").textContent = $("gen-len").value; });
$("gen-btn").addEventListener("click", () => {
  $("gen-out").value = generatePassword(Number($("gen-len").value), $("gen-symbols").checked);
});
$("gen-copy").addEventListener("click", async () => {
  const v = $("gen-out").value;
  if (!v) return;
  try {
    await navigator.clipboard.writeText(v);
    $("gen-copy").textContent = "Copied!";
  } catch (e) {
    $("gen-out").select();
    document.execCommand("copy");
    $("gen-copy").textContent = "Copied!";
  }
  setTimeout(() => { $("gen-copy").textContent = "Copy"; }, 1500);
});

// ---------- Phishing tab ----------
function runUrlCheck() {
  const r = analyzeUrl($("url-in").value);
  const box = $("url-out");
  if (!r) { box.hidden = true; return; }
  box.hidden = false;

  const list = $("url-findings");
  clearNode(list);

  if (r.error) {
    $("url-verdict").textContent = r.error;
    $("url-score").textContent = "-";
    $("url-domain").textContent = "-";
    $("url-bar").style.width = "0%";
    return;
  }

  const barColor = { good: "#22c55e", warn: "#f59e0b", bad: "#ef4444" }[r.color];
  $("url-bar").style.width = Math.max(r.score, 4) + "%";
  $("url-bar").style.background = barColor;
  $("url-verdict").textContent = r.verdict;
  $("url-verdict").style.color = barColor;
  $("url-score").textContent = r.score;
  $("url-domain").textContent = r.domain;
  r.findings.forEach(f => addEl(list, "li", f.level, f.text));
}

$("url-btn").addEventListener("click", runUrlCheck);
$("url-in").addEventListener("keydown", e => { if (e.key === "Enter") runUrlCheck(); });
document.querySelectorAll(".sample").forEach(a => {
  a.addEventListener("click", e => {
    e.preventDefault();
    $("url-in").value = a.textContent;
    runUrlCheck();
  });
});

// ---------- Hash tab ----------
$("hash-in").addEventListener("input", async () => {
  const text = $("hash-in").value;
  if (!text) { $("h256").textContent = $("h512").textContent = $("h1").textContent = "-"; return; }
  if (needSecureContext()) return;
  const data = encoder.encode(text);
  $("h256").textContent = await digest("SHA-256", data);
  $("h512").textContent = await digest("SHA-512", data);
  $("h1").textContent = await digest("SHA-1", data);
});

let fileHash = "";
function compareFileHash() {
  const out = $("file-result");
  const expected = $("expected").value.trim().toLowerCase();
  if (!fileHash || !expected) { out.textContent = ""; out.className = "result"; return; }
  if (expected === fileHash) {
    out.className = "result good";
    out.textContent = "Match! The file is intact and unchanged.";
  } else {
    out.className = "result bad";
    out.textContent = "MISMATCH! The file was changed or is not the original.";
  }
}

$("file-in").addEventListener("change", async () => {
  const file = $("file-in").files[0];
  if (!file) return;
  if (needSecureContext()) return;
  $("file-hash").textContent = "Calculating...";
  fileHash = await digest("SHA-256", await file.arrayBuffer());
  $("file-hash").textContent = fileHash;
  compareFileHash();
});
$("expected").addEventListener("input", compareFileHash);

// ---------- Encrypt tab ----------
async function deriveKey(passphrase, salt) {
  const baseKey = await crypto.subtle.importKey("raw", encoder.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 150000, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

function setStatus(text, cls) {
  $("enc-status").textContent = text;
  $("enc-status").className = "result " + (cls || "");
}

$("enc-btn").addEventListener("click", async () => {
  const text = $("enc-text").value, pass = $("enc-pass").value;
  if (!text || !pass) { setStatus("Enter text and a passphrase.", "warn"); return; }
  if (needSecureContext()) return;
  try {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(pass, salt);
    const cipher = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(text)));
    const packed = new Uint8Array(salt.length + iv.length + cipher.length);
    packed.set(salt, 0);
    packed.set(iv, salt.length);
    packed.set(cipher, salt.length + iv.length);
    $("enc-out").value = toBase64(packed);
    setStatus("Encrypted. Share the text and tell the passphrase separately.", "good");
  } catch (e) {
    setStatus("Encryption failed.", "bad");
  }
});

$("dec-btn").addEventListener("click", async () => {
  const text = $("enc-text").value, pass = $("enc-pass").value;
  if (!text || !pass) { setStatus("Paste encrypted text and enter the passphrase.", "warn"); return; }
  if (needSecureContext()) return;
  try {
    const packed = fromBase64(text);
    const salt = packed.slice(0, 16), iv = packed.slice(16, 28), cipher = packed.slice(28);
    const key = await deriveKey(pass, salt);
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, cipher);
    $("enc-out").value = decoder.decode(plain);
    setStatus("Decrypted successfully.", "good");
  } catch (e) {
    $("enc-out").value = "";
    setStatus("Failed: wrong passphrase or the text was changed.", "bad");
  }
});

// ---------- Quiz tab ----------
const QUIZ = [
  { q: "You get an SMS: 'Your bank account is blocked, click this link to verify now.' What do you do?",
    o: ["Click and enter details quickly", "Ignore it and contact the bank using its official app or number", "Forward it to friends"],
    a: 1, e: "Banks never ask for details through links. Urgency is a classic phishing trick." },
  { q: "Which password is the best choice?",
    o: ["Rahul@2005", "qwerty123", "Mango-Train-Pencil-Cloud-84"],
    a: 2, e: "Long passphrases of random words are much harder to crack than short 'clever' passwords." },
  { q: "What does two-factor authentication (2FA) add?",
    o: ["A second proof of identity besides your password", "Faster login", "A longer password"],
    a: 0, e: "Even if your password leaks, attackers still need your second factor." },
  { q: "Is it safe to do online banking on free public Wi-Fi without protection?",
    o: ["Yes, always", "No, attackers on the same network may spy on traffic", "Only on weekends"],
    a: 1, e: "Use mobile data or a trusted VPN, and only visit HTTPS sites." },
  { q: "You find a USB drive in the college parking lot. What should you do?",
    o: ["Plug it in to find the owner", "Hand it to the IT team without plugging it in", "Format it and use it"],
    a: 1, e: "Unknown USB drives can carry malware that runs automatically." },
  { q: "Is reusing one password on many websites a good idea?",
    o: ["Yes, easier to remember", "No, one breach exposes all your accounts", "Yes, if it is long"],
    a: 1, e: "Attackers try leaked passwords on other sites (credential stuffing). Use a password manager." },
  { q: "A site shows a padlock and https://. Does this prove it is safe?",
    o: ["Yes, it is always safe", "No, it only means the connection is encrypted", "Yes, if it is a .com"],
    a: 1, e: "Phishing sites can use HTTPS too. Always check the domain name." },
  { q: "What is the best reaction to a software update prompt?",
    o: ["Postpone it for months", "Install updates from official sources promptly", "Download updates from random sites"],
    a: 1, e: "Updates fix security holes that attackers actively exploit." }
];

let quizAnswers = [];
let quizDone = 0;

function renderQuiz() {
  const box = $("quiz-box");
  clearNode(box);
  quizAnswers = new Array(QUIZ.length).fill(null);
  quizDone = 0;

  QUIZ.forEach((item, qi) => {
    const wrap = addEl(box, "div", "q");
    addEl(wrap, "h3", "", (qi + 1) + ". " + item.q);
    const buttons = item.o.map((text, oi) => {
      const b = addEl(wrap, "button", "opt", text);
      b.addEventListener("click", () => {
        if (quizAnswers[qi] !== null) return;
        quizAnswers[qi] = oi;
        quizDone++;
        buttons.forEach((btn, i) => {
          if (i === item.a) btn.classList.add("right");
          else if (i === oi) btn.classList.add("wrong");
        });
        addEl(wrap, "p", "explain", (oi === item.a ? "Correct! " : "Not quite. ") + item.e);
        if (quizDone === QUIZ.length) showQuizResult();
      });
      return b;
    });
  });
}

function showQuizResult() {
  const box = $("quiz-box");
  const score = quizAnswers.filter((a, i) => a === QUIZ[i].a).length;
  const pct = Math.round((score / QUIZ.length) * 100);
  let rating;
  if (pct >= 88) rating = "Cyber Champion! You are hard to fool.";
  else if (pct >= 63) rating = "Pretty safe, but review the tips above.";
  else rating = "Beginner. Read the explanations and try again.";

  const result = addEl(box, "div", "q");
  addEl(result, "p", "label", "Your Cyber Safety Score");
  addEl(result, "div", "bigscore", score + " / " + QUIZ.length + " (" + pct + "%)");
  addEl(result, "p", "", rating);
  const again = addEl(result, "button", "", "Try again");
  again.addEventListener("click", renderQuiz);
  result.scrollIntoView({ behavior: "smooth" });
}

renderQuiz();
updatePassword();
