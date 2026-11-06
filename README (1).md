# 🛡️ SafeSurf - Cyber Safety Toolkit

SafeSurf is a free, browser-based toolkit that helps students and everyday users protect themselves online. Everything runs locally in the browser. No account, no server, and no data is stored or sent anywhere (except the optional breach check, which uses a privacy-preserving method described below).

## The problem
Most cyber attacks on students and beginners succeed because of weak passwords, phishing links and low awareness, not because of advanced hacking.

## Our solution
Five tools in one simple website:

| Tool | What it does |
|------|--------------|
| 🔑 Password Analyzer | Calculates entropy and estimated crack time, flags common passwords, repeats, sequences and "Name@2005" style patterns |
| 🔍 Breach Check | Checks if a password appears in known data breaches using the Have I Been Pwned range API with k-anonymity (only the first 5 characters of the SHA-1 hash are sent) |
| 🎣 Phishing Link Analyzer | Scores a URL's risk using rules: no HTTPS, IP address hosts, `@` tricks, punycode, typosquatting and brand impersonation (leetspeak and Levenshtein distance), risky endings, shorteners, pressure words |
| #️⃣ Hash and File Integrity | Generates SHA-256/512/1 hashes and verifies a downloaded file against an expected hash |
| 🔒 Encrypt / Decrypt | AES-256-GCM encryption with a key derived from a passphrase using PBKDF2 (150,000 rounds, random salt and IV) |
| 🧠 Security Quiz | 8 real-life scenario questions with explanations and a Cyber Safety Score |

## Tech stack
HTML, CSS, JavaScript (no frameworks). Web Crypto API for hashing and encryption.

## Project structure
- `index.html` - page layout
- `style.css` - styling
- `logic.js` - security logic (password and URL analysis), testable in Node
- `script.js` - connects the logic to the page

## How to run
Open the live GitHub Pages link, or download the repo and open `index.html`.
(Hashing, encryption and the breach check need `https://` or `localhost`, so the GitHub Pages link is the best way to use all features.)

## Security design notes
- Passwords are never stored or transmitted.
- Breach check uses k-anonymity, so the full password or hash is never sent.
- Encryption uses an authenticated mode (AES-GCM), so tampered text fails to decrypt.
- User input is displayed with `textContent`, never `innerHTML`, to prevent XSS.

## Limitations
- The phishing analyzer is rule-based, not a guarantee. It gives a risk estimate to help users decide.
- Crack time assumes 10 billion guesses per second and is only an estimate.

## Future scope
- Browser extension that warns about risky links automatically
- Machine-learning phishing detection trained on real datasets
- Email header analyzer
- Multi-language support for wider awareness

## Team
- Member 1 - Logic and code
- Member 2 - Design and testing
- Member 3 - Presentation and research
