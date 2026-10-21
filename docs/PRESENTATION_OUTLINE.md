# Bootcamp presentation outline (about 10 minutes + demo + questions)

Replace the `[brackets]`. Put your own screenshots on the slides (see `docs/screenshots/README.md`).

## Slides

**1. Title**
- CyberSentry - Explainable Phishing & Security Threat Analyzer
- [Your name], [bootcamp name], [date]

**2. The problem**
- Phishing links are the most common way attackers start an attack. People see only the beginning of a link.
- Most tools say "safe" or "dangerous" with no reason - users don't learn and can't judge false alarms.
- Goal: **explain why** a URL looks suspicious.

**3. What CyberSentry does**
- You paste a URL -> a score from 0 to 100, a risk level, the indicators found with reasons, and advice.
- Runs locally. It only reads the **text** of the URL. It never opens it.
- Python + Streamlit + Pandas, standard-library `urllib.parse` and `ipaddress`.

**4. How it works (architecture)**
- Diagram: Text box -> `validator.py` -> `rules.py` (16 rules) -> `analyzer.py` (score + level + advice) -> dashboard / CSV.
- One file = one job. All numbers are in `config.py`.

**5. Transparent scoring**
- Score = sum of the points of the rules that fired, capped at 100. Nothing hidden, nothing subtracted.
- Levels: Low 0-19, Medium 20-44, High 45-69, Critical 70+.
- It is a heuristic, **not a probability**.

**6. Example rules (pick 4)**
- IP address instead of a domain (`http://45.12.30.77/...`)
- The `@` trick (`http://paypal.com@evil.example`)
- Look-alike spelling (`paypa1.com`, `rnicrosoft.com`)
- Brand inside someone else's domain (`paypal.com.account-verify.example.net`)

**7. Live demo** (script below)

**8. Security of the tool itself**
- Never visits URLs, no external services, input validated and length-limited.
- Output escaped (no Markdown/image injection), URLs shown as text, defanged copies in reports.
- CSV injection protection (cells starting with `= + - @`).

**9. Testing**
- [111] automated tests: validation, every rule, score boundaries, CSV export, the UI (`AppTest`).
- Tests that document limitations on purpose (false positive / false negative).
- Show the green `pytest` output.

**10. Limitations (be honest - examiners like this)**
- Low score != safe (brand-new clean-looking domain, hacked legit site, short links hide the target).
- High score != malicious (`pineapple.com` matches "apple"; honest long/tracking links).
- Only the URL text: no page content, no reputation, no domain age. Small demo lists.

**11. What I learned / future work**
- Learned: [URL structure, phishing tricks, writing testable rules, Streamlit, working with an AI coding assistant and verifying its output].
- Next: more brands, Public Suffix List, optional offline log analyzer, optional ML as a second opinion.

**12. Thank you / questions**
- GitHub link: [https://github.com/<you>/CyberSentry]

## Demo script (4-5 minutes)

Use the sidebar example buttons so there is no typing risk.

1. **Ordinary website** -> Low, 0. "No rule matched, but this does not prove it's safe."
2. **Look-alike brand** (`paypa1`) -> Medium. Read one explanation aloud: swapping `1` for `l`.
3. **The '@' trick** -> High. "The browser goes to what is *after* the @."
4. **Fake brand page** -> Critical, 95. Scroll the indicators: each one has points and a reason. Point out "score capped at 100" is not hit here, the sum is the score.
5. Open **Analyze several URLs**, paste 3 lines including one invalid (`javascript:alert(1)`) -> show the friendly error.
6. **Dashboard & history** tab -> metrics, charts, "Most common indicators".
7. **Download CSV report** -> open it in Excel: defanged URLs, explanations.
8. **How it works** tab -> rules table and the limitations section.
9. Terminal: `python -m pytest` -> all green.

Backup plan: if the app won't start, show your screenshots and the pytest output.

## Questions you may get (and short answers)

| Question | Answer |
|---|---|
| Why not machine learning? | Rules are transparent: every point has a reason. That is the goal. ML could be a second opinion later, but would be harder to explain. |
| Is the score a probability? | No. It is a count of weighted warning signs. It was never calibrated against real data. |
| What if it says Low for a phishing site? | That is a false negative. Rules only see the URL text. Always check the sender and context. |
| What if it says High for a normal site? | False positive, e.g. `pineapple.com` matches "apple". Heuristics trade accuracy for explainability. |
| Does it open the links? | Never. It only reads characters, so analyzing a malicious link is safe. |
| How did you choose the points? | By how strongly each sign is linked to phishing (IP host, `@` high; HTTP, long URL low). They are my judgment, editable in `config.py`. |
| What is defanging? | Writing `hxxp://example[.]com` so a link can't be clicked by accident in reports. |
| What is CSV injection? | Excel runs cells starting with `=`, `+`, `-`, `@` as formulas. We prefix them with an apostrophe. |
| What is a homograph attack? | Letters from other alphabets that look the same, e.g. Cyrillic `а` vs Latin `a` (`xn--` in punycode). |
| How did you use AI? | [Bob wrote drafts, I reviewed each change, ran the tests, and can explain every module.] |
| What would you improve? | Public Suffix List, bigger brand list, domain-age/reputation lookups (opt-in, since they send data), more tests. |
