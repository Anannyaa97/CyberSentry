# Prompts for IBM Bob

IBM Bob writes and edits code **inside your project folder**. Open the `CyberSentry` folder in Bob and paste these prompts.
Bob cannot see your ChatGPT/Claude chats, so each prompt carries the rules it needs.

## The golden rule: generated is not tested

Code that Bob wrote is only a *draft* until you have **run it**. After every Bob change:

1. Run `python -m pytest` - all tests must pass.
2. Run `streamlit run app.py` and try the feature by hand.
3. Look at what changed (Source Control panel in VS Code - the diff). If you don't understand a change, ask Bob to explain it.
4. Write the result in `docs/TESTING_CHECKLIST.md` (evidence log).

## Guardrails - paste this at the start of EVERY prompt

```text
Project rules for CyberSentry (a beginner-friendly phishing URL analyzer in Python + Streamlit):
- NEVER visit, fetch, resolve or send any submitted URL to any service. No network calls, no external APIs.
- Treat all input as untrusted. Never put raw user text into st.markdown without cybersentry.report.escape_markdown.
- Keep it simple and beginner-readable: small functions, clear names, comments that explain WHY.
- Minimal dependencies: only streamlit, pandas, pytest (plus the standard library). Do not add new packages without asking.
- The risk score is a heuristic, NOT a probability. Never describe it as a probability or as proof of safety/maliciousness.
- Scoring numbers live in cybersentry/config.py; rule logic lives in cybersentry/rules.py.
- Every change needs a test in tests/. Run `python -m pytest` before and after and show me the output.
- Explain what you changed in simple language when you are done.
```

---

## 1. Understand the project (do this first)

```text
Read the whole CyberSentry project. Explain it to a beginner: what each file does, how a URL travels from the text box
in app.py through validator.py, rules.py and analyzer.py to the result on screen, and how the CSV export works.
Use a short example URL. Finish with a list of the 5 most important ideas I should be able to explain in a presentation.
Do not change any files.
```

## 2. Set up and verify

```text
Check that the project runs: create/use the .venv, install requirements.txt, run `python -m pytest`, then start
`streamlit run app.py`. Report exactly what passed or failed. Fix only real errors, and explain each fix.
```

## 3. Add a new detection rule

```text
[paste the guardrails]
Add a new rule: <describe it, e.g. "flag hosts where more than 40% of the characters are digits">.
Follow the 4 steps in README.md "Extending the project": a check_ function in cybersentry/rules.py returning an Indicator or None,
points in POINTS (config.py), a Rule entry in RULES (with a description and advice), and tests in tests/test_analyzer.py
(one test where it fires, one where it must not fire). Keep points small (5-15). Run the tests and show me the output.
Then tell me one possible false positive of this rule.
```

## 4. Add more brands or keywords

```text
[paste the guardrails]
Add these brands to BRANDS in cybersentry/config.py with their official domains: <list>. Brand names must be at least 5 letters.
Add one test that an official domain does not trigger the rule and one that a fake domain does. Run pytest.
```

## 5. Fix a bug

```text
[paste the guardrails]
I have a bug. What I did: <steps>. What I expected: <...>. What happened instead: <...>.
Error message / terminal output:
<paste the full output>
First explain the cause in simple words. Then write a failing test that reproduces it, fix the code, and show that the whole test suite passes.
```

## 6. Improve the dashboard

```text
[paste the guardrails]
In app.py, <describe the change, e.g. "add a filter above the history table to show only High and Critical rows">.
Do not break the existing features: single URL, batch mode, history, charts, CSV download. Keep URLs displayed as plain text
(never as links). Run pytest (tests/test_app_smoke.py covers the UI) and tell me how to check it by hand.
```

## 7. Security review (great for your report)

```text
Review CyberSentry for security problems in the way it handles untrusted URL input: input validation, error messages,
display of URLs (Markdown/HTML injection), CSV injection, denial of service by huge input, and anything that could
cause a network request. List findings by severity with the file and line, explain each in simple words, and propose
small fixes. Do not change files until I approve.
```

## 8. Check my understanding

```text
Quiz me on this project like a bootcamp examiner. Ask one question at a time about the code (validation, a rule, scoring,
CSV export, limitations). After each answer tell me what was right, what was missing, and the short correct explanation.
```

## 9. Final polish

```text
Check README.md for accuracy against the real code (features, commands, file names, test count, rule table, limitations).
List anything wrong or missing. Do not invent features. Do not change code.
```
