# Testing checklist and evidence log

"Generated" is not "tested". Tick a box only after you actually did it, and write down what you saw.

## A. Automated tests

- [ ] `python -m pytest` -> all tests pass (write the count here: ______ passed)
- [ ] After any change (yours or Bob's), pytest was run again

## B. Manual tests in the app (`streamlit run app.py`)

**Single URL**
- [ ] Each sidebar example button analyzes and shows score, level, indicators, advice
- [ ] Typing `example.com` (no http) works and shows the note "HTTPS check was skipped"
- [ ] Pasting `hxxps://example[.]com/login` works
- [ ] Empty input -> friendly error, no crash
- [ ] `javascript:alert(1)` -> friendly error
- [ ] `http://exa mple.com` (space) -> friendly error
- [ ] A very long URL (5000 characters) -> friendly error or accepted up to the limit, no crash

**Batch mode**
- [ ] 3 valid lines -> summary table + one expander per URL
- [ ] 2 valid + 1 invalid line -> 2 results and a "Line 3: ..." error
- [ ] 26 lines -> warning about the limit

**Dashboard & export**
- [ ] Dashboard shows "No analyses yet" before the first analysis
- [ ] After several analyses: metrics, level chart, score chart, indicator chart, history table
- [ ] CSV downloads and opens in Excel; columns look right; `@evil.com` cell starts with `'`
- [ ] Clear history empties everything
- [ ] Refreshing the browser page starts a new empty session (expected)

**Safety**
- [ ] Analyzed URLs are shown as plain text (not clickable)
- [ ] `![x](http://evil.example/a.png)` as input does not display an image
- [ ] The terminal shows no network activity caused by analyzing URLs

## C. Evidence log (fill in as you go)

| Date/time | Feature or change | Written by (me / Bob / Claude) | How I tested it | Result | Notes |
|---|---|---|---|---|---|
| | Project set up, pytest run | | `python -m pytest` | | |
| | | | | | |
| | | | | | |

## D. Known limitations to mention (already documented in README)

- [ ] I can explain one false positive and one false negative from `docs/TEST_URLS.md`
