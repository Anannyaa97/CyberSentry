# 24-hour plan

Hour 0 = when you start. The project already works, so your time goes into **understanding, verifying, customizing and presenting**.
If you fall behind, skip the "optional" items - never skip testing or screenshots.

| Hours | Goal | Done when |
|---|---|---|
| 0 - 1 | **Setup**: extract the folder, open it in VS Code / IBM Bob, create `.venv`, install requirements | `streamlit run app.py` opens the dashboard |
| 1 - 2 | **Verify**: run `python -m pytest`; click every sidebar example | tests pass, you saw all 4 risk levels |
| 2 - 5 | **Understand the code**: read `config.py` -> `validator.py` -> `rules.py` -> `analyzer.py` -> `report.py` -> `app.py` (use prompt #1 in `BOB_PROMPTS.md`). Explain each file out loud in 2 sentences | you can trace one URL through the whole program |
| 5 - 8 | **Make it yours**: add 3-5 brands, tweak a few point values, add 1 new rule + tests (prompt #3) | pytest passes with your new tests |
| 8 - 9 | Break time / sleep buffer | |
| 9 - 12 | **Manual testing**: go through `docs/TESTING_CHECKLIST.md`; fix anything found (prompt #5) | checklist ticked, evidence log filled |
| 12 - 14 | **Screenshots** (6, see `docs/screenshots/README.md`) and uncomment them in the README | images in `docs/screenshots/` |
| 14 - 16 | **GitHub**: create the repo, push (commands in README), check the README renders | repo link works |
| 16 - 20 | **Presentation**: build slides from `docs/PRESENTATION_OUTLINE.md`; practice the demo twice | demo runs in under 5 minutes |
| 20 - 22 | **Q&A practice**: use prompt #8 in `BOB_PROMPTS.md`; review the questions table | you answer without reading |
| 22 - 24 | **Buffer**: final `pytest`, final README check (prompt #9), commit and push, backup copy of the folder | everything submitted |

## If time runs short

1. Must have: app runs, tests pass, 4 screenshots, README, GitHub link, 5-minute demo.
2. Should have: your own new rule + tests, evidence log, slides.
3. Nice to have: batch-mode demo, extra brands, deeper limitations discussion.
4. Postpone: machine learning, external APIs, databases, login, cloud deployment, log analyzer.
