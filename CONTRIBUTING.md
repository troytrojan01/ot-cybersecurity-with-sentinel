# Contributing

Contributions welcome — issues, queries, or generator improvements.

## Adding a new KQL query

1. Pick the right folder based on intent:
   - `exploration/` — confirm data is flowing, sanity checks
   - `parsers/` — reusable functions (must be saveable as Sentinel functions)
   - `detections/` — analytics-rule-shaped, fires on specific conditions
   - `hunting/` — open-ended, analyst-driven
   - `operations/` — pipeline health, cost, parser-quality
2. File naming: `NN-short-name.kql` where NN is a two-digit sort order.
3. Header comment block should explain:
   - What the query does in plain English
   - Suggested cadence/severity if it's a detection
   - Any parser functions it depends on
4. Time filter goes first in the pipeline — `where TimeGenerated > ago(Nm)` before anything else.

## Adding generator content

Event templates live near the top of `generator/ot_log_generator.py` in the `DRAGOS_NOTIFICATIONS`, `EYEINSPECT_ALERTS`, and `EYESEGMENT_VIOLATIONS` tuples. Match the existing tuple shape — the rest of the generator picks up new entries automatically.

For a new platform entirely, you'll need a triplet of functions: `gen_<platform>_event`, `render_<platform>_cef`, `render_<platform>_json`, registered in the `PLATFORMS` dict near the bottom of the file.

## Running tests

The generator has no automated test suite yet — the smoke test is:

```bash
python3 generator/ot_log_generator.py --count 30 --seed 1 --out-dir /tmp/test_out
head -3 /tmp/test_out/dragos.cef.log
```

Eyeball the output — RFC 3164 framing, no concatenated IPs, valid CEF structure. PRs that change rendering should include before/after sample output in the description.
