# Eval results — 2026-11-03

Models: muse-wonder-1.0 · Runs: 5 (brightwaterfleet.example x3, copperline.example x2) · Total cost: $1.7411

## brightwaterfleet.example (outside-in + SOC 2 + interview)

| run | finding recall | precision | contra recall | verdict acc | schema | narrative (att) | rating | profile | score | cost | time |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `dg_tb9lwo1st8o7` | 100.0% | 100.0% | 100.0% | 100.0% | pass | pass (2) | D (match) | match | 56.8 | $0.4855 | 83.9s |
| `dg_3tp9o3lhhif7` | 100.0% | 100.0% | 100.0% | 100.0% | pass | FAIL (2) | D (match) | match | 57.3 | $0.4467 | 67.9s |
| `dg_ea8uqhzdk6f5` | 100.0% | 93.8% | 100.0% | 100.0% | pass | FAIL (2) | D (match) | match | 55.5 | $0.4665 | 78.3s |
| mean | 100.0% | 97.9% | 100.0% | 100.0% | | | | | 56.5 | | |
| min | 100.0% | 93.8% | 100.0% | 100.0% | | | | | | | |

## copperline.example (outside-in only)

| run | finding recall | precision | contra recall | verdict acc | schema | narrative (att) | rating | profile | score | cost | time |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `dg_o7wjrz52pwph` | 100.0% | 100.0% | n/a | n/a | pass | pass (2) | B (match) | match | 98.4 | $0.1768 | 47.4s |
| `dg_otkdxvho44we` | 100.0% | 100.0% | n/a | n/a | pass | FAIL (2) | B (match) | match | 98.4 | $0.1656 | 53.4s |
| mean | 100.0% | 100.0% | n/a | n/a | | | | | 98.4 | | |
| min | 100.0% | 100.0% | n/a | n/a | | | | | | | |

## Aggregate

- schema pass rate: 100.0%
- narrative pass rate: 40.0%
- rating match fraction: 100.0%
- profile match fraction: 100.0%
- scoring determinism: 100.0% byte-identical
- score variance: 420.64
