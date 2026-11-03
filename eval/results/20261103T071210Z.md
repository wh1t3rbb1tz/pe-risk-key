# Eval results — 2026-11-03

Models: muse-wonder-1.0 · Runs: 5 (brightwaterfleet.example x3, copperline.example x2) · Total cost: $1.3541

## brightwaterfleet.example (outside-in + SOC 2 + interview)

| run | finding recall | precision | contra recall | verdict acc | schema | narrative (att) | rating | profile | score | cost | time |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `dg_1lsuvteab6tk` | 100.0% | 100.0% | 100.0% | 100.0% | pass | pass (1) | D (match) | match | 56.8 | $0.3850 | 48.9s |
| `dg_co0cxi7wkexh` | 100.0% | 100.0% | 100.0% | 100.0% | pass | pass (1) | D (match) | match | 56.8 | $0.3794 | 60.0s |
| `dg_6f0pdq5c5kbz` | 100.0% | 100.0% | 100.0% | 100.0% | pass | pass (1) | D (match) | match | 56.8 | $0.3872 | 65.7s |
| mean | 100.0% | 100.0% | 100.0% | 100.0% | | | | | 56.8 | | |
| min | 100.0% | 100.0% | 100.0% | 100.0% | | | | | | | |

## copperline.example (outside-in only)

| run | finding recall | precision | contra recall | verdict acc | schema | narrative (att) | rating | profile | score | cost | time |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `dg_qitmmzuiskgb` | 100.0% | 100.0% | n/a | n/a | pass | pass (1) | B (match) | match | 98.4 | $0.1006 | 27.7s |
| `dg_xdi3nu467iqe` | 100.0% | 100.0% | n/a | n/a | pass | pass (1) | B (match) | match | 98.4 | $0.1020 | 31.1s |
| mean | 100.0% | 100.0% | n/a | n/a | | | | | 98.4 | | |
| min | 100.0% | 100.0% | n/a | n/a | | | | | | | |

## Aggregate

- schema pass rate: 100.0%
- narrative pass rate: 100.0%
- rating match fraction: 100.0%
- profile match fraction: 100.0%
- scoring determinism: 100.0% byte-identical
- brightwaterfleet.example score: 56.8, std dev 0.0, range 56.8–56.8
- copperline.example score: 98.4, std dev 0.0, range 98.4–98.4
