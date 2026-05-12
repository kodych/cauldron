<!--
Thanks for the PR. A short, focused description here speeds the
review up considerably — and the GitHub release notes get drafted
from these summaries, so anything you write here ends up visible to
end users.
-->

## What this changes

One or two sentences on the user-visible change. *Why* it changes,
not just *what* — the diff already shows the "what".

## Linked issues

Closes #
Relates to #

## Type of change

<!-- check all that apply -->

- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] Feature (non-breaking change adding new functionality)
- [ ] Breaking change (fix or feature that would change existing behavior)
- [ ] Refactor / cleanup (no functional change)
- [ ] Documentation / samples / chore

## Verification

How you confirmed it works. For pipeline / enrichment changes, the
gold standard is a before/after on one of `data/samples/` —
mention which sample and what counter / output shifted.

- [ ] `pytest tests/` passes locally
- [ ] `npx tsc --noEmit` (frontend) passes
- [ ] Manually verified against `data/samples/` (which one: ___ )
- [ ] N/A — explain:

## Anything reviewers should look at first

If one file is the heart of the change and the rest is mechanical
fall-out, point at it here.

## Notes for the changelog

A single-line summary suitable for the release notes. Leave blank if
the PR title already says it.
