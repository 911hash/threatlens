# ThreatLens Architecture & Phased Performance Notes

## Phase 6 performance task
- Bundle currently 793KB / 214KB gzip. Recharts is the largest contributor.
- Phase 6 must: (a) route-split every page via React.lazy + Suspense,
  (b) confirm Recharts only loads on routes that render it (Compare, Result,
  Dashboard), (c) target Lighthouse >= 95 Performance on Overview with a
  cold cache. Do not touch in Phase 2/3.
