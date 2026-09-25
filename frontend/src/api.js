const BASE = '/api';

async function req(path, { method = 'GET', body } = {}) {
  const r = await fetch(BASE + path, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await r.text();
  const data = text ? JSON.parse(text) : null;
  if (!r.ok) throw new Error(data?.detail || `${r.status} ${r.statusText}`);
  return data;
}

export const api = {
  listPolicies: () => req('/policies'),
  getPolicy: (id) => req(`/policies/${id}`),
  createPolicy: (b) => req('/policies', { method: 'POST', body: b }),
  setRules: (id, rules, default_action) =>
    req(`/policies/${id}/rules`, { method: 'PUT', body: { rules, default_action } }),
  analyze: (id) => req(`/policies/${id}/analyze`),
  classify: (id, prefix) =>
    req(`/policies/${id}/classify`, { method: 'POST', body: { prefix } }),
  batch: (id, probes) =>
    req(`/policies/${id}/classify/batch`, { method: 'POST', body: { probes } }),
  trie: (id) => req(`/policies/${id}/trie`),
  snapshots: (id) => req(`/policies/${id}/snapshots`),
  snapshot: (id, label, created_by = 'lab') =>
    req(`/policies/${id}/snapshots`, { method: 'POST', body: { label, created_by } }),
  getSnapshot: (id) => req(`/snapshots/${id}`),
  diff: (a, b) => req('/snapshots/diff', { method: 'POST', body: { old_snapshot_id: a, new_snapshot_id: b } }),
  replay: (id, probes) =>
    req(`/snapshots/${id}/replay`, { method: 'POST', body: { probes } }),
  scenarios: () => req('/scenarios'),
  scenario: (id) => req(`/scenarios/${id}`),
  replayScenario: (id) => req(`/scenarios/${id}/replay`, { method: 'POST' }),
  neighbors: () => req('/neighbors'),
  frrStatus: () => req('/frr/status'),
  crossValidate: (id, probes, node = 'a') =>
    req(`/snapshots/${id}/cross-validate`, { method: 'POST', body: { probes, node } }),
  runs: () => req('/runs'),
  // reviewable release pipeline
  releases: (pid) => req(`/policies/${pid}/releases`),
  activeRelease: (pid) => req(`/policies/${pid}/releases/active`),
  allReleases: (params = {}) => {
    const q = new URLSearchParams(
      Object.entries(params).filter(([, v]) => v != null && v !== '')
    ).toString();
    return req(`/releases${q ? `?${q}` : ''}`);
  },
  release: (id) => req(`/releases/${id}`),
  createDraft: (pid, body = {}) =>
    req(`/policies/${pid}/releases/draft`, { method: 'POST', body }),
  validateRelease: (id, body = {}) =>
    req(`/releases/${id}/validate`, { method: 'POST', body }),
  approveRelease: (id, body) =>
    req(`/releases/${id}/approve`, { method: 'POST', body }),
  publishRelease: (id, body = {}) =>
    req(`/releases/${id}/publish`, { method: 'POST', body }),
  rollbackRelease: (id, body = {}) =>
    req(`/releases/${id}/rollback`, { method: 'POST', body }),
  liveConfig: (id) => req(`/releases/${id}/live-config`),
};
