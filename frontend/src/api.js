const BASE = '/api';

async function req(path, { method = 'GET', body, headers } = {}) {
  const h = headers || {};
  if (body) h['Content-Type'] = 'application/json';
  const r = await fetch(BASE + path, {
    method,
    headers: Object.keys(h).length ? h : undefined,
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

  // ---- release pipeline ----
  validateSnapshot: (id, probes = null, node = 'a') =>
    req(`/snapshots/${id}/validate`, { method: 'POST', body: { probes, node } }),
  approveSnapshot: (id, approver, comment) =>
    req(`/snapshots/${id}/approve`, { method: 'POST', body: { approver, comment } }),
  publishSnapshot: (id, node = 'a', key = null) =>
    req(`/snapshots/${id}/publish`, {
      method: 'POST', body: { node }, headers: key ? { 'Idempotency-Key': key } : undefined,
    }),
  rollbackSnapshot: (id, node = 'a', key = null) =>
    req(`/snapshots/${id}/rollback`, {
      method: 'POST', body: { node }, headers: key ? { 'Idempotency-Key': key } : undefined,
    }),
  releases: (pid) => req(`/policies/${pid}/releases`),
  allReleases: () => req('/releases'),
  release: (id) => req(`/releases/${id}`),
  retryRelease: (id) => req(`/releases/${id}/retry`, { method: 'POST' }),
  drift: (pid, node = 'a') => req(`/policies/${pid}/drift?node=${node}`),
  activeRelease: (pid, node = 'a') =>
    req(`/policies/${pid}/active-release?node=${node}`),
};
