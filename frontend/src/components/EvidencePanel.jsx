import React, { useState } from 'react'
import { api } from '../api.js'

export default function EvidencePanel({ rel }) {
  const ev = rel.evidence || {}
  const approval = rel.approval || {}
  const diff = ev.semantic_diff
  const [live, setLive] = useState(null)
  const [liveErr, setLiveErr] = useState('')

  async function checkLive() {
    setLiveErr(''); setLive(null)
    try { setLive(await api.liveConfig(rel.id)) }
    catch (e) { setLiveErr(e.message) }
  }

  return (
    <div className="evidence">
      <details open={rel.state === 'pending_approval' || rel.state === 'approved'}>
        <summary>① 审批冻结包 {Object.keys(approval).length > 0
          ? <span className="ok">（已由 {approval.approved_by} 冻结）</span>
          : <span className="muted">（验证通过后生成，批准时再冻结校验和）</span>}</summary>
        <div className="ev-grid">
          <div><b>规则顺序校验和</b><br /><code>{approval.rules_checksum
            ? approval.rules_checksum.slice(0, 24) + '…' : '—'}</code></div>
          <div><b>邻居校验和</b><br /><code>{approval.neighbors_checksum
            ? approval.neighbors_checksum.slice(0, 24) + '…' : '—'}</code></div>
          <div><b>证据指纹</b><br /><code>{approval.evidence_fingerprint
            ? approval.evidence_fingerprint.slice(0, 24) + '…' : '—'}</code></div>
          <div><b>默认动作</b>
            <span className={ev.default_action === 'deny' ? 'permit' : 'deny'}>
              {ev.default_action ?? '—'}</span> · IPv{ev.family ?? '?'}</div>
        </div>
      </details>

      <details open>
        <summary>② 冻结的规则顺序（{ev.frozen_rules_ordered?.length ?? 0} 条）</summary>
        <table className="cv rules">
          <thead><tr><th>seq</th><th>动作</th><th>前缀</th><th>ge</th><th>le</th></tr></thead>
          <tbody>
            {(ev.frozen_rules_ordered || []).map((r) => (
              <tr key={r.seq}>
                <td>{r.seq}</td>
                <td className={r.action}>{r.action}</td>
                <td><code>{r.prefix}</code></td>
                <td>{r.ge ?? '—'}</td><td>{r.le ?? '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </details>

      <details>
        <summary>③ 邻居绑定（{ev.neighbors?.length ?? 0}）</summary>
        <table className="cv">
          <thead><tr><th>名称</th><th>IP</th><th>族</th><th>ASN</th>
            <th>入站策略</th><th>出站策略</th></tr></thead>
          <tbody>
            {(ev.neighbors || []).map((n) => (
              <tr key={n.id}><td>{n.name}</td><td><code>{n.ip}</code></td>
                <td>IPv{n.family}</td><td>{n.asn ?? '—'}</td>
                <td>{n.inbound_policy ?? '—'}</td>
                <td>{n.outbound_policy ?? '—'}</td></tr>
            ))}
            {(ev.neighbors || []).length === 0 &&
              <tr><td colSpan={6} className="muted">无邻居</td></tr>}
          </tbody>
        </table>
      </details>

      <details open={!!diff && diff.witness_count > 0}>
        <summary>④ 语义差异（最小见证前缀，{diff?.witness_count ?? 0} 个变化区域）
          {diff?.baseline && <span className="muted"> · 基线：{diff.baseline}</span>}
          {diff && !diff.baseline &&
            <span className="muted"> · 基线快照 #{diff.old_snapshot_id}</span>}
        </summary>
        {diff ? (
          <>
            <div className="summary">
              <span>默认动作：{diff.old_default} ⟶ {diff.new_default}</span>
              <span className="deny2">新增拒绝 {diff.newly_denied.length}</span>
              <span className="permit2">新增放行 {diff.newly_permitted.length}</span>
            </div>
            <table className="witness">
              <thead><tr><th>见证前缀</th><th>旧</th><th>新</th><th>旧seq</th><th>新seq</th></tr></thead>
              <tbody>
                {diff.witnesses.map((w) => (
                  <tr key={w.prefix} className={w.change}>
                    <td><code>{w.prefix}</code></td>
                    <td className={w.old_action}>{w.old_action}{w.old_seq == null ? '（默认）' : ` #${w.old_seq}`}</td>
                    <td className={w.new_action}>{w.new_action}{w.new_seq == null ? '（默认）' : ` #${w.new_seq}`}</td>
                    <td>{w.old_seq ?? '—'}</td><td>{w.new_seq ?? '—'}</td>
                  </tr>
                ))}
                {diff.witness_count === 0 &&
                  <tr><td colSpan={5} className="ok">与基线行为完全等价（无语义变化）</td></tr>}
              </tbody>
            </table>
          </>
        ) : <span className="muted">无基线可比较。</span>}
      </details>

      <details open>
        <summary>⑤ 探针结果（{ev.probes?.length ?? 0} 条有序探针）· 默认拒绝守卫
          {ev.default_deny_guard?.violation
            ? <span className="error"> 违规：{ev.default_deny_guard.violation}</span>
            : <span className="ok"> ✓ 未回归</span>}
        </summary>
        <p className="muted">
          外部探针 <code>{ev.default_deny_guard?.outsider}</code> 判定：
          <b className={ev.default_deny_guard?.action === 'deny' ? 'permit' : 'deny'}>
            {' '}{ev.default_deny_guard?.action}</b>
        </p>
        <table className="cv">
          <thead><tr><th>#</th><th>前缀</th><th>模拟器动作</th><th>seq</th></tr></thead>
          <tbody>
            {(ev.probe_results || []).map((r) => (
              <tr key={r.order}>
                <td>{r.order + 1}</td><td><code>{r.prefix}</code></td>
                <td className={r.action}>{r.action}</td>
                <td>{r.seq ?? '默认'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </details>

      <details open>
        <summary>⑥ FRRouting 交叉验证证据（隔离容器）</summary>
        <table className="cv">
          <thead><tr><th>节点</th><th>Run</th><th>状态</th><th>不一致数</th>
            <th>setup error</th></tr></thead>
          <tbody>
            {Object.entries(ev.frr_nodes || {}).map(([node, e]) => (
              <tr key={node}>
                <td>router-{node}</td><td>#{e.run_id}</td>
                <td className={e.status === 'match' ? 'permit' : 'deny'}>{e.status}</td>
                <td>{e.mismatch_count}</td>
                <td>{e.setup_error ?? '—'}</td>
              </tr>
            ))}
            {Object.keys(ev.frr_nodes || {}).length === 0 &&
              <tr><td colSpan={5} className="error">无 FRR 证据（验证失败）</td></tr>}
          </tbody>
        </table>
      </details>

      {rel.state === 'simulated_published' && (
        <details open>
          <summary>⑦ 实际隔离配置核对</summary>
          <button className="mini" onClick={checkLive}>读取容器实际 prefix-list</button>
          {liveErr && <span className="error"> {liveErr}</span>}
          {live && (
            <>
              <p className="muted">发布名 <code>{live.plist_name}</code> ·
                校验和 <code>{live.checksum.slice(0, 20)}…</code></p>
              {Object.entries(live.nodes).map(([node, e]) => (
                <div key={node} className={`cvbox ${e.matches_release ? 'match' : 'mismatch'}`}>
                  <b>router-{node}</b>：
                  {e.reachable
                    ? (e.matches_release
                      ? <span className="ok"> ✓ 实际配置与发布版本一致</span>
                      : <span className="error"> ✗ 与发布版本不一致</span>)
                    : <span className="error"> 不可达：{e.error}</span>}
                  <pre>{e.shown ?? '(无此 prefix-list)'}</pre>
                </div>
              ))}
            </>
          )}
        </details>
      )}

      <details>
        <summary>⑧ 事件历史（append-only 审计）</summary>
        <table className="cv">
          <thead><tr><th>时间</th><th>操作者</th><th>事件</th><th>详情</th></tr></thead>
          <tbody>
            {(rel.events || []).map((e) => (
              <tr key={e.id}>
                <td className="muted">{e.at?.replace('T', ' ').slice(0, 19)}</td>
                <td>{e.actor}</td><td>{e.event}</td>
                <td><code>{Object.keys(e.detail || {}).length
                  ? JSON.stringify(e.detail).slice(0, 160) : ''}</code></td>
              </tr>
            ))}
          </tbody>
        </table>
      </details>
    </div>
  )
}
