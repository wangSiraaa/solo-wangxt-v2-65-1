import React, { useEffect, useMemo, useState } from 'react'
import { api } from '../api.js'

const STATES = {
  draft: { label: '草稿', cls: 'st-draft' },
  validating: { label: '验证中', cls: 'st-validating' },
  validation_failed: { label: '验证失败', cls: 'st-failed' },
  pending_approval: { label: '待审批', cls: 'st-pending' },
  approved: { label: '已批准', cls: 'st-approved' },
  simulated_published: { label: '已模拟发布', cls: 'st-published' },
  superseded: { label: '已替代', cls: 'st-superseded' },
}

const FLOW = ['draft', 'validating', 'validation_failed', 'pending_approval',
  'approved', 'simulated_published', 'superseded']

function StatePill({ status }) {
  const m = STATES[status] || { label: status, cls: 'st-draft' }
  return <span className={`pill ${m.cls}`}>{m.label}</span>
}

export default function ReleaseGate({ policy, onChange }) {
  const [snaps, setSnaps] = useState([])
  const [sid, setSid] = useState(null)
  const [releases, setReleases] = useState([])
  const [active, setActive] = useState(null)
  const [drift, setDrift] = useState(null)
  const [node, setNode] = useState('a')
  const [probesText, setProbesText] = useState('')
  const [approver, setApprover] = useState('netops')
  const [comment, setComment] = useState('')
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState('')
  const [showEvidence, setShowEvidence] = useState(true)

  async function refresh() {
    const [s, rs, act, dr] = await Promise.all([
      api.snapshots(policy.id),
      api.releases(policy.id).catch(() => []),
      api.activeRelease(policy.id, node).catch(() => null),
      api.drift(policy.id, node).catch(() => null),
    ])
    setSnaps(s)
    setReleases(rs)
    setActive(act)
    setDrift(dr)
    setSid((cur) => cur ?? s[0]?.id ?? null)
  }

  useEffect(() => { refresh() }, [policy.id, node])

  const snap = useMemo(
    () => snaps.find((x) => x.id === sid) || snaps[0] || null,
    [snaps, sid])

  function flash(m) { setMsg(m); setTimeout(() => setMsg(''), 6000) }
  async function run(fn, okText) {
    setBusy(true); setMsg('')
    try { await fn(); await refresh(); flash(okText); onChange?.() }
    catch (e) { flash('错误：' + e.message) }
    finally { setBusy(false) }
  }

  const probes = probesText.split(/[\s,]+/).filter(Boolean)

  function doValidate() {
    return run(() => api.validateSnapshot(snap.id, probes.length ? probes : null, node),
      '验证完成：证据已冻结，等待审批')
  }
  function doApprove() {
    if (!approver.trim()) { flash('请填写审批人'); return }
    return run(() => api.approveSnapshot(snap.id, approver, comment),
      `已批准 v${snap.version}（规则顺序/邻居/默认动作/差异/探针/FRR 证据已冻结）`)
  }
  function doPublish() {
    const key = `pub-${snap.id}-${node}-${Date.now()}`
    return run(() => api.publishSnapshot(snap.id, node, key),
      '已写入本地隔离 FRR（仅隔离容器，不连生产）')
  }
  function doRollback() {
    const key = `rb-${snap.id}-${node}-${Date.now()}`
    return run(() => api.rollbackSnapshot(snap.id, node, key),
      `已回滚：从历史 v${snap.version} 生成了新的发布记录`)
  }

  const can = {
    validate: snap && ['draft', 'validation_failed', 'pending_approval'].includes(snap.status),
    approve: snap && snap.status === 'pending_approval',
    publish: snap && ['approved'].includes(snap.status),
    rollback: snap && active && snap.id !== active.snapshot_id &&
      snap.status !== 'draft' && snap.status !== 'validation_failed' &&
      snap.status !== 'validating' && snap.status !== 'pending_approval',
  }

  return (
    <div className="gate">
      <div className="bar">
        <span>可审查发布闭环（验证 → 审批 → 模拟发布 → 回滚）</span>
        <select value={node} onChange={(e) => setNode(e.target.value)}>
          <option value="a">隔离节点 router-a</option>
          <option value="b">隔离节点 router-b</option>
        </select>
        <button className="small" onClick={refresh}>刷新</button>
        {msg && <span className={msg.startsWith('错误') ? 'error' : 'ok'}>{msg}</span>}
      </div>

      <div className="gate-grid">
        <div className="panel">
          <h4>① 选择快照版本（编辑规则后须重新走验证/审批）</h4>
          <select value={snap?.id ?? ''} onChange={(e) => setSid(Number(e.target.value))}>
            {snaps.map((s) => (
              <option key={s.id} value={s.id}>
                v{s.version} {s.label} — {STATES[s.status]?.label || s.status}
              </option>
            ))}
          </select>

          {snap && (
            <div className="flow">
              {FLOW.map((st) => (
                <div key={st} className={`flow-step ${snap.status === st ? 'cur' : ''} ${
                  FLOW.indexOf(st) < FLOW.indexOf(snap.status) ? 'done' : ''}`}>
                  <span className="dot" />{STATES[st].label}
                </div>
              ))}
            </div>
          )}

          <h4>② 验证探针（留空使用自动最小见证集）</h4>
          <textarea rows={5} placeholder={'192.168.100.0/24\n8.8.8.8/32'}
            value={probesText} onChange={(e) => setProbesText(e.target.value)} />
          <div className="actions">
            <button onClick={doValidate} disabled={busy || !can.validate}>
              运行验证（模拟器 + 隔离 FRR 交叉验证）
            </button>
          </div>

          <h4>③ 审批（冻结证据，后续编辑生成新草稿）</h4>
          <div className="bar-inline">
            <input placeholder="审批人" value={approver}
              onChange={(e) => setApprover(e.target.value)} />
            <input className="grow" placeholder="审批意见" value={comment}
              onChange={(e) => setComment(e.target.value)} />
            <button className="primary" onClick={doApprove}
              disabled={busy || !can.approve}>批准发布</button>
          </div>
          {snap?.invalidated_reason && (
            <div className="invalidated">
              ⚠ 该版本已失效：{snap.invalidated_reason}；请编辑后创建新快照并重新验证。
            </div>
          )}

          <h4>④ 模拟发布 / 回滚（仅本地隔离 FRR）</h4>
          <div className="actions">
            <button className="primary" onClick={doPublish}
              disabled={busy || !can.publish}>
              发布到隔离节点 {node}
            </button>
            <button onClick={doRollback} disabled={busy || !can.rollback}>
              回滚到此版本（追加新记录）
            </button>
          </div>
          <p className="muted">
            当前生效：{active
              ? <>release #{active.id} · 快照 v{active.snapshot_version}
                <code> {active.kind === 'rollback' ? '(回滚记录)' : ''}</code></>
              : '无'}；
            设备漂移核对：{drift == null ? '—' : drift.drift
              ? <b className="error">检测到漂移</b>
              : <b className="ok">配置一致</b>}
          </p>
        </div>

        {snap && <Evidence snap={snap} show={showEvidence} setShow={setShowEvidence} />}
      </div>

      <ReleaseHistory releases={releases} onRetry={async (id) =>
        run(() => api.retryRelease(id), `发布 #${id} 重试成功`)} />
    </div>
  )
}

function Evidence({ snap, show, setShow }) {
  const v = snap.validation
  const a = snap.approval
  return (
    <div className="panel evidence">
      <div className="ev-head">
        <h4>冻结证据 · v{snap.version}</h4>
        <button className="mini" onClick={() => setShow(!show)}>
          {show ? '收起' : '展开'}
        </button>
      </div>
      {!show ? null : (
        <>
          <div className="kv">
            <span>内容哈希（SHA-256）</span>
            <code className="hash">{snap.content_hash?.slice(0, 24)}…</code>
          </div>
          {!v ? <div className="muted">尚未验证。</div> : (
            <>
              <div className="kv"><span>验证时间 / 节点</span>
                <b>{v.validated_at?.replace('T', ' ').slice(0, 19)} · {v.node}</b></div>
              <div className="kv"><span>规则顺序（冻结 seq）</span>
                <code>[{v.rule_order.join(', ')}]</code></div>
              <div className="kv"><span>默认动作</span>
                <b className={v.default_action}>{v.default_action}</b></div>
              <div className="kv"><span>FRR 交叉验证</span>
                <b className={v.frr.status === 'match' ? 'permit' : 'deny'}>
                  {v.frr.status} · 不一致 {v.frr.mismatch_count}
                </b></div>

              <details>
                <summary>邻居绑定（{v.neighbors.length}）</summary>
                <table className="mini-tbl">
                  <tbody>
                    {v.neighbors.map((n) => (
                      <tr key={n.id} className={n.bound ? 'bound' : ''}>
                        <td>{n.name}</td><td><code>{n.ip}</code></td>
                        <td>in: {n.inbound_policy || '—'}</td>
                        <td>out: {n.outbound_policy || '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </details>

              <details>
                <summary>语义差异 / 最小见证前缀
                  （{v.semantic_diff ? v.semantic_diff.witness_count : '首次发布'}）
                </summary>
                {!v.semantic_diff ? <div className="muted">首个版本，无基线可 diff。</div> : (
                  <table className="mini-tbl">
                    <thead><tr><th>见证前缀</th><th>旧</th><th>新</th><th>变化</th></tr></thead>
                    <tbody>
                      {v.semantic_diff.witnesses.map((w) => (
                        <tr key={w.prefix}>
                          <td><code>{w.prefix}</code></td>
                          <td>{w.old_action}#{w.old_seq ?? '默'}</td>
                          <td>{w.new_action}#{w.new_seq ?? '默'}</td>
                          <td className={w.change === 'permit->deny' ? 'deny' : 'warn'}>
                            {w.change}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </details>

              <details open>
                <summary>探针结果（{v.frr.rows.length}，FRR 逐条比对）</summary>
                <table className="mini-tbl">
                  <thead><tr><th>前缀</th><th>模拟</th><th>FRR</th><th>一致</th></tr></thead>
                  <tbody>
                    {v.frr.rows.map((r, i) => (
                      <tr key={i} className={r.action_match && r.seq_match ? '' : 'badrow'}>
                        <td><code>{r.prefix}</code></td>
                        <td>{r.sim_action}#{r.sim_seq ?? '默'}</td>
                        <td>{r.frr_action}#{r.frr_seq ?? '默'}</td>
                        <td>{r.action_match && r.seq_match ? '✓' : '✗'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </details>

              <details>
                <summary>FRR 配置（vtysh，发布即下发此文本）</summary>
                <pre>{snap.frr_config || '(空)'}</pre>
              </details>
            </>
          )}

          {a && (
            <div className="approval-box">
              <div className="kv"><span>审批人</span><b>{a.approver}</b></div>
              <div className="kv"><span>审批时间</span>
                <b>{a.approved_at?.replace('T', ' ').slice(0, 19)}</b></div>
              <div className="kv"><span>审批冻结哈希</span>
                <code className="hash">{a.frozen_content_hash.slice(0, 24)}…</code></div>
              {a.comment && <div className="kv"><span>意见</span><b>{a.comment}</b></div>}
            </div>
          )}
        </>
      )}
    </div>
  )
}

function ReleaseHistory({ releases, onRetry }) {
  return (
    <div className="panel history">
      <h4>发布 / 回滚历史（只追加，不回写旧记录）</h4>
      <table className="mini-tbl">
        <thead><tr>
          <th>#</th><th>类型</th><th>快照</th><th>节点</th><th>状态</th>
          <th>尝试</th><th>基线</th><th>回滚自</th><th>时间</th><th></th>
        </tr></thead>
        <tbody>
          {releases.map((r) => (
            <tr key={r.id} className={`rel-${r.status}`}>
              <td>{r.id}</td>
              <td>{r.kind === 'rollback' ? '↩ 回滚' : '发布'}</td>
              <td>v{r.snapshot_version}</td>
              <td>{r.node}</td>
              <td><ReleaseStatus s={r.status} r={r} /></td>
              <td>{r.attempts}</td>
              <td>{r.baseline_release_id ?? '—'}</td>
              <td>{r.rolled_back_release_id ?? '—'}</td>
              <td className="muted">{r.created_at?.replace('T', ' ').slice(0, 19)}</td>
              <td>
                {r.status === 'failed' &&
                  <button className="mini primary" onClick={() => onRetry(r.id)}>
                    重试
                  </button>}
              </td>
            </tr>
          ))}
          {releases.length === 0 && (
            <tr><td colSpan={10} className="muted">尚无发布记录。</td></tr>)}
        </tbody>
      </table>
    </div>
  )
}

function ReleaseStatus({ s, r }) {
  const map = {
    applying: ['st-validating', '应用中'],
    active: ['st-published', '生效中'],
    failed: ['st-failed', '失败可重试'],
    superseded: ['st-superseded', '已替代'],
  }
  const [cls, label] = map[s] || ['st-draft', s]
  return (
    <span className={`pill ${cls}`}>
      {label}
      {s === 'failed' && r.detail?.last_error &&
        <em className="err-detail" title={r.detail.last_error}> ⓘ</em>}
    </span>
  )
}
