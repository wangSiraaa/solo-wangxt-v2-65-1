import React, { useEffect, useMemo, useState } from 'react'
import { api } from '../api.js'
import EvidencePanel from './EvidencePanel.jsx'

const STATE_FLOW = [
  ['draft', '草稿'],
  ['validating', '验证中'],
  ['validation_failed', '验证失败'],
  ['pending_approval', '待审批'],
  ['approved', '已批准'],
  ['simulated_published', '已模拟发布'],
  ['superseded', '已替代'],
]

const STATE_STYLE = {
  draft: 'st-draft',
  validating: 'st-validating',
  validation_failed: 'st-failed',
  pending_approval: 'st-pending',
  approved: 'st-approved',
  simulated_published: 'st-live',
  superseded: 'st-superseded',
}

export default function ReleaseGate({ policy, onChange }) {
  const [releases, setReleases] = useState([])
  const [active, setActive] = useState(null)
  const [selId, setSelId] = useState(null)
  const [detail, setDetail] = useState(null)
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState('')
  const [approver, setApprover] = useState('reviewer')
  const [comment, setComment] = useState('')

  async function refresh() {
    const [rs, act] = await Promise.all([
      api.releases(policy.id),
      api.activeRelease(policy.id),
    ])
    setReleases(rs)
    setActive(act.active)
    return rs
  }

  useEffect(() => {
    setErr(''); setDetail(null)
    refresh()
      .then((rs) => setSelId((cur) => (cur && rs.some((r) => r.id === cur) ? cur : rs[0]?.id ?? null)))
      .catch((e) => setErr(e.message))
  }, [policy.id])

  useEffect(() => {
    if (selId == null) { setDetail(null); return }
    api.release(selId).then(setDetail).catch((e) => setErr(e.message))
  }, [selId])

  async function run(label, fn) {
    setBusy(label); setErr('')
    try {
      await fn()
      const rs = await refresh()
      if (label === 'draft' || label === 'rollback') {
        const newest = rs[0]
        if (newest) setSelId(newest.id)
      }
      if (selId != null) setDetail(await api.release(selId))
      onChange?.()
    } catch (e) {
      setErr(e.message)
    } finally {
      setBusy('')
    }
  }

  const rel = detail

  return (
    <div className="gate">
      <div className="bar">
        <span>可审查发布流程（仅写入本地隔离 FRR，不连生产）</span>
        <button className="primary" disabled={!!busy}
          onClick={() => run('draft', () =>
            api.createDraft(policy.id, { created_by: 'lab', label: `candidate` }))}>
          {busy === 'draft' ? '铸造快照中…' : '从当前规则生成草稿（新快照）'}
        </button>
        {active
          ? <span className="tag st-live">当前生效 #{active.id} · 快照 v{active.snapshot_version}
              · {active.published_nodes.join(',')}</span>
          : <span className="tag st-draft">尚无已模拟发布版本</span>}
        {err && <span className="error">{err}</span>}
      </div>

      <div className="gate-cols">
        <div className="gate-list">
          <h4>发布记录 / 历史（新版本永不改写旧记录）</h4>
          <table className="cv">
            <thead><tr><th>#</th><th>类型</th><th>快照</th><th>状态</th><th>操作</th></tr></thead>
            <tbody>
              {releases.map((r) => (
                <tr key={r.id}
                  className={selId === r.id ? 'selrow' : ''}>
                  <td>{r.id}</td>
                  <td>{r.kind === 'rollback'
                    ? <span className="tag rollback">回滚 ↩{r.rollback_of_id ? ` #${r.rollback_of_id}` : ''}</span>
                    : '发布'}</td>
                  <td>v{r.snapshot_version}</td>
                  <td><span className={`tag ${STATE_STYLE[r.state]}`}>
                    {STATE_FLOW.find(([s]) => s === r.state)?.[1] ?? r.state}
                  </span></td>
                  <td>
                    <button className="mini" onClick={() => setSelId(r.id)}>证据/历史</button>
                    {r.state === 'simulated_published' &&
                      <RollbackButton id={r.id} busy={busy} run={run} />}
                  </td>
                </tr>
              ))}
              {releases.length === 0 &&
                <tr><td colSpan={5} className="muted">尚无发布记录，先生成一个草稿。</td></tr>}
            </tbody>
          </table>
        </div>

        {rel && (
          <div className="gate-detail">
            <StateFlow state={rel.state} />
            <div className="actions">
              {(rel.state === 'draft' || rel.state === 'validation_failed') &&
                <button className="primary" disabled={!!busy}
                  onClick={() => run('validate', () =>
                    api.validateRelease(rel.id, {}))}>
                  {rel.state === 'validation_failed' ? '重新验证（可重试）' : '执行验证（语义差异+探针+FRR 交叉验证）'}
                </button>}
              {rel.state === 'pending_approval' && (
                <span className="approve-box">
                  <input value={approver} onChange={(e) => setApprover(e.target.value)}
                    placeholder="审批人" />
                  <input className="comment" value={comment}
                    onChange={(e) => setComment(e.target.value)}
                    placeholder="审批意见（可选）" />
                  <button className="primary" disabled={!!busy || !approver.trim()}
                    onClick={() => run('approve', () =>
                      api.approveRelease(rel.id, {
                        approved_by: approver.trim(), comment }))}>
                    批准（冻结全部证据）
                  </button>
                </span>
              )}
              {rel.state === 'approved' &&
                <button className="primary" disabled={!!busy}
                  onClick={() => run('publish', () => api.publishRelease(rel.id, {}))}>
                  模拟发布到隔离 FRR（{rel.evidence?.frr_nodes
                    ? Object.keys(rel.evidence.frr_nodes).join(',') : ''}）
                </button>}
              {rel.state === 'simulated_published' &&
                <RollbackButton id={rel.id} busy={busy} run={run} big />}
              {rel.last_error && Object.keys(rel.last_error).length > 0 &&
                rel.state !== 'simulated_published' &&
                <div className="errbox">
                  <b>可重试失败：</b>
                  <pre>{JSON.stringify(rel.last_error, null, 2)}</pre>
                  {rel.state === 'approved' &&
                    <button className="mini" disabled={!!busy}
                      onClick={() => run('publish', () => api.publishRelease(rel.id, {}))}>
                      重试发布</button>}
                </div>}
            </div>
            <EvidencePanel rel={rel} />
          </div>
        )}
      </div>
    </div>
  )
}

function RollbackButton({ id, busy, run, big }) {
  return <button className={`mini danger ${big ? 'bigbtn' : ''}`} disabled={!!busy}
    onClick={() => {
      if (confirm('从该历史快照创建新的回滚发布记录（旧记录保留不改写）？')) {
        run('rollback', () => api.rollbackRelease(id, { actor: 'lab' }))
      }
    }}>
    ↩ 从此版本回滚（新建记录）
  </button>
}

function StateFlow({ state }) {
  const order = ['draft', 'validating', 'pending_approval', 'approved',
    'simulated_published']
  const failed = state === 'validation_failed'
  const idx = failed ? 2 : order.indexOf(state)
  return (
    <div className="flow">
      {order.map((s, i) => {
        const on = state === s || (s === 'pending_approval' && failed)
        const past = i < idx
        return (
          <React.Fragment key={s}>
            <span className={`flowstep ${on ? STATE_STYLE[s] : ''} ${past ? 'past' : ''}`}>
              {STATE_FLOW.find(([x]) => x === s)?.[1]}
              {s === 'pending_approval' && failed &&
                <span className="flow-fail">（验证失败，可重试）</span>}
            </span>
            {i < order.length - 1 && <span className="flowarrow">→</span>}
          </React.Fragment>
        )
      })}
      {state === 'superseded' &&
        <span className="tag st-superseded flow-sup">已替代（规则后续编辑或被新版本取代）</span>}
    </div>
  )
}
