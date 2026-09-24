import React, { useEffect, useState } from 'react'
import { api } from '../api.js'

export default function DiffView({ policy, policies }) {
  const [snaps, setSnaps] = useState([])
  const [fromId, setFromId] = useState('')
  const [toId, setToId] = useState('')
  const [diff, setDiff] = useState(null)
  const [err, setErr] = useState('')

  useEffect(() => {
    api.snapshots(policy.id).then((s) => {
      setSnaps(s)
      const ordered = [...s].sort((a, b) => a.version - b.version)
      if (ordered.length >= 2) {
        setFromId(ordered[ordered.length - 2].id)
        setToId(ordered[ordered.length - 1].id)
      } else if (ordered.length === 1) {
        setFromId(ordered[0].id)
        setToId(ordered[0].id)
      }
    }).catch((e) => setErr(e.message))
  }, [policy.id])

  async function run() {
    setErr(''); setDiff(null)
    try { setDiff(await api.diff(Number(fromId), Number(toId))) }
    catch (e) { setErr(e.message) }
  }

  return (
    <div className="diffview">
      <div className="bar">
        <span>快照间语义差异（行为变化的最小前缀集合）</span>
        <select value={fromId} onChange={(e) => setFromId(e.target.value)}>
          <option value="" disabled>旧快照…</option>
          {snaps.map((s) => <option key={s.id} value={s.id}>v{s.version} {s.label}</option>)}
        </select>
        <span className="arrow">⟶</span>
        <select value={toId} onChange={(e) => setToId(e.target.value)}>
          <option value="" disabled>新快照…</option>
          {snaps.map((s) => <option key={s.id} value={s.id}>v{s.version} {s.label}</option>)}
        </select>
        <button onClick={run} disabled={!fromId || !toId}>计算最小见证集</button>
        {err && <span className="error">{err}</span>}
      </div>

      {diff && (
        <>
          <div className="summary">
            <span>默认动作：{diff.old_default} ⟶ {diff.new_default}</span>
            <span className="deny2">新增拒绝 {diff.newly_denied.length}</span>
            <span className="permit2">新增放行 {diff.newly_permitted.length}</span>
            <span>见证前缀总数（精确最小）：<b>{diff.witness_count}</b></span>
          </div>
          {diff.witness_count === 0
            ? <div className="ok">两个快照在该地址族上行为完全等价——即使规则文本不同，也没有任何前缀的转发结果变化。</div>
            : (
              <table className="witness">
                <thead><tr>
                  <th>见证前缀（最浅代表）</th><th>旧结果</th><th>新结果</th>
                  <th>旧命中 seq</th><th>新命中 seq</th><th>变化</th>
                </tr></thead>
                <tbody>
                  {diff.witnesses.map((w) => (
                    <tr key={w.prefix} className={w.change}>
                      <td><code className="chip big">{w.prefix}</code></td>
                      <td className={w.old_action}>{w.old_action}{w.old_seq == null ? '（默认）' : ` #${w.old_seq}`}</td>
                      <td className={w.new_action}>{w.new_action}{w.new_seq == null ? '（默认）' : ` #${w.new_seq}`}</td>
                      <td>{w.old_seq ?? '—'}</td>
                      <td>{w.new_seq ?? '—'}</td>
                      <td>{w.change === 'deny->permit'
                        ? '⚠ 更具体路由被放行' : '新增拒绝'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          <p className="muted">
            说明：每个见证前缀代表一个最大等价区域（同深度相邻 + 跨深度包含且获胜规则相同）。
            这是语义差异：deny→deny 但命中规则改变不会出现；无行为变化的纯文本改写得到空集。
          </p>
        </>
      )}
    </div>
  )
}
