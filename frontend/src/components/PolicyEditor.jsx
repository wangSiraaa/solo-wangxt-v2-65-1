import React, { useEffect, useState } from 'react'
import { api } from '../api.js'

function blankRule(seq) {
  return { seq, prefix: '', action: 'permit', ge: '', le: '', remark: '' }
}

export default function PolicyEditor({ policy, onChange }) {
  const [rows, setRows] = useState(policy.rules.map((r) => ({ ...r })))
  const [defaultAction, setDefaultAction] = useState(policy.default_action)
  const [analysis, setAnalysis] = useState(null)
  const [msg, setMsg] = useState('')
  const [snapLabel, setSnapLabel] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    setRows(policy.rules.map((r) => ({ ...r })))
    setDefaultAction(policy.default_action)
    setAnalysis(null)
  }, [policy.id, policy.rules])

  function update(i, patch) {
    setRows((rs) => rs.map((r, j) => j === i ? { ...r, ...patch } : r))
  }
  function addRow() {
    const next = rows.length ? Math.max(...rows.map((r) => Number(r.seq))) + 10 : 10
    setRows([...rows, blankRow(next)])
  }
  function del(i) { setRows(rows.filter((_, j) => j !== i)) }
  function move(i, dir) {
    const j = i + dir
    if (j < 0 || j >= rows.length) return
    const next = [...rows]
    ;[next[i], next[j]] = [next[j], next[i]]
    // re-sequence in steps of 10 preserving intended order
    setRows(next.map((r, k) => ({ ...r, seq: (k + 1) * 10 })))
  }

  async function save(analyzeAfter = true) {
    setBusy(true); setMsg('')
    try {
      const payload = rows
        .filter((r) => r.prefix.trim() !== '')
        .map((r) => ({
          seq: Number(r.seq),
          prefix: r.prefix.trim(),
          action: r.action,
          ge: r.ge === '' || r.ge == null ? null : Number(r.ge),
          le: r.le === '' || r.le == null ? null : Number(r.le),
          remark: r.remark || '',
        }))
      await api.setRules(policy.id, payload, defaultAction)
      await onChange()
      if (analyzeAfter) setAnalysis(await api.analyze(policy.id))
      setMsg('已保存并重新分析')
    } catch (e) { setMsg('错误：' + e.message) }
    finally { setBusy(false) }
  }

  async function snapshot() {
    if (!snapLabel.trim()) { setMsg('请填写快照标签'); return }
    setBusy(true)
    try {
      await api.snapshot(policy.id, snapLabel)
      setMsg(`快照「${snapLabel}」已创建（不可变，可回放）`)
      setSnapLabel('')
      await onChange()
    } catch (e) { setMsg('错误：' + e.message) }
    finally { setBusy(false) }
  }

  const shadowed = new Set(analysis?.fully_shadowed || [])
  const partial = analysis?.partial_overlaps || {}

  return (
    <div className="editor">
      <div className="bar">
        <span>策略 <b>{policy.name}</b> · IPv{policy.family}
          {policy.family === 4 ? ' (0–32)' : ' (0–128)'}</span>
        <label>隐式默认：
          <select value={defaultAction} onChange={(e) => setDefaultAction(e.target.value)}>
            <option value="deny">deny（默认拒绝）</option>
            <option value="permit">permit（默认允许）</option>
          </select>
        </label>
        <button onClick={() => save(true)} disabled={busy}>保存 + 遮蔽分析</button>
        <button onClick={addRow}>新增条目</button>
        <input placeholder="快照标签，如 v3-收紧" value={snapLabel}
          onChange={(e) => setSnapLabel(e.target.value)} />
        <button onClick={snapshot} disabled={busy}>创建快照</button>
        <span className={msg.startsWith('错误') ? 'error' : 'ok'}>{msg}</span>
      </div>

      <table className="rules">
        <thead>
          <tr>
            <th style={{ width: 60 }}>seq</th><th style={{ width: 40 }}>序</th>
            <th>前缀（严格 IPv{policy.family}）</th>
            <th style={{ width: 100 }}>动作</th>
            <th style={{ width: 70 }}>ge</th>
            <th style={{ width: 70 }}>le</th>
            <th>备注</th><th style={{ width: 150 }}>分析</th><th></th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => {
            const isShadowed = shadowed.has(Number(r.seq))
            const over = partial[String(r.seq)]
            return (
              <tr key={i} className={isShadowed ? 'shadowed' : over ? 'partial' : ''}>
                <td><input value={r.seq} onChange={(e) => update(i, { seq: e.target.value })} /></td>
                <td>
                  <button className="mini" onClick={() => move(i, -1)}>↑</button>
                  <button className="mini" onClick={() => move(i, 1)}>↓</button>
                </td>
                <td><input className="prefix" value={r.prefix}
                  onChange={(e) => update(i, { prefix: e.target.value })}
                  placeholder={policy.family === 4 ? '192.168.0.0/16' : '2001:db8::/32'} /></td>
                <td>
                  <select value={r.action} onChange={(e) => update(i, { action: e.target.value })}>
                    <option value="permit">permit</option>
                    <option value="deny">deny</option>
                  </select>
                </td>
                <td><input value={r.ge ?? ''} onChange={(e) => update(i, { ge: e.target.value })} /></td>
                <td><input value={r.le ?? ''} onChange={(e) => update(i, { le: e.target.value })} /></td>
                <td><input value={r.remark || ''} onChange={(e) => update(i, { remark: e.target.value })} /></td>
                <td>
                  {isShadowed && <span className="tag bad">⛔ 完全遮蔽</span>}
                  {!isShadowed && over && <span className="tag warn">部分重叠 #{over.join(',')}</span>}
                </td>
                <td><button className="mini danger" onClick={() => del(i)}>✕</button></td>
              </tr>
            )
          })}
        </tbody>
      </table>

      {analysis && (
        <div className="analysis">
          <h4>遮蔽分析（精确，非采样）</h4>
          {analysis.fully_shadowed.length === 0 && !Object.keys(analysis.partial_overlaps).length
            ? <div className="ok">没有被遮蔽的条目；每条规则至少能在一个前缀上命中。</div>
            : (
              <ul>
                {analysis.shadow_detail.filter((s) => s.fully_shadowed).map((s) => (
                  <li key={s.rule.seq}>
                    <b className="bad">seq {s.rule.seq} {s.rule.prefix}</b> 永远不可达。
                    代表被截获前缀：
                    {s.witnesses.slice(0, 5).map((w) => <code key={w} className="chip">{w}</code>)}
                  </li>
                ))}
                {analysis.shadow_detail.filter((s) => !s.fully_shadowed && s.partial_shadowed_by.length)
                  .map((s) => (
                    <li key={s.rule.seq}>
                      <b className="warn">seq {s.rule.seq} {s.rule.prefix}</b> 部分区域与
                      {' '}#{s.partial_shadowed_by.join(', #')} 重叠（仍有可达区域）。
                    </li>
                  ))}
              </ul>
            )}
          <details>
            <summary>FRR 配置预览（vtysh）</summary>
            <pre>{(policiesFRR(policy, rows, defaultAction))}</pre>
          </details>
        </div>
      )}
    </div>
  )
}

function policiesFRR(policy, rows, defaultAction) {
  const ip = policy.family === 4 ? 'ip' : 'ipv6'
  return [...rows]
    .filter((r) => r.prefix)
    .sort((a, b) => Number(a.seq) - Number(b.seq))
    .map((r) => {
      const ge = r.ge !== '' && r.ge != null ? ` ge ${r.ge}` : ''
      const le = r.le !== '' && r.le != null ? ` le ${r.le}` : ''
      return `${ip} prefix-list ${policy.name} seq ${r.seq} ${r.action} ${r.prefix}${ge}${le}`
    }).join('\n')
}
