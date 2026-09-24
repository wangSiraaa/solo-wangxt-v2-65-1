import React, { useEffect, useState } from 'react'
import { api } from '../api.js'

export default function TrieView({ policy }) {
  const [trie, setTrie] = useState(null)
  const [probe, setProbe] = useState(policy.family === 4 ? '172.31.5.0/24' : '2001:db8:1::/48')
  const [hit, setHit] = useState(null)
  const [err, setErr] = useState('')

  async function load() {
    setTrie(await api.trie(policy.id))
  }
  useEffect(() => { load() }, [policy.id, JSON.stringify(policy.rules)])

  async function classify() {
    setErr(''); setHit(null)
    try { setHit(await api.classify(policy.id, probe.trim())) }
    catch (e) { setErr(e.message) }
  }

  const hitSet = new Set(hit?.trie_path || [])
  const matchedSeq = hit?.matched_seq

  return (
    <div className="trie-view">
      <div className="bar">
        <span>前缀树（仅显示规则基址及其祖先链；规则按 seq 首条匹配）</span>
        <input className="probe" value={probe}
          onChange={(e) => setProbe(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && classify()}
          placeholder={policy.family === 4 ? '192.168.100.128/25' : '2001:db8:1::/64'} />
        <button onClick={classify}>推演命中链</button>
        {err && <span className="error">{err}</span>}
      </div>

      {hit && (
        <div className={`hitbox ${hit.final_action}`}>
          <div className="hit-head">
            {hit.prefix} → <b>{hit.final_action.toUpperCase()}</b>
            <span className="muted">（{hit.terminal === 'default'
              ? `未命中任何条目，使用隐式默认 ${hit.final_action}`
              : `命中 seq ${matchedSeq}`}）</span>
          </div>
          <table className="chain">
            <thead><tr>
              <th>seq</th><th>规则前缀</th><th>动作</th><th>地址包含?</th>
              <th>长度窗口?</th><th>结果</th><th>原因</th>
            </tr></thead>
            <tbody>
              {hit.chain.map((c, i) => (
                <tr key={i} className={c.matched ? 'matched'
                  : c.contained ? 'contained' : c.seq == null ? 'defaultrow' : ''}>
                  <td>{c.seq ?? '默认'}</td>
                  <td><code>{c.prefix}</code>{c.ge != null && <em> ge {c.ge}</em>}
                    {c.le != null && <em> le {c.le}</em>}</td>
                  <td className={c.action}>{c.action}</td>
                  <td>{c.seq == null ? '—' : c.contained ? '✓' : '✗'}</td>
                  <td>{c.seq == null ? '—' : c.length_ok ? '✓' : '✗'}</td>
                  <td>{c.matched ? '🎯 命中并终止' : c.seq == null ? '⬛ 落到默认' : '继续'}</td>
                  <td className="muted">{c.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {trie && (
        <div className="tree">
          <TrieNode key0={trie.root} nodes={trie.nodes} hitSet={hitSet}
            matchedSeq={matchedSeq} depth={0} defaultOpen />
        </div>
      )}
    </div>
  )
}

function TrieNode({ key0, nodes, hitSet, matchedSeq, depth, defaultOpen }) {
  const n = nodes[key0]
  const [open, setOpen] = useState(!!defaultOpen || hitSet.has(key0) || depth < 2)
  if (!n) return null
  const inHit = hitSet.has(key0)
  const children = n.children.map((c) => nodes[c]).filter(Boolean)
    .sort((a, b) => a.prefix.localeCompare(b.prefix, undefined, { numeric: true }))
  return (
    <div className="tnode" style={{ marginLeft: depth === 0 ? 0 : 18 }}>
      <div className={`trow ${inHit ? 'onpath' : ''}`}>
        {children.length > 0
          ? <button className="twist" onClick={() => setOpen(!open)}>{open ? '▾' : '▸'}</button>
          : <span className="twist placeholder" />}
        <span className="prefix-label">{key0}</span>
        {n.rules.map((r) => (
          <span key={r.seq}
            className={`rule-pill ${r.action} ${r.shadowed ? 'shadowed' : ''} ${matchedSeq === r.seq ? 'matched-pill' : ''}`}
            title={`min_len=${r.min_len} max_len=${r.max_len}${r.shadowed ? '（被遮蔽）' : ''}`}>
            #{r.seq} {r.action}{r.ge != null ? ` ge${r.ge}` : ''}{r.le != null ? ` le${r.le}` : ''}
            {r.shadowed && ' ⛔'}
            {r.partial_shadowed_by.length > 0 && !r.shadowed &&
              <em className="partialmark"> ·重叠#{r.partial_shadowed_by.join(',')}</em>}
          </span>
        ))}
      </div>
      {open && children.map((c) => (
        <TrieNode key={c.prefix} key0={c.prefix} nodes={nodes}
          hitSet={hitSet} matchedSeq={matchedSeq} depth={depth + 1} />
      ))}
    </div>
  )
}
