import React, { useEffect, useState } from 'react'
import { api } from '../api.js'

export default function ReplayLab({ policy }) {
  const [snaps, setSnaps] = useState([])
  const [snapId, setSnapId] = useState('')
  const [probesText, setProbesText] = useState(
    '192.168.0.0/16\n192.168.100.0/24\n172.31.5.0/24\n8.8.8.8/32')
  const [replay, setReplay] = useState(null)
  const [cv, setCv] = useState(null)
  const [node, setNode] = useState('a')
  const [err, setErr] = useState('')
  const [runs, setRuns] = useState([])

  useEffect(() => {
    api.snapshots(policy.id).then((s) => {
      setSnaps(s)
      const latest = [...s].sort((a, b) => b.version - a.version)[0]
      setSnapId(latest?.id ?? '')
    })
    api.runs().then(setRuns).catch(() => {})
  }, [policy.id])

  const probes = probesText.split(/[\s,]+/).filter(Boolean)

  async function doReplay() {
    setErr(''); setReplay(null)
    try { setReplay(await api.replay(Number(snapId), probes)) }
    catch (e) { setErr(e.message) }
  }
  async function doCV() {
    setErr(''); setCv(null)
    try {
      setCv(await api.crossValidate(Number(snapId), probes, node))
      setRuns(await api.runs())
    } catch (e) { setErr(e.message) }
  }

  return (
    <div className="replay">
      <div className="bar">
        <span>有序输入回放 + 本地 FRR 容器交叉验证</span>
        <select value={snapId} onChange={(e) => setSnapId(e.target.value)}>
          {snaps.map((s) => <option key={s.id} value={s.id}>v{s.version} {s.label}</option>)}
        </select>
        <select value={node} onChange={(e) => setNode(e.target.value)}>
          <option value="a">router-a (127.0.0.1:2222)</option>
          <option value="b">router-b (127.0.0.1:2223)</option>
        </select>
        <button onClick={doReplay} disabled={!snapId}>模拟器回放</button>
        <button onClick={doCV} disabled={!snapId} className="primary">
          推送 FRR 并比对
        </button>
        {err && <span className="error">{err}</span>}
      </div>

      <div className="cols">
        <div>
          <h4>有序探针（按行，顺序即生效次序）</h4>
          <textarea rows={10} value={probesText}
            onChange={(e) => setProbesText(e.target.value)} />
          <p className="muted">
            推送方式：把快照渲染成 <code>ip/ipv6 prefix-list ... seq ... [ge/le]</code>
            配置到本地容器，再用 FRR 原生命令
            <code> show ip prefix-list NAME match PREFIX </code>
            读取 FRR 自己的匹配结果，结束后删除该列表。全程无生产设备连接。
          </p>
          {replay && (
            <details open>
              <summary>下发到 FRR 的配置（可重放）</summary>
              <pre>{replay.frr_config}</pre>
            </details>
          )}
        </div>

        <div>
          {replay && (
            <>
              <h4>模拟器结果（快照 v{replay.version}）</h4>
              <table className="cv">
                <thead><tr><th>#</th><th>前缀</th><th>动作</th><th>命中 seq</th></tr></thead>
                <tbody>
                  {replay.results.map((r) => (
                    <tr key={r.order} className={r.error ? 'badrow' : r.final_action}>
                      <td>{r.order + 1}</td><td><code>{r.prefix}</code></td>
                      <td>{r.error ? <span className="error">{r.error}</span> : r.final_action}</td>
                      <td>{r.matched_seq ?? (r.error ? '—' : '默认')}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}

          {cv && (
            <div className={`cvbox ${cv.status}`}>
              <h4>FRR {cv.node.toUpperCase()} 比对：
                {cv.status === 'match'
                  ? <span className="ok">✓ {cv.rows.length} 个探针全部一致</span>
                  : <span className="error">✗ {cv.mismatch_count} 处不一致</span>}
              </h4>
              <table className="cv">
                <thead><tr>
                  <th>#</th><th>前缀</th><th>模拟器</th><th>FRR</th><th>seq 一致</th>
                </tr></thead>
                <tbody>
                  {cv.rows.map((r) => (
                    <tr key={r.order} className={r.action_match && r.seq_match ? 'okrow' : 'badrow'}>
                      <td>{r.order + 1}</td><td><code>{r.prefix}</code></td>
                      <td className={r.sim_action}>{r.sim_action} #{r.sim_seq ?? '默认'}</td>
                      <td className={r.frr_action}>{r.frr_action} #{r.frr_seq ?? '默认'}</td>
                      <td>{r.action_match && r.seq_match ? '✓' : '✗'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      <h4>历史验证运行</h4>
      <table className="cv">
        <thead><tr><th>id</th><th>快照</th><th>节点</th><th>状态</th><th>不一致数</th><th>时间</th></tr></thead>
        <tbody>
          {runs.map((r) => (
            <tr key={r.id}>
              <td>{r.id}</td><td>{r.snapshot_id}</td><td>{r.node}</td>
              <td className={r.status === 'match' ? 'permit' : 'deny'}>{r.status}</td>
              <td>{r.detail?.mismatch_count ?? 0}</td>
              <td>{r.created_at}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
