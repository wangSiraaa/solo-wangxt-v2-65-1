import React, { useEffect, useState } from 'react'
import { api } from '../api.js'

export default function Neighbors() {
  const [rows, setRows] = useState([])
  const [err, setErr] = useState('')
  useEffect(() => { api.neighbors().then(setRows).catch(setErr) }, [])

  return (
    <div>
      <h3>本地实验室邻居（配置快照绑定；无生产设备）</h3>
      {err && <div className="error">{err.message || String(err)}</div>}
      <table className="cv">
        <thead><tr>
          <th>名称</th><th>地址</th><th>族</th><th>ASN</th>
          <th>入向策略</th><th>出向策略</th><th>说明</th>
        </tr></thead>
        <tbody>
          {rows.map((n) => (
            <tr key={n.id}>
              <td>{n.name}</td><td><code>{n.ip}</code></td>
              <td>IPv{n.family}</td><td>{n.asn}</td>
              <td>{n.inbound_policy || '—'}</td>
              <td>{n.outbound_policy || '—'}</td>
              <td className="muted">{n.description}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
