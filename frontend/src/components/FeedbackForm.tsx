import { useState } from 'react'
import { api } from '../services/api'

export default function FeedbackForm({ scanId }: { scanId?: string }) {
  const [message, setMessage] = useState('')
  const [sent, setSent] = useState(false)
  return (
    <div className="card">
      <h2 className="font-semibold">Feedback</h2>
      <textarea value={message} onChange={e => setMessage(e.target.value)}
        placeholder="Report a false positive, false negative, or suggestion"
        className="mt-3 w-full rounded-lg border border-navy-700 bg-navy-800 p-3 text-sm" rows={4} />
      <button className="btn-primary mt-3" onClick={async () => {
        await api.post('/feedback', { scan_id: scanId, category: 'suggestion', message })
        setSent(true)
      }}>Submit feedback</button>
      {sent && <p className="mt-2 text-sm text-emerald-400">Feedback received.</p>}
    </div>
  )
}
