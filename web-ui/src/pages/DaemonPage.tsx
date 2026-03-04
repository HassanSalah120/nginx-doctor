import { useEffect, useState } from 'react'
import { api, type Server } from '../services/api'

function StatusBadge({ running }: { running: boolean }) {
  return (
    <span className={`inline-flex items-center rounded-full px-3 py-1 text-sm font-medium ${running ? 'bg-green-500/20 text-green-400' : 'bg-slate-700 text-slate-400'}`}>
      {running ? '● Running' : '○ Stopped'}
    </span>
  )
}

export default function DaemonPage() {
  const [status, setStatus] = useState<{ running: boolean; pid: number | null; interval: number; servers: number[]; scan_count: number } | null>(null)
  const [servers, setServers] = useState<Server[]>([])
  const [scanInterval, setScanInterval] = useState(3600)
  const [selectedServers, setSelectedServers] = useState<number[]>([])
  const [loading, setLoading] = useState(true)
  const [actionLoading, setActionLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [message, setMessage] = useState<string | null>(null)

  useEffect(() => {
    loadData()
  }, [])

  useEffect(() => {
    if (!status?.running) return
    const intervalId = setInterval(loadData, 5000)
    return () => clearInterval(intervalId)
  }, [status?.running])

  async function loadData() {
    try {
      const [statusData, serversData] = await Promise.all([api.getDaemonStatus(), api.getServers()])
      setStatus(statusData)
      setServers(serversData)
      if (statusData.servers?.length > 0) {
        setSelectedServers(statusData.servers)
      }
      if (statusData.interval) {
        setScanInterval(statusData.interval)
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load daemon status')
    } finally {
      setLoading(false)
    }
  }

  async function handleStart() {
    try {
      setActionLoading(true)
      await api.startDaemon(scanInterval, selectedServers.length > 0 ? selectedServers : servers.map(s => s.id))
      setMessage('Daemon started successfully')
      loadData()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start daemon')
    } finally {
      setActionLoading(false)
    }
  }

  async function handleStop() {
    try {
      setActionLoading(true)
      await api.stopDaemon()
      setMessage('Daemon stopped successfully')
      loadData()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to stop daemon')
    } finally {
      setActionLoading(false)
    }
  }

  async function handleScanNow() {
    try {
      setActionLoading(true)
      await api.triggerScan()
      setMessage('Scan triggered')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to trigger scan')
    } finally {
      setActionLoading(false)
    }
  }

  function toggleServer(id: number) {
    setSelectedServers(prev =>
      prev.includes(id) ? prev.filter(sid => sid !== id) : [...prev, id]
    )
  }

  if (loading) {
    return (
      <div className="flex h-64 items-center justify-center">
        <div className="text-slate-400">Loading...</div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Daemon</h1>
        <p className="text-sm text-slate-400">Background monitoring and scheduled scans</p>
      </div>

      {message && (
        <div className="rounded-lg border border-green-800 bg-green-950/30 p-3 text-green-400">
          {message}
        </div>
      )}

      {error && (
        <div className="rounded-lg border border-red-800 bg-red-950/30 p-3 text-red-400">
          {error}
        </div>
      )}

      <div className="grid gap-4 md:grid-cols-2">
        <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-4">
          <h3 className="font-medium">Status</h3>
          <div className="mt-4 flex items-center gap-4">
            <StatusBadge running={status?.running ?? false} />
            {status?.pid && <span className="text-sm text-slate-400">PID: {status.pid}</span>}
          </div>
          <div className="mt-4 grid grid-cols-2 gap-4 text-sm">
            <div>
              <span className="text-slate-400">Scan Interval</span>
              <p className="font-medium">{status?.interval ?? 3600}s</p>
            </div>
            <div>
              <span className="text-slate-400">Total Scans</span>
              <p className="font-medium">{status?.scan_count ?? 0}</p>
            </div>
          </div>
        </div>

        <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-4">
          <h3 className="font-medium">Actions</h3>
          <div className="mt-4 space-y-2">
            {status?.running ? (
              <>
                <button
                  onClick={handleStop}
                  disabled={actionLoading}
                  className="w-full rounded-md bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-500 disabled:opacity-50"
                >
                  {actionLoading ? 'Stopping...' : 'Stop Daemon'}
                </button>
                <button
                  onClick={handleScanNow}
                  disabled={actionLoading}
                  className="w-full rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500 disabled:opacity-50"
                >
                  {actionLoading ? 'Triggering...' : 'Scan Now'}
                </button>
              </>
            ) : (
              <button
                onClick={handleStart}
                disabled={actionLoading || servers.length === 0}
                className="w-full rounded-md bg-green-600 px-4 py-2 text-sm font-medium text-white hover:bg-green-500 disabled:opacity-50"
              >
                {actionLoading ? 'Starting...' : 'Start Daemon'}
              </button>
            )}
          </div>
        </div>
      </div>

      <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-4">
        <h3 className="font-medium">Configuration</h3>
        <div className="mt-4 space-y-4">
          <div>
            <label className="block text-sm text-slate-400">Scan Interval (seconds)</label>
            <input
              type="number"
              value={scanInterval}
              onChange={e => setScanInterval(parseInt(e.target.value) || 3600)}
              disabled={status?.running}
              className="mt-1 w-full rounded-md border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-white disabled:opacity-50"
              placeholder="3600"
            />
          </div>

          <div>
            <label className="block text-sm text-slate-400">Monitored Servers</label>
            <div className="mt-2 space-y-2">
              {servers.length === 0 ? (
                <p className="text-sm text-slate-500">No servers configured. Add servers first.</p>
              ) : (
                servers.map(server => (
                  <label key={server.id} className="flex items-center gap-2 text-sm">
                    <input
                      type="checkbox"
                      checked={selectedServers.includes(server.id)}
                      onChange={() => toggleServer(server.id)}
                      disabled={status?.running}
                      className="rounded border-slate-600 bg-slate-700"
                    />
                    <span>{server.name}</span>
                    <span className="text-slate-500">({server.host})</span>
                  </label>
                ))
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
