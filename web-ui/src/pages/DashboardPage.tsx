import { useEffect, useState } from 'react'
import { api, type Server, type Job, type DaemonStatus } from '../services/api'

function StatCard({ label, value, color = 'text-slate-100' }: { label: string; value: string | number; color?: string }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-4">
      <div className="text-sm text-slate-400">{label}</div>
      <div className={`mt-1 text-2xl font-semibold ${color}`}>{value}</div>
    </div>
  )
}

function StatusBadge({ running }: { running: boolean }) {
  return (
    <span className={`inline-flex items-center rounded-full px-2 py-1 text-xs font-medium ${running ? 'bg-green-500/20 text-green-400' : 'bg-slate-700 text-slate-400'}`}>
      {running ? '● Running' : '○ Stopped'}
    </span>
  )
}

export default function DashboardPage() {
  const [servers, setServers] = useState<Server[]>([])
  const [jobs, setJobs] = useState<Job[]>([])
  const [daemonStatus, setDaemonStatus] = useState<DaemonStatus | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    async function loadData() {
      try {
        setLoading(true)
        const [serversData, jobsData, daemonData] = await Promise.all([
          api.getServers(),
          api.getJobs(),
          api.getDaemonStatus(),
        ])
        setServers(serversData)
        setJobs(jobsData)
        setDaemonStatus(daemonData)
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load data')
      } finally {
        setLoading(false)
      }
    }
    loadData()
  }, [])

  const runningJobs = jobs.filter(j => j.status === 'running').length
  const completedJobs = jobs.filter(j => j.status === 'success').length
  const failedJobs = jobs.filter(j => j.status === 'failed').length

  if (loading) {
    return (
      <div className="flex h-64 items-center justify-center">
        <div className="text-slate-400">Loading...</div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="rounded-lg border border-red-800 bg-red-950/30 p-4 text-red-400">
        Error: {error}
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Dashboard</h1>
        <p className="mt-1 text-sm text-slate-400">
          Overview of your infrastructure and monitoring status
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <StatCard label="Servers" value={servers.length} />
        <StatCard label="Total Jobs" value={jobs.length} />
        <StatCard label="Running Jobs" value={runningJobs} color="text-blue-400" />
        <StatCard 
          label="Daemon Status" 
          value={daemonStatus?.running ? 'Running' : 'Stopped'} 
          color={daemonStatus?.running ? 'text-green-400' : 'text-slate-400'}
        />
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-4">
          <h3 className="font-medium">Job Summary</h3>
          <div className="mt-3 space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-slate-400">Completed</span>
              <span className="text-green-400">{completedJobs}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Failed</span>
              <span className="text-red-400">{failedJobs}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Queued</span>
              <span className="text-slate-300">{jobs.filter(j => j.status === 'queued').length}</span>
            </div>
          </div>
        </div>

        <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-4">
          <h3 className="font-medium">Daemon Monitoring</h3>
          <div className="mt-3 space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-slate-400">Status</span>
              <StatusBadge running={daemonStatus?.running ?? false} />
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Interval</span>
              <span>{daemonStatus?.interval ?? 3600}s</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Monitored Servers</span>
              <span>{daemonStatus?.servers?.length ?? 0}</span>
            </div>
          </div>
        </div>

        <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-4">
          <h3 className="font-medium">Quick Links</h3>
          <div className="mt-3 space-y-2">
            <a href="/servers" className="block text-sm text-blue-400 hover:text-blue-300">→ Manage Servers</a>
            <a href="/jobs" className="block text-sm text-blue-400 hover:text-blue-300">→ View Jobs</a>
            <a href="/settings/daemon" className="block text-sm text-blue-400 hover:text-blue-300">→ Configure Daemon</a>
          </div>
        </div>
      </div>

      {servers.length === 0 && (
        <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-6 text-center">
          <p className="text-slate-400">No servers configured yet.</p>
          <a href="/servers" className="mt-2 inline-block text-sm text-blue-400 hover:text-blue-300">
            Add your first server →
          </a>
        </div>
      )}
    </div>
  )
}
