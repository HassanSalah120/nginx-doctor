export default function DashboardPage() {
  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Dashboard</h1>
        <p className="mt-1 text-sm text-slate-400">
          This React UI is being migrated. Next: wire real data from the existing FastAPI APIs.
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <div className="rounded-lg border border-slate-900 bg-slate-950 p-4">
          <div className="text-sm text-slate-400">Servers</div>
          <div className="mt-1 text-2xl font-semibold">-</div>
        </div>
        <div className="rounded-lg border border-slate-900 bg-slate-950 p-4">
          <div className="text-sm text-slate-400">Jobs</div>
          <div className="mt-1 text-2xl font-semibold">-</div>
        </div>
        <div className="rounded-lg border border-slate-900 bg-slate-950 p-4">
          <div className="text-sm text-slate-400">Daemon</div>
          <div className="mt-1 text-2xl font-semibold">-</div>
        </div>
      </div>
    </div>
  )
}
