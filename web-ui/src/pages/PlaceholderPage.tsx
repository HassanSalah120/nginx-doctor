export default function PlaceholderPage({ title }: { title: string }) {
  return (
    <div className="space-y-2">
      <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
      <p className="text-sm text-slate-400">UI migration in progress.</p>
      <div className="rounded-lg border border-slate-900 bg-slate-950 p-4 text-sm text-slate-300">
        This page will be replaced with a real implementation that calls the existing FastAPI endpoints.
      </div>
    </div>
  )
}
