import { useEffect, useState } from 'react'
import { api, type Server } from '../services/api'

export default function ServersPage() {
  const [servers, setServers] = useState<Server[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [showAddForm, setShowAddForm] = useState(false)
  const [formData, setFormData] = useState({
    name: '',
    host: '',
    port: 22,
    username: 'root',
    password: '',
    key_path: '',
    tags: '',
  })

  useEffect(() => {
    loadServers()
  }, [])

  async function loadServers() {
    try {
      setLoading(true)
      const data = await api.getServers()
      setServers(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load servers')
    } finally {
      setLoading(false)
    }
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    try {
      await api.createServer(formData)
      setShowAddForm(false)
      setFormData({ name: '', host: '', port: 22, username: 'root', password: '', key_path: '', tags: '' })
      loadServers()
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Failed to create server')
    }
  }

  async function handleDelete(id: number) {
    if (!confirm('Are you sure you want to delete this server?')) return
    try {
      await api.deleteServer(id)
      loadServers()
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Failed to delete server')
    }
  }

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
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Servers</h1>
          <p className="text-sm text-slate-400">Manage your infrastructure servers</p>
        </div>
        <button
          onClick={() => setShowAddForm(!showAddForm)}
          className="rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500"
        >
          {showAddForm ? 'Cancel' : 'Add Server'}
        </button>
      </div>

      {showAddForm && (
        <form onSubmit={handleSubmit} className="rounded-lg border border-slate-800 bg-slate-900/50 p-4 space-y-3">
          <div className="grid gap-3 md:grid-cols-2">
            <div>
              <label className="block text-sm text-slate-400">Name</label>
              <input
                type="text"
                value={formData.name}
                onChange={e => setFormData({ ...formData, name: e.target.value })}
                className="mt-1 w-full rounded-md border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-white"
                placeholder="Production Server"
                required
              />
            </div>
            <div>
              <label className="block text-sm text-slate-400">Host</label>
              <input
                type="text"
                value={formData.host}
                onChange={e => setFormData({ ...formData, host: e.target.value })}
                className="mt-1 w-full rounded-md border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-white"
                placeholder="192.168.1.100 or server.example.com"
                required
              />
            </div>
            <div>
              <label className="block text-sm text-slate-400">Port</label>
              <input
                type="number"
                value={formData.port}
                onChange={e => setFormData({ ...formData, port: parseInt(e.target.value) })}
                className="mt-1 w-full rounded-md border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-white"
              />
            </div>
            <div>
              <label className="block text-sm text-slate-400">Username</label>
              <input
                type="text"
                value={formData.username}
                onChange={e => setFormData({ ...formData, username: e.target.value })}
                className="mt-1 w-full rounded-md border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-white"
              />
            </div>
            <div>
              <label className="block text-sm text-slate-400">Password (optional)</label>
              <input
                type="password"
                value={formData.password}
                onChange={e => setFormData({ ...formData, password: e.target.value })}
                className="mt-1 w-full rounded-md border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-white"
              />
            </div>
            <div>
              <label className="block text-sm text-slate-400">SSH Key Path (optional)</label>
              <input
                type="text"
                value={formData.key_path}
                onChange={e => setFormData({ ...formData, key_path: e.target.value })}
                className="mt-1 w-full rounded-md border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-white"
                placeholder="~/.ssh/id_rsa"
              />
            </div>
            <div className="md:col-span-2">
              <label className="block text-sm text-slate-400">Tags (comma separated)</label>
              <input
                type="text"
                value={formData.tags}
                onChange={e => setFormData({ ...formData, tags: e.target.value })}
                className="mt-1 w-full rounded-md border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-white"
                placeholder="production, nginx, web"
              />
            </div>
          </div>
          <div className="flex justify-end">
            <button
              type="submit"
              className="rounded-md bg-green-600 px-4 py-2 text-sm font-medium text-white hover:bg-green-500"
            >
              Create Server
            </button>
          </div>
        </form>
      )}

      {servers.length === 0 ? (
        <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-8 text-center">
          <p className="text-slate-400">No servers configured yet.</p>
          <button
            onClick={() => setShowAddForm(true)}
            className="mt-2 text-sm text-blue-400 hover:text-blue-300"
          >
            Add your first server →
          </button>
        </div>
      ) : (
        <div className="rounded-lg border border-slate-800 bg-slate-900/50 overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-slate-800/50 text-slate-400">
              <tr>
                <th className="px-4 py-3 text-left">Name</th>
                <th className="px-4 py-3 text-left">Host</th>
                <th className="px-4 py-3 text-left">Username</th>
                <th className="px-4 py-3 text-left">Tags</th>
                <th className="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {servers.map(server => (
                <tr key={server.id} className="hover:bg-slate-800/30">
                  <td className="px-4 py-3 font-medium">{server.name}</td>
                  <td className="px-4 py-3 text-slate-400">{server.host}:{server.port}</td>
                  <td className="px-4 py-3 text-slate-400">{server.username}</td>
                  <td className="px-4 py-3">
                    {server.tags && (
                      <span className="inline-flex gap-1">
                        {server.tags.split(',').map((tag, i) => (
                          <span key={i} className="rounded bg-slate-700 px-2 py-0.5 text-xs">{tag.trim()}</span>
                        ))}
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-right">
                    <button
                      onClick={() => handleDelete(server.id)}
                      className="text-sm text-red-400 hover:text-red-300"
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
