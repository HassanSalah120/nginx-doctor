const API_BASE = '/api'

export interface Server {
  id: number
  name: string
  host: string
  port: number
  username: string
  tags: string
  created_at: string
}

export interface Job {
  id: number
  server_id: number
  status: 'queued' | 'running' | 'success' | 'failed' | 'cancelled'
  score: number | null
  summary: string | null
  created_at: string
  started_at: string | null
  finished_at: string | null
}

export interface DaemonStatus {
  running: boolean
  pid: number | null
  interval: number
  servers: number[]
  scan_count: number
}

class ApiService {
  private async fetch<T>(path: string, options?: RequestInit): Promise<T> {
    const response = await fetch(`${API_BASE}${path}`, options)
    if (!response.ok) {
      throw new Error(`API error: ${response.status}`)
    }
    return response.json()
  }

  async getServers(): Promise<Server[]> {
    const data = await this.fetch<{ servers: Server[] }>('/servers')
    return data.servers || []
  }

  async createServer(server: Omit<Server, 'id' | 'created_at'>): Promise<Server> {
    const data = await this.fetch<{ server: Server }>('/servers', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(server),
    })
    return data.server
  }

  async deleteServer(id: number): Promise<void> {
    await this.fetch(`/servers/${id}`, { method: 'DELETE' })
  }

  async getJobs(): Promise<Job[]> {
    const data = await this.fetch<{ jobs: Job[] }>('/jobs')
    return data.jobs || []
  }

  async getDaemonStatus(): Promise<DaemonStatus> {
    return this.fetch<DaemonStatus>('/daemon/status')
  }

  async startDaemon(interval: number, serverIds: number[]): Promise<void> {
    await this.fetch('/daemon/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ interval, server_ids: serverIds }),
    })
  }

  async stopDaemon(): Promise<void> {
    await this.fetch('/daemon/stop', { method: 'POST' })
  }

  async triggerScan(): Promise<void> {
    await this.fetch('/daemon/scan-now', { method: 'POST' })
  }
}

export const api = new ApiService()
