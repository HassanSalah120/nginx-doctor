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
  repo_scan_paths?: string | null
  status: 'queued' | 'running' | 'success' | 'failed' | 'cancelled' | 'cancel_requested'
  score: number | null
  summary: string | null
  progress?: number
  created_at: string
  started_at: string | null
  finished_at: string | null
  server_name?: string | null
  server_host?: string | null
}

export interface DaemonStatus {
  running: boolean
  pid: number | null
  interval: number
  servers: number[]
  started_at: string | null
  last_scan: string | null
  next_scan: string | null
  scan_count: number
  error_count: number
}

export interface DaemonHistoryEntry {
  timestamp: string
  server: string
  status: string
  message?: string
  new_findings?: number
  resolved_findings?: number
  findings_total?: number
}

export interface StartScanResponse {
  job_id: number
  status: 'queued'
}

export interface Finding {
  id: number
  job_id: number
  rule_id: string
  category: string | null
  component: string | null
  severity: string
  title: string
  description: string | null
  evidence_ref: string | null
  evidence_json: string | null
  recommendation: string | null
  created_at: string
}

export interface ReportResponse {
  job: Job
  findings: Finding[]
  diagnosis: unknown
  message?: string
  ssl_status?: SSLCertificate[]
  telemetry?: TelemetryData
  logs?: LogsData
  storage?: StorageData
  resources?: ResourcesPressureData
  kernel_limits?: KernelLimitsData
  topology?: TopologyData
  port_map?: PortMapping[]
  service_health?: ServiceHealthItem[]
  support_pack?: ReportSupportPack
}

export interface ReportSupportPack {
  runtime_context: {
    job_id: number | null
    status: string
    doctor_version: string
    doctor_build: string
    mode: string
    os: string
    nginx: string
    target_host: string
    runner: string
    install_hint: string
    started_at: string | null
    finished_at: string | null
    generated_at: string
  }
  raw_diagnosis: unknown
  reproduction_commands: {
    title: string
    command: string
    expected: string
    observed: string
  }[]
  evidence_snippets: {
    topic: string
    command: string
    snippet: string
  }[]
  path_notes: string[]
  coverage_matrix: {
    check: string
    status: 'collected' | 'not_observed' | 'not_accessible' | 'not_applicable' | 'error'
    detail: string
  }[]
  expected_behavior: string[]
}

export interface TopologyData {
  has_data: boolean
  nginx?: {
    version: string
    mode: string
    server_count: number
  }
  apps?: {
    name: string
    type: 'upstream' | 'docker' | 'systemd' | 'php-fpm'
    targets?: string[]
    image?: string
    status?: string
    ports?: number[]
    versions?: string[]
    sockets?: string[]
  }[]
  databases?: {
    type: 'mysql' | 'mariadb' | 'postgresql' | 'mongodb' | 'redis' | 'elasticsearch' | string
    version: string
    status: string
  }[]
  network?: {
    address: string
    port: number
    protocol: string
  }[]
  certbot?: {
    installed: boolean
    service_failed: boolean
    domains: string[]
    expiry_days: number[]
  } | null
}

export interface PortMapping {
  port: number
  service: string
  type: 'tcp' | 'docker'
  status: 'open' | 'closed'
  container_port?: number
}

export interface ServiceHealthItem {
  name: string
  state: string
  sub_state?: string
  restart_count: number
  health: 'healthy' | 'unhealthy'
  ports: number[]
  type?: 'docker'
}

export interface SSLCertificate {
  path: string
  issuer: string
  subject: string
  expires_at: string
  days_remaining: number | null
  sans: string[]
  status: 'critical' | 'warning' | 'caution' | 'healthy' | 'unknown'
  color: 'red' | 'orange' | 'yellow' | 'green' | 'gray'
  urgent: boolean
}

export interface TelemetryData {
  has_data: boolean
  cpu?: {
    cores: number | null
    load_1: number | null
    load_5: number | null
    load_15: number | null
    usage_percent: number | null
    status: 'critical' | 'warning' | 'healthy' | 'unknown'
  }
  memory?: {
    total_gb: number
    available_gb: number | null
    used_gb: number | null
    used_percent: number | null
    status: 'critical' | 'warning' | 'healthy' | 'unknown'
  }
  disks?: {
    mount: string
    total_gb: number
    used_gb: number
    used_percent: number
    status: 'critical' | 'warning' | 'healthy'
  }[]
}

export interface LogsData {
  has_data: boolean
  status?: 'critical' | 'warning' | 'healthy'
  journal_errors_24h?: number | null
  journal_oom_events_24h?: number | null
  nginx_error_counts?: Record<string, number>
  nginx_error_samples?: string[]
  php_fpm_error_counts?: Record<string, number>
  php_fpm_error_samples?: string[]
  docker_crashloop_containers?: string[]
  docker_error_samples?: string[]
  collection_status?: Record<string, string>
  collection_notes?: Record<string, string>
}

export interface StorageData {
  has_data: boolean
  status?: 'critical' | 'warning' | 'healthy'
  mounts?: {
    mount: string
    total_gb: number
    used_gb: number
    used_percent: number
    inode_used_percent: number | null
    read_only: boolean
    status: 'critical' | 'warning' | 'healthy'
  }[]
  read_only_mounts?: string[]
  failed_mount_units?: string[]
  io_wait_percent?: number | null
  io_error_samples?: string[]
  collection_status?: Record<string, string>
  collection_notes?: Record<string, string>
}

export interface ResourcesPressureData {
  has_data: boolean
  status?: 'critical' | 'warning' | 'healthy'
  cpu_cores?: number | null
  load_1?: number | null
  load_5?: number | null
  load_15?: number | null
  load_percent?: number | null
  mem_total_mb?: number | null
  mem_available_mb?: number | null
  mem_used_mb?: number | null
  mem_used_percent?: number | null
  swap_total_mb?: number | null
  swap_free_mb?: number | null
  swap_used_mb?: number | null
  swap_used_percent?: number | null
  oom_events_24h?: number | null
  psi_cpu_some_avg10?: number | null
  psi_memory_some_avg10?: number | null
  psi_io_some_avg10?: number | null
  top_cpu_processes?: string[]
  top_mem_processes?: string[]
  collection_status?: Record<string, string>
  collection_notes?: Record<string, string>
}

export interface KernelLimitsData {
  has_data: boolean
  status?: 'critical' | 'warning' | 'healthy'
  nofile_soft?: number | null
  nofile_hard?: number | null
  fs_file_max?: number | null
  somaxconn?: number | null
  tcp_max_syn_backlog?: number | null
  ip_local_port_range_start?: number | null
  ip_local_port_range_end?: number | null
  ip_local_port_range_width?: number | null
  tcp_fin_timeout?: number | null
  netdev_max_backlog?: number | null
  nginx_worker_connections?: number | null
  nginx_worker_processes?: number | null
  nginx_worker_fd_budget?: number | null
  collection_status?: Record<string, string>
  collection_notes?: Record<string, string>
}

class ApiService {
  private async fetch<T>(path: string, options?: RequestInit): Promise<T> {
    const response = await fetch(`${API_BASE}${path}`, options)
    if (!response.ok) {
      let message = `API error: ${response.status}`
      try {
        const data: unknown = await response.json()
        if (data && typeof data === 'object') {
          const maybeDetail = (data as { detail?: unknown }).detail
          const maybeMessage = (data as { message?: unknown }).message
          const detailText = typeof maybeDetail === 'string' ? maybeDetail : null
          const messageText = typeof maybeMessage === 'string' ? maybeMessage : null
          message = detailText || messageText || message
        }
      } catch {
        // ignore JSON parse errors
      }
      throw new Error(message)
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

  async startScan(serverId: number, options?: { repo_scan_paths?: string }): Promise<StartScanResponse> {
    return this.fetch<StartScanResponse>('/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        server_id: serverId,
        repo_scan_paths: options?.repo_scan_paths || undefined,
      }),
    })
  }

  async getReport(jobId: number): Promise<ReportResponse> {
    return this.fetch<ReportResponse>(`/reports/${jobId}`)
  }

  async getDaemonStatus(): Promise<DaemonStatus> {
    return this.fetch<DaemonStatus>('/daemon/status')
  }

  async getDaemonHistory(limit = 20): Promise<DaemonHistoryEntry[]> {
    return this.fetch<DaemonHistoryEntry[]>(`/daemon/history?limit=${encodeURIComponent(String(limit))}`)
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
