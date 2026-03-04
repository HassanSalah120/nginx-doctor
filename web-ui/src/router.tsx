import { createBrowserRouter } from 'react-router-dom'

import AppLayout from './components/AppLayout'
import DashboardPage from './pages/DashboardPage'
import ServersPage from './pages/ServersPage'
import JobsPage from './pages/JobsPage'
import DaemonPage from './pages/DaemonPage'
import IntegrationsPage from './pages/IntegrationsPage'
import KubernetesPage from './pages/KubernetesPage'
import PlaceholderPage from './pages/PlaceholderPage'

export const router = createBrowserRouter([
  {
    element: <AppLayout />,
    children: [
      { path: '/', element: <DashboardPage /> },
      { path: '/servers', element: <ServersPage /> },
      { path: '/jobs', element: <JobsPage /> },
      { path: '/jobs/:jobId', element: <PlaceholderPage title="Job Details" /> },
      { path: '/reports/:jobId', element: <PlaceholderPage title="Report" /> },
      {
        path: '/settings/integrations',
        element: <IntegrationsPage />,
      },
      { path: '/settings/daemon', element: <DaemonPage /> },
      { path: '/kubernetes', element: <KubernetesPage /> },
      { path: '/wizard', element: <PlaceholderPage title="Wizard" /> },
      { path: '*', element: <PlaceholderPage title="Not Found" /> },
    ],
  },
])
