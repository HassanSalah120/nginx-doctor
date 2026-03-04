import { createBrowserRouter } from 'react-router-dom'

import AppLayout from './components/AppLayout'
import DashboardPage from './pages/DashboardPage'
import ServersPage from './pages/ServersPage'
import PlaceholderPage from './pages/PlaceholderPage'

export const router = createBrowserRouter([
  {
    element: <AppLayout />,
    children: [
      { path: '/', element: <DashboardPage /> },
      { path: '/servers', element: <ServersPage /> },
      { path: '/jobs', element: <PlaceholderPage title="Jobs" /> },
      { path: '/jobs/:jobId', element: <PlaceholderPage title="Job Details" /> },
      { path: '/reports/:jobId', element: <PlaceholderPage title="Report" /> },
      {
        path: '/settings/integrations',
        element: <PlaceholderPage title="Integrations" />,
      },
      { path: '/settings/daemon', element: <PlaceholderPage title="Daemon" /> },
      { path: '/kubernetes', element: <PlaceholderPage title="Kubernetes" /> },
      { path: '/wizard', element: <PlaceholderPage title="Wizard" /> },
      { path: '*', element: <PlaceholderPage title="Not Found" /> },
    ],
  },
])
