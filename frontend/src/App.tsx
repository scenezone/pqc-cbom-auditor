import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { BrowserRouter, Route, Routes } from 'react-router-dom'
import Navbar from './components/Navbar'
import Footer from './components/Footer'
import Home from './pages/Home'
import NewAudit from './pages/NewAudit'
import ScanProgress from './pages/ScanProgress'
import AuditDashboard from './pages/AuditDashboard'
import FindingsExplorer from './pages/FindingsExplorer'
import CBOMViewerPage from './pages/CBOMViewerPage'
import Reports from './pages/Reports'
import Methodology from './pages/Methodology'
import ProjectList from './pages/ProjectList'

const qc = new QueryClient()

export default function App() {
  return (
    <QueryClientProvider client={qc}>
      <BrowserRouter>
        <div className="min-h-screen text-slate-100">
          <Navbar />
          <main className="mx-auto min-h-[calc(100vh-140px)] max-w-[1440px] px-4 py-7 sm:px-6 sm:py-9 lg:px-8">
            <Routes>
              <Route path="/" element={<Home />} />
              <Route path="/projects" element={<ProjectList />} />
              <Route path="/audits" element={<ProjectList />} />
              <Route path="/new-audit" element={<NewAudit />} />
              <Route path="/scans/:scanId/progress" element={<ScanProgress />} />
              <Route path="/scans/:scanId" element={<AuditDashboard />} />
              <Route path="/scans/:scanId/findings" element={<FindingsExplorer />} />
              <Route path="/scans/:scanId/cbom" element={<CBOMViewerPage />} />
              <Route path="/scans/:scanId/reports" element={<Reports />} />
              <Route path="/methodology" element={<Methodology />} />
            </Routes>
          </main>
          <Footer />
        </div>
      </BrowserRouter>
    </QueryClientProvider>
  )
}
