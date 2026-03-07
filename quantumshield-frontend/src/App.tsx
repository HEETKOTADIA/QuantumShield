import { useState } from 'react';
import Layout from './components/Layout';
import StatusPage from './components/StatusPage';
import KEMTLSPage from './components/KEMTLSPage';
import AuthPage from './components/AuthPage';
import BenchmarksPage from './components/BenchmarksPage';
import ScannerPage from './components/ScannerPage';

function App() {
  const [currentPage, setCurrentPage] = useState('status');

  const pages: Record<string, JSX.Element> = {
    status: <StatusPage />,
    kemtls: <KEMTLSPage />,
    auth: <AuthPage />,
    benchmarks: <BenchmarksPage />,
    scanner: <ScannerPage />,
  };

  return (
    <Layout currentPage={currentPage} onNavigate={setCurrentPage}>
      {pages[currentPage] || <StatusPage />}
    </Layout>
  );
}

export default App;
