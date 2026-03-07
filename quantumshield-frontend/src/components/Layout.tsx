import { useState } from 'react';
import { Shield, Activity, Lock, BarChart3, Radar, Home, Menu, X } from 'lucide-react';

interface LayoutProps {
  children: React.ReactNode;
  currentPage: string;
  onNavigate: (page: string) => void;
}

const NAV_ITEMS = [
  { id: 'status', label: 'System Status', icon: Home },
  { id: 'kemtls', label: 'KEMTLS Monitor', icon: Lock },
  { id: 'auth', label: 'Authentication', icon: Activity },
  { id: 'benchmarks', label: 'Benchmarks', icon: BarChart3 },
  { id: 'scanner', label: 'Quantum Scanner', icon: Radar },
];

export default function Layout({ children, currentPage, onNavigate }: LayoutProps) {
  const [sidebarOpen, setSidebarOpen] = useState(false);

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 flex">
      {/* Sidebar */}
      <aside className={`fixed inset-y-0 left-0 z-50 w-64 bg-zinc-900 border-r border-zinc-800 transform transition-transform duration-200 lg:translate-x-0 lg:static ${sidebarOpen ? 'translate-x-0' : '-translate-x-full'}`}>
        <div className="flex items-center gap-3 px-6 py-5 border-b border-zinc-800">
          <Shield className="h-7 w-7 text-violet-500" />
          <div>
            <h1 className="text-base font-semibold text-zinc-100 tracking-tight">QuantumShield</h1>
            <p className="text-xs text-zinc-500">Post-Quantum Security</p>
          </div>
        </div>
        <nav className="px-3 py-4 space-y-1">
          {NAV_ITEMS.map(item => {
            const Icon = item.icon;
            const active = currentPage === item.id;
            return (
              <button
                key={item.id}
                onClick={() => { onNavigate(item.id); setSidebarOpen(false); }}
                className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-colors ${active ? 'bg-violet-500/10 text-violet-400' : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800'}`}
              >
                <Icon className="h-4 w-4" />
                {item.label}
              </button>
            );
          })}
        </nav>
        <div className="absolute bottom-0 left-0 right-0 p-4 border-t border-zinc-800">
          <div className="flex items-center gap-2">
            <div className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse" />
            <span className="text-xs text-zinc-500">Quantum Resistant</span>
          </div>
        </div>
      </aside>

      {/* Overlay */}
      {sidebarOpen && (
        <div className="fixed inset-0 z-40 bg-black/50 lg:hidden" onClick={() => setSidebarOpen(false)} />
      )}

      {/* Main */}
      <div className="flex-1 flex flex-col min-h-screen">
        <header className="sticky top-0 z-30 bg-zinc-900/80 backdrop-blur-sm border-b border-zinc-800 px-4 py-3 flex items-center gap-4 lg:px-8">
          <button className="lg:hidden text-zinc-400 hover:text-zinc-100" onClick={() => setSidebarOpen(true)}>
            {sidebarOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
          </button>
          <div className="flex-1" />
          <div className="flex items-center gap-3 text-xs text-zinc-500">
            <span className="hidden sm:inline">KEMTLS</span>
            <span className="hidden sm:inline text-zinc-700">|</span>
            <span className="hidden sm:inline">Kyber768</span>
            <span className="hidden sm:inline text-zinc-700">|</span>
            <span className="hidden sm:inline">Dilithium3</span>
            <div className="h-6 w-px bg-zinc-800" />
            <div className="flex items-center gap-1.5">
              <div className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
              <span>Operational</span>
            </div>
          </div>
        </header>
        <main className="flex-1 p-4 lg:p-8 overflow-auto">
          {children}
        </main>
      </div>
    </div>
  );
}
