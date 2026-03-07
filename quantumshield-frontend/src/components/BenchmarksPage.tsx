import { useState } from 'react';
import { Play, RefreshCw, BarChart3, Clock, Zap } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { api } from '../lib/api';

interface BenchmarkResult {
  operation: string;
  algorithm: string;
  category: string;
  iterations: number;
  mean_ms: number;
  median_ms: number;
  min_ms: number;
  max_ms: number;
  stddev_ms: number;
}

interface SuiteData {
  run_timestamp: number;
  total_duration_s: number;
  results: BenchmarkResult[];
}

export default function BenchmarksPage() {
  const [suite, setSuite] = useState<SuiteData | null>(null);
  const [loading, setLoading] = useState(false);
  const [iterations, setIterations] = useState(100);

  const runBenchmarks = async (iters?: number) => {
    setLoading(true);
    try {
      const data = iters ? await api.runBenchmarks(iters) : await api.runQuickBenchmarks();
      setSuite(data);
    } catch (e) {
      console.error(e);
    }
    setLoading(false);
  };

  // Prepare chart data
  const sigChartData = suite ? (() => {
    const dil = suite.results.filter(r => r.algorithm === 'Dilithium3' && r.category === 'Signature');
    const rsa = suite.results.filter(r => r.algorithm === 'RSA-2048');
    const ops = ['Key Generation', 'Sign', 'Verify'];
    return ops.map(op => ({
      operation: op,
      'Dilithium3': dil.find(r => r.operation === op)?.mean_ms || 0,
      'RSA-2048': rsa.find(r => r.operation === op)?.mean_ms || 0,
    }));
  })() : [];

  const kemChartData = suite ? (() => {
    const kyber = suite.results.filter(r => r.algorithm === 'Kyber768');
    const x25519 = suite.results.filter(r => r.algorithm.includes('X25519'));
    return [
      {
        operation: 'Key Generation',
        'Kyber768': kyber.find(r => r.operation === 'Key Generation')?.mean_ms || 0,
        'X25519': x25519.find(r => r.operation === 'Key Generation')?.mean_ms || 0,
      },
      {
        operation: 'Encap/Exchange',
        'Kyber768': kyber.find(r => r.operation === 'Encapsulation')?.mean_ms || 0,
        'X25519': x25519.find(r => r.operation === 'Key Exchange')?.mean_ms || 0,
      },
    ];
  })() : [];

  return (
    <div className="space-y-8">
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h2 className="text-2xl font-semibold text-zinc-100">Benchmark Results</h2>
          <p className="text-sm text-zinc-500 mt-1">Post-quantum vs classical cryptography performance comparison</p>
        </div>
        <div className="flex items-center gap-3">
          <select
            value={iterations}
            onChange={e => setIterations(Number(e.target.value))}
            className="bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-300"
          >
            <option value={10}>10 iterations</option>
            <option value={100}>100 iterations</option>
            <option value={1000}>1000 iterations</option>
          </select>
          <button
            onClick={() => runBenchmarks(iterations)}
            disabled={loading}
            className="flex items-center gap-2 px-4 py-2.5 bg-violet-600 hover:bg-violet-500 disabled:opacity-50 text-white text-sm font-medium rounded-lg transition-colors"
          >
            {loading ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
            {loading ? 'Running...' : 'Run Benchmarks'}
          </button>
        </div>
      </div>

      {suite && (
        <>
          {/* Summary cards */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
              <div className="flex items-center gap-2 mb-2">
                <Clock className="h-4 w-4 text-zinc-500" />
                <span className="text-xs text-zinc-500">Duration</span>
              </div>
              <p className="text-lg font-semibold text-zinc-100">{suite.total_duration_s.toFixed(2)}s</p>
            </div>
            <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
              <div className="flex items-center gap-2 mb-2">
                <BarChart3 className="h-4 w-4 text-zinc-500" />
                <span className="text-xs text-zinc-500">Operations</span>
              </div>
              <p className="text-lg font-semibold text-zinc-100">{suite.results.length}</p>
            </div>
            <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
              <div className="flex items-center gap-2 mb-2">
                <Zap className="h-4 w-4 text-zinc-500" />
                <span className="text-xs text-zinc-500">Fastest Op</span>
              </div>
              <p className="text-lg font-semibold text-zinc-100">
                {suite.results.reduce((a, b) => a.min_ms < b.min_ms ? a : b).algorithm}
              </p>
              <p className="text-xs text-zinc-500">{suite.results.reduce((a, b) => a.min_ms < b.min_ms ? a : b).min_ms.toFixed(4)}ms</p>
            </div>
            <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
              <div className="flex items-center gap-2 mb-2">
                <Clock className="h-4 w-4 text-zinc-500" />
                <span className="text-xs text-zinc-500">KEMTLS Handshake</span>
              </div>
              <p className="text-lg font-semibold text-zinc-100">
                {(suite.results.find(r => r.operation === 'Full Handshake')?.mean_ms || 0).toFixed(2)}ms
              </p>
            </div>
          </div>

          {/* Charts */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-6">
              <h3 className="text-sm font-medium text-zinc-400 uppercase tracking-wider mb-4">Signature: Dilithium3 vs RSA-2048</h3>
              <ResponsiveContainer width="100%" height={280}>
                <BarChart data={sigChartData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#27272a" />
                  <XAxis dataKey="operation" tick={{ fill: '#71717a', fontSize: 12 }} />
                  <YAxis tick={{ fill: '#71717a', fontSize: 12 }} />
                  <Tooltip contentStyle={{ background: '#18181b', border: '1px solid #27272a', borderRadius: '8px', color: '#fafafa' }} />
                  <Legend />
                  <Bar dataKey="Dilithium3" fill="#8b5cf6" radius={[4, 4, 0, 0]} />
                  <Bar dataKey="RSA-2048" fill="#f59e0b" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>

            <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-6">
              <h3 className="text-sm font-medium text-zinc-400 uppercase tracking-wider mb-4">KEM: Kyber768 vs X25519</h3>
              <ResponsiveContainer width="100%" height={280}>
                <BarChart data={kemChartData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#27272a" />
                  <XAxis dataKey="operation" tick={{ fill: '#71717a', fontSize: 12 }} />
                  <YAxis tick={{ fill: '#71717a', fontSize: 12 }} />
                  <Tooltip contentStyle={{ background: '#18181b', border: '1px solid #27272a', borderRadius: '8px', color: '#fafafa' }} />
                  <Legend />
                  <Bar dataKey="Kyber768" fill="#10b981" radius={[4, 4, 0, 0]} />
                  <Bar dataKey="X25519" fill="#ef4444" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Results table */}
          <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-6">
            <h3 className="text-sm font-medium text-zinc-400 uppercase tracking-wider mb-4">Detailed Results</h3>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-zinc-500 text-xs uppercase tracking-wider border-b border-zinc-800">
                    <th className="text-left py-3 pr-4">Operation</th>
                    <th className="text-left py-3 pr-4">Algorithm</th>
                    <th className="text-left py-3 pr-4">Category</th>
                    <th className="text-right py-3 pr-4">Mean (ms)</th>
                    <th className="text-right py-3 pr-4">Median (ms)</th>
                    <th className="text-right py-3 pr-4">Min (ms)</th>
                    <th className="text-right py-3 pr-4">Max (ms)</th>
                    <th className="text-right py-3">StdDev (ms)</th>
                  </tr>
                </thead>
                <tbody>
                  {suite.results.map((r, i) => (
                    <tr key={i} className="border-b border-zinc-800/50 last:border-0 hover:bg-zinc-800/30">
                      <td className="py-2.5 pr-4 text-zinc-300">{r.operation}</td>
                      <td className="py-2.5 pr-4">
                        <span className={`text-xs font-mono px-2 py-0.5 rounded ${r.category.includes('Classical') ? 'bg-amber-500/10 text-amber-400' : 'bg-violet-500/10 text-violet-400'}`}>
                          {r.algorithm}
                        </span>
                      </td>
                      <td className="py-2.5 pr-4 text-zinc-500 text-xs">{r.category}</td>
                      <td className="py-2.5 pr-4 text-right font-mono text-zinc-200">{r.mean_ms.toFixed(4)}</td>
                      <td className="py-2.5 pr-4 text-right font-mono text-zinc-400">{r.median_ms.toFixed(4)}</td>
                      <td className="py-2.5 pr-4 text-right font-mono text-zinc-400">{r.min_ms.toFixed(4)}</td>
                      <td className="py-2.5 pr-4 text-right font-mono text-zinc-400">{r.max_ms.toFixed(4)}</td>
                      <td className="py-2.5 text-right font-mono text-zinc-500">{r.stddev_ms.toFixed(4)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}

      {!suite && !loading && (
        <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-12 text-center">
          <BarChart3 className="h-12 w-12 text-zinc-700 mx-auto mb-4" />
          <p className="text-zinc-500">Run benchmarks to compare post-quantum and classical cryptography</p>
          <p className="text-xs text-zinc-600 mt-2">Measures Kyber768, Dilithium3, RSA-2048, X25519, KEMTLS, and JWT operations</p>
        </div>
      )}
    </div>
  );
}
