import { useState } from 'react';
import { Radar, Play, ShieldAlert, ShieldCheck, AlertTriangle, RefreshCw, X } from 'lucide-react';
import { api } from '../lib/api';

interface ScanResult {
  domain: string;
  port: number;
  scan_time: number;
  tls_version: string;
  cipher_suite: string;
  cipher_bits: number;
  certificate: {
    subject: string;
    issuer: string;
    algorithm: string;
    key_type: string;
    key_bits: number;
    san_domains?: string[];
  };
  quantum_readiness: string;
  vulnerabilities: string[];
  recommendations: string[];
  error: string | null;
  scan_duration_ms: number;
}

const DEFAULT_DOMAINS = ['google.com', 'github.com', 'cloudflare.com', 'amazon.com', 'microsoft.com'];

const READINESS_CONFIG: Record<string, { color: string; bg: string; icon: React.ComponentType<{ className?: string }>; label: string }> = {
  quantum_vulnerable: { color: 'text-red-400', bg: 'bg-red-500/10', icon: ShieldAlert, label: 'Quantum Vulnerable' },
  quantum_resistant: { color: 'text-emerald-400', bg: 'bg-emerald-500/10', icon: ShieldCheck, label: 'Quantum Resistant' },
  hybrid: { color: 'text-amber-400', bg: 'bg-amber-500/10', icon: AlertTriangle, label: 'Hybrid' },
  unknown: { color: 'text-zinc-400', bg: 'bg-zinc-500/10', icon: AlertTriangle, label: 'Unknown' },
};

export default function ScannerPage() {
  const [results, setResults] = useState<ScanResult[]>([]);
  const [loading, setLoading] = useState(false);
  const [domains, setDomains] = useState(DEFAULT_DOMAINS.join('\n'));
  const [summary, setSummary] = useState<Record<string, number> | null>(null);
  const [selectedResult, setSelectedResult] = useState<ScanResult | null>(null);

  const runScan = async () => {
    setLoading(true);
    setResults([]);
    setSelectedResult(null);
    try {
      const domainList = domains.split('\n').map(d => d.trim()).filter(d => d.length > 0);
      const data = await api.scanDomains(domainList);
      setResults(data.results);
      setSummary(data.summary);
    } catch (e) {
      console.error(e);
    }
    setLoading(false);
  };

  return (
    <div className="space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-semibold text-zinc-100">Quantum Readiness Scanner</h2>
          <p className="text-sm text-zinc-500 mt-1">Analyze TLS configurations for quantum vulnerability</p>
        </div>
      </div>

      {/* Input */}
      <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-6">
        <h3 className="text-sm font-medium text-zinc-400 uppercase tracking-wider mb-3">Domains to Scan</h3>
        <div className="flex gap-4">
          <textarea
            value={domains}
            onChange={e => setDomains(e.target.value)}
            className="flex-1 bg-zinc-800 border border-zinc-700 rounded-lg px-4 py-3 text-sm text-zinc-200 font-mono resize-none"
            rows={5}
            placeholder="Enter domains, one per line..."
          />
          <button
            onClick={runScan}
            disabled={loading}
            className="self-end flex items-center gap-2 px-6 py-2.5 bg-violet-600 hover:bg-violet-500 disabled:opacity-50 text-white text-sm font-medium rounded-lg transition-colors"
          >
            {loading ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
            {loading ? 'Scanning...' : 'Scan'}
          </button>
        </div>
      </div>

      {/* Summary */}
      {summary && (
        <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
          {[
            { label: 'Vulnerable', value: summary.vulnerable, color: 'text-red-400' },
            { label: 'Resistant', value: summary.resistant, color: 'text-emerald-400' },
            { label: 'Hybrid', value: summary.hybrid, color: 'text-amber-400' },
            { label: 'Unknown', value: summary.unknown, color: 'text-zinc-400' },
            { label: 'Errors', value: summary.errors, color: 'text-zinc-500' },
          ].map(item => (
            <div key={item.label} className="bg-zinc-900 border border-zinc-800 rounded-xl p-4 text-center">
              <p className={`text-2xl font-semibold ${item.color}`}>{item.value}</p>
              <p className="text-xs text-zinc-500 mt-1">{item.label}</p>
            </div>
          ))}
        </div>
      )}

      {/* Results */}
      {results.length > 0 && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-6">
            <h3 className="text-sm font-medium text-zinc-400 uppercase tracking-wider mb-4">Scan Results</h3>
            <div className="space-y-2">
              {results.map((result, i) => {
                const config = READINESS_CONFIG[result.quantum_readiness] || READINESS_CONFIG.unknown;
                const Icon = config.icon;
                return (
                  <button
                    key={i}
                    onClick={() => setSelectedResult(result)}
                    className={`w-full flex items-center gap-3 p-3 rounded-lg border transition-colors text-left ${selectedResult?.domain === result.domain ? 'border-violet-500/50 bg-violet-500/5' : 'border-zinc-800 hover:border-zinc-700 bg-zinc-800/30'}`}
                  >
                    <div className={`p-1.5 rounded-lg ${config.bg}`}>
                      <Icon className={`h-4 w-4 ${config.color}`} />
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-zinc-200 truncate">{result.domain}</p>
                      <p className="text-xs text-zinc-500">{result.tls_version} | {result.scan_duration_ms.toFixed(0)}ms</p>
                    </div>
                    <span className={`text-xs font-medium ${config.color}`}>{config.label}</span>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Detail panel */}
          <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-6">
            {selectedResult ? (
              <>
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-sm font-medium text-zinc-400 uppercase tracking-wider">{selectedResult.domain}</h3>
                  <button onClick={() => setSelectedResult(null)} className="text-zinc-600 hover:text-zinc-400">
                    <X className="h-4 w-4" />
                  </button>
                </div>

                <div className="space-y-4">
                  {/* Status */}
                  {(() => {
                    const config = READINESS_CONFIG[selectedResult.quantum_readiness] || READINESS_CONFIG.unknown;
                    return (
                      <div className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-lg ${config.bg}`}>
                        <config.icon className={`h-4 w-4 ${config.color}`} />
                        <span className={`text-sm font-medium ${config.color}`}>{config.label}</span>
                      </div>
                    );
                  })()}

                  {/* TLS info */}
                  <div className="space-y-2">
                    {[
                      ['TLS Version', selectedResult.tls_version],
                      ['Cipher Suite', selectedResult.cipher_suite],
                      ['Key Bits', `${selectedResult.cipher_bits}`],
                      ['Cert Algorithm', selectedResult.certificate.algorithm],
                      ['Key Type', selectedResult.certificate.key_type],
                      ['Key Size', `${selectedResult.certificate.key_bits} bits`],
                      ['Issuer', selectedResult.certificate.issuer],
                    ].map(([k, v]) => (
                      <div key={k} className="flex justify-between items-center py-1 border-b border-zinc-800/50">
                        <span className="text-xs text-zinc-500">{k}</span>
                        <span className="text-xs font-mono text-zinc-300 text-right max-w-xs truncate">{v}</span>
                      </div>
                    ))}
                  </div>

                  {/* Vulnerabilities */}
                  {selectedResult.vulnerabilities.length > 0 && (
                    <div>
                      <h4 className="text-xs font-medium text-red-400 uppercase tracking-wider mb-2">Vulnerabilities</h4>
                      {selectedResult.vulnerabilities.map((v, i) => (
                        <p key={i} className="text-xs text-zinc-400 mb-1">- {v}</p>
                      ))}
                    </div>
                  )}

                  {/* Recommendations */}
                  {selectedResult.recommendations.length > 0 && (
                    <div>
                      <h4 className="text-xs font-medium text-amber-400 uppercase tracking-wider mb-2">Recommendations</h4>
                      {selectedResult.recommendations.map((r, i) => (
                        <p key={i} className="text-xs text-zinc-400 mb-1">- {r}</p>
                      ))}
                    </div>
                  )}

                  {selectedResult.error && (
                    <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-3">
                      <p className="text-xs text-red-400">{selectedResult.error}</p>
                    </div>
                  )}
                </div>
              </>
            ) : (
              <div className="flex items-center justify-center h-full text-center py-12">
                <div>
                  <Radar className="h-10 w-10 text-zinc-700 mx-auto mb-3" />
                  <p className="text-sm text-zinc-500">Select a domain to view details</p>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {results.length === 0 && !loading && (
        <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-12 text-center">
          <Radar className="h-12 w-12 text-zinc-700 mx-auto mb-4" />
          <p className="text-zinc-500">Enter domains and click "Scan" to assess quantum readiness</p>
          <p className="text-xs text-zinc-600 mt-2">Inspects TLS certificates and cipher suites for quantum vulnerability</p>
        </div>
      )}
    </div>
  );
}
