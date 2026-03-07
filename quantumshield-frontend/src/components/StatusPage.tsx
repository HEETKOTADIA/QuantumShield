import { useEffect, useState } from 'react';
import { Shield, Lock, Key, FileCheck, Cpu, RefreshCw } from 'lucide-react';
import { api } from '../lib/api';

interface StatusData {
  system: string;
  version: string;
  status: string;
  transport_protocol: string;
  quantum_resistance: string;
  oidc_compliance: string;
  crypto_config: {
    kem_algorithm: { name: string; nist_name: string; claimed_nist_level: number; public_key_length: number; ciphertext_length: number; shared_secret_length: number };
    signature_algorithm: { name: string; nist_name: string; claimed_nist_level: number; public_key_length: number; signature_length: number };
    symmetric_cipher: string;
    kdf: string;
  };
  endpoints: Record<string, string>;
  uptime_since: number;
}

function MetricCard({ icon: Icon, label, value, sub, color }: { icon: React.ComponentType<{ className?: string }>; label: string; value: string; sub?: string; color: string }) {
  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-5">
      <div className="flex items-center gap-3 mb-3">
        <div className={`p-2 rounded-lg ${color}`}>
          <Icon className="h-4 w-4" />
        </div>
        <span className="text-xs font-medium text-zinc-500 uppercase tracking-wider">{label}</span>
      </div>
      <p className="text-lg font-semibold text-zinc-100">{value}</p>
      {sub && <p className="text-xs text-zinc-500 mt-1">{sub}</p>}
    </div>
  );
}

export default function StatusPage() {
  const [data, setData] = useState<StatusData | null>(null);
  const [loading, setLoading] = useState(true);
  const fetchData = async () => {
    setLoading(true);
    try {
      const [status] = await Promise.all([api.getStatus(), api.getAlgorithms()]);
      setData(status);
    } catch (e) {
      console.error(e);
    }
    setLoading(false);
  };

  useEffect(() => { fetchData(); }, []);

  if (loading || !data) {
    return <div className="flex items-center justify-center h-64"><RefreshCw className="h-6 w-6 text-zinc-500 animate-spin" /></div>;
  }

  const kem = data.crypto_config.kem_algorithm;
  const sig = data.crypto_config.signature_algorithm;

  return (
    <div className="space-y-8">
      <div>
        <h2 className="text-2xl font-semibold text-zinc-100">System Status</h2>
        <p className="text-sm text-zinc-500 mt-1">Post-quantum cryptographic configuration overview</p>
      </div>

      {/* Status indicators */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-4">
        <MetricCard icon={Lock} label="Transport" value={data.transport_protocol} sub="KEM-based TLS" color="bg-violet-500/10 text-violet-400" />
        <MetricCard icon={Key} label="KEM Algorithm" value={kem.name} sub={kem.nist_name} color="bg-emerald-500/10 text-emerald-400" />
        <MetricCard icon={Shield} label="Signatures" value={sig.name} sub={sig.nist_name} color="bg-blue-500/10 text-blue-400" />
        <MetricCard icon={FileCheck} label="OIDC" value={data.oidc_compliance} sub="Authorization Code + PKCE" color="bg-amber-500/10 text-amber-400" />
        <MetricCard icon={Cpu} label="Quantum Resistance" value={data.quantum_resistance === 'enabled' ? 'Enabled' : 'Disabled'} sub="NIST Level 3" color="bg-rose-500/10 text-rose-400" />
      </div>

      {/* Crypto details */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-6">
          <h3 className="text-sm font-medium text-zinc-400 uppercase tracking-wider mb-4">Key Encapsulation Mechanism</h3>
          <div className="space-y-3">
            {[
              ['Algorithm', kem.name],
              ['NIST Name', kem.nist_name],
              ['Security Level', `NIST Level ${kem.claimed_nist_level}`],
              ['Public Key', `${kem.public_key_length} bytes`],
              ['Ciphertext', `${kem.ciphertext_length} bytes`],
              ['Shared Secret', `${kem.shared_secret_length} bytes`],
            ].map(([k, v]) => (
              <div key={k} className="flex justify-between items-center py-1.5 border-b border-zinc-800/50 last:border-0">
                <span className="text-sm text-zinc-500">{k}</span>
                <span className="text-sm font-mono text-zinc-200">{v}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-6">
          <h3 className="text-sm font-medium text-zinc-400 uppercase tracking-wider mb-4">Digital Signature Scheme</h3>
          <div className="space-y-3">
            {[
              ['Algorithm', sig.name],
              ['NIST Name', sig.nist_name],
              ['Security Level', `NIST Level ${sig.claimed_nist_level}`],
              ['Public Key', `${sig.public_key_length} bytes`],
              ['Signature Size', `${sig.signature_length} bytes`],
              ['Usage', 'JWT Signing, Server Auth'],
            ].map(([k, v]) => (
              <div key={k} className="flex justify-between items-center py-1.5 border-b border-zinc-800/50 last:border-0">
                <span className="text-sm text-zinc-500">{k}</span>
                <span className="text-sm font-mono text-zinc-200">{v}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* System config table */}
      <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-6">
        <h3 className="text-sm font-medium text-zinc-400 uppercase tracking-wider mb-4">Security Configuration</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-x-12 gap-y-3">
          {[
            ['Transport Protocol', 'KEMTLS'],
            ['KEM Algorithm', 'Kyber768 (ML-KEM-768)'],
            ['Signature Algorithm', 'Dilithium3 (ML-DSA-65)'],
            ['Symmetric Cipher', data.crypto_config.symmetric_cipher],
            ['Key Derivation', data.crypto_config.kdf],
            ['OIDC Compliance', 'Active'],
            ['PKCE Support', 'S256'],
            ['Quantum Resistance', 'Enabled'],
          ].map(([k, v]) => (
            <div key={k} className="flex justify-between items-center py-2 border-b border-zinc-800/50">
              <span className="text-sm text-zinc-500">{k}</span>
              <span className="text-sm font-medium text-emerald-400">{v}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
