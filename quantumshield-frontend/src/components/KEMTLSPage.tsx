import { useState } from 'react';
import { Lock, Play, ArrowRight, RefreshCw } from 'lucide-react';
import { api } from '../lib/api';

interface HandshakeMessage {
  type: string;
  size_bytes: number;
  timestamp: number;
}

interface SessionData {
  status: string;
  server_session: {
    session_id: string;
    kem_algorithm: string;
    sig_algorithm: string;
    cipher_suite: string;
    handshake_latency_ms: number;
    bytes_exchanged: number;
    state: string;
    messages: HandshakeMessage[];
  };
  channel_test?: {
    plaintext_size: number;
    ciphertext_size: number;
    decryption_verified: boolean;
    cipher_suite: string;
  };
}

const STEP_COLORS: Record<string, string> = {
  ClientHello: 'bg-blue-500',
  ServerHello: 'bg-violet-500',
  ClientKEMEncap: 'bg-emerald-500',
  ServerKEMDecap: 'bg-amber-500',
  ServerAuth: 'bg-rose-500',
  ClientVerify: 'bg-cyan-500',
};

const STEP_DESCRIPTIONS: Record<string, string> = {
  ClientHello: 'Client initiates handshake with supported algorithms',
  ServerHello: 'Server responds with Kyber768 public key + Dilithium3 signing key',
  ClientKEMEncap: 'Client encapsulates shared secret using server\'s KEM public key',
  ServerKEMDecap: 'Server decapsulates to derive the same shared secret',
  ServerAuth: 'Server signs handshake transcript with Dilithium3',
  ClientVerify: 'Client verifies signature and confirms secure channel',
};

export default function KEMTLSPage() {
  const [session, setSession] = useState<SessionData | null>(null);
  const [loading, setLoading] = useState(false);
  const [activeStep, setActiveStep] = useState(-1);
  const performHandshake = async () => {
    setLoading(true);
    setSession(null);
    setActiveStep(-1);
    try {
      const data = await api.performHandshake();
      setSession(data);
      // Animate through steps
      const msgs = data.server_session.messages;
      for (let i = 0; i < msgs.length; i++) {
        await new Promise(r => setTimeout(r, 400));
        setActiveStep(i);
      }
    } catch (e) {
      console.error(e);
    }
    setLoading(false);
  };

  return (
    <div className="space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-semibold text-zinc-100">KEMTLS Handshake Monitor</h2>
          <p className="text-sm text-zinc-500 mt-1">Post-quantum key exchange and authentication protocol</p>
        </div>
        <button
          onClick={performHandshake}
          disabled={loading}
          className="flex items-center gap-2 px-4 py-2.5 bg-violet-600 hover:bg-violet-500 disabled:opacity-50 text-white text-sm font-medium rounded-lg transition-colors"
        >
          {loading ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
          {loading ? 'Running...' : 'Perform Handshake'}
        </button>
      </div>

      {/* Protocol visualization */}
      <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-6">
        <h3 className="text-sm font-medium text-zinc-400 uppercase tracking-wider mb-6">Protocol Flow</h3>

        {/* Client / Server columns */}
        <div className="flex items-start gap-6">
          <div className="w-20 text-center">
            <div className="bg-blue-500/10 text-blue-400 rounded-lg px-3 py-2 text-xs font-medium">Client</div>
          </div>
          <div className="flex-1 space-y-3">
            {['ClientHello', 'ServerHello', 'ClientKEMEncap', 'ServerKEMDecap', 'ServerAuth', 'ClientVerify'].map((step, i) => {
              const msg = session?.server_session.messages.find(m => m.type === step);
              const active = i <= activeStep;
              const isRight = step.startsWith('Server');

              return (
                <div key={step} className={`flex items-center gap-3 transition-all duration-300 ${active ? 'opacity-100' : 'opacity-30'}`}>
                  <div className={`w-3 h-3 rounded-full ${active ? STEP_COLORS[step] : 'bg-zinc-700'} transition-colors`} />
                  <div className={`flex-1 flex ${isRight ? 'justify-end' : 'justify-start'}`}>
                    <div className={`inline-flex items-center gap-3 px-4 py-2.5 rounded-lg border ${active ? 'border-zinc-700 bg-zinc-800/50' : 'border-zinc-800 bg-zinc-900'}`}>
                      {!isRight && <ArrowRight className="h-3 w-3 text-zinc-600" />}
                      <div>
                        <p className="text-sm font-medium text-zinc-200">{step}</p>
                        <p className="text-xs text-zinc-500">{STEP_DESCRIPTIONS[step]}</p>
                        {msg && active && (
                          <p className="text-xs text-zinc-600 mt-1">{msg.size_bytes} bytes</p>
                        )}
                      </div>
                      {isRight && <ArrowRight className="h-3 w-3 text-zinc-600 rotate-180" />}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
          <div className="w-20 text-center">
            <div className="bg-violet-500/10 text-violet-400 rounded-lg px-3 py-2 text-xs font-medium">Server</div>
          </div>
        </div>
      </div>

      {/* Session details */}
      {session && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-6">
            <h3 className="text-sm font-medium text-zinc-400 uppercase tracking-wider mb-4">Session Details</h3>
            <div className="space-y-3">
              {[
                ['Session ID', session.server_session.session_id.substring(0, 16) + '...'],
                ['KEM Algorithm', session.server_session.kem_algorithm],
                ['Signature', session.server_session.sig_algorithm],
                ['Cipher Suite', session.server_session.cipher_suite],
                ['State', session.server_session.state],
              ].map(([k, v]) => (
                <div key={k} className="flex justify-between items-center py-1.5 border-b border-zinc-800/50 last:border-0">
                  <span className="text-sm text-zinc-500">{k}</span>
                  <span className="text-sm font-mono text-zinc-200">{v}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-6">
            <h3 className="text-sm font-medium text-zinc-400 uppercase tracking-wider mb-4">Performance Metrics</h3>
            <div className="space-y-3">
              {[
                ['Handshake Latency', `${session.server_session.handshake_latency_ms.toFixed(2)} ms`],
                ['Bytes Exchanged', `${session.server_session.bytes_exchanged} bytes`],
                ['Messages', `${session.server_session.messages.length} steps`],
                ['Channel Cipher', session.channel_test?.cipher_suite ?? session.server_session.cipher_suite],
                ['Channel Verified', session.channel_test?.decryption_verified ? 'Yes' : 'Pending'],
              ].map(([k, v]) => (
                <div key={k} className="flex justify-between items-center py-1.5 border-b border-zinc-800/50 last:border-0">
                  <span className="text-sm text-zinc-500">{k}</span>
                  <span className={`text-sm font-mono ${v === 'Yes' ? 'text-emerald-400' : 'text-zinc-200'}`}>{v}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Message log */}
          <div className="lg:col-span-2 bg-zinc-900 border border-zinc-800 rounded-xl p-6">
            <h3 className="text-sm font-medium text-zinc-400 uppercase tracking-wider mb-4">Handshake Message Log</h3>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-zinc-500 text-xs uppercase tracking-wider border-b border-zinc-800">
                    <th className="text-left py-2 pr-4">#</th>
                    <th className="text-left py-2 pr-4">Message</th>
                    <th className="text-right py-2 pr-4">Size</th>
                    <th className="text-right py-2">Timestamp</th>
                  </tr>
                </thead>
                <tbody>
                  {session.server_session.messages.map((msg, i) => (
                    <tr key={i} className="border-b border-zinc-800/50 last:border-0">
                      <td className="py-2 pr-4 text-zinc-600">{i + 1}</td>
                      <td className="py-2 pr-4">
                        <div className="flex items-center gap-2">
                          <div className={`w-2 h-2 rounded-full ${STEP_COLORS[msg.type] || 'bg-zinc-500'}`} />
                          <span className="font-mono text-zinc-200">{msg.type}</span>
                        </div>
                      </td>
                      <td className="py-2 pr-4 text-right text-zinc-400">{msg.size_bytes} B</td>
                      <td className="py-2 text-right text-zinc-600 font-mono text-xs">{new Date(msg.timestamp * 1000).toISOString().split('T')[1]}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {!session && !loading && (
        <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-12 text-center">
          <Lock className="h-12 w-12 text-zinc-700 mx-auto mb-4" />
          <p className="text-zinc-500">Click "Perform Handshake" to initiate a KEMTLS session</p>
          <p className="text-xs text-zinc-600 mt-2">Uses Kyber768 key encapsulation and Dilithium3 server authentication</p>
        </div>
      )}
    </div>
  );
}
