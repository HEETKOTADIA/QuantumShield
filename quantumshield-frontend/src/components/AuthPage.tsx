import { useState } from 'react';
import { Play, CheckCircle, XCircle, User, Key, FileCheck, Shield, RefreshCw } from 'lucide-react';
import { api } from '../lib/api';

export default function AuthPage() {
  interface OIDCStep {
    step: number;
    name: string;
    [key: string]: unknown;
  }
  interface FlowResult {
    flow: string;
    steps: OIDCStep[];
    user: { sub: string; name: string; email: string };
    security: Record<string, unknown>;
  }
  const [flowResult, setFlowResult] = useState<FlowResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [activeStep, setActiveStep] = useState(-1);

  const runDemoFlow = async () => {
    setLoading(true);
    setFlowResult(null);
    setActiveStep(-1);
    try {
      const data = await api.demoOIDCFlow();
      setFlowResult(data);
      for (let i = 0; i < data.steps.length; i++) {
        await new Promise(r => setTimeout(r, 500));
        setActiveStep(i);
      }
    } catch (e) {
      console.error(e);
    }
    setLoading(false);
  };

  const stepIcons = [Key, FileCheck, Shield, CheckCircle];
  const stepColors = ['text-blue-400', 'text-violet-400', 'text-emerald-400', 'text-amber-400'];

  return (
    <div className="space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-semibold text-zinc-100">Authentication Flow</h2>
          <p className="text-sm text-zinc-500 mt-1">OIDC Authorization Code Flow with PKCE, signed with Dilithium3</p>
        </div>
        <button
          onClick={runDemoFlow}
          disabled={loading}
          className="flex items-center gap-2 px-4 py-2.5 bg-violet-600 hover:bg-violet-500 disabled:opacity-50 text-white text-sm font-medium rounded-lg transition-colors"
        >
          {loading ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
          {loading ? 'Running...' : 'Run Auth Flow'}
        </button>
      </div>

      {/* Flow diagram */}
      <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-6">
        <h3 className="text-sm font-medium text-zinc-400 uppercase tracking-wider mb-6">OIDC Flow Visualization</h3>
        <div className="flex items-center justify-between gap-2 mb-8 overflow-x-auto pb-2">
          {['User', 'Client App', 'Authorization Server', 'Resource Server'].map((label, i) => (
            <div key={label} className="flex items-center gap-2 flex-shrink-0">
              <div className="bg-zinc-800 border border-zinc-700 rounded-lg px-4 py-2 text-xs font-medium text-zinc-300">{label}</div>
              {i < 3 && <div className="w-8 h-px bg-zinc-700" />}
            </div>
          ))}
        </div>

        {/* Steps */}
        <div className="space-y-4">
          {flowResult?.steps?.map((step: OIDCStep, i: number) => {
            const Icon = stepIcons[i] || CheckCircle;
            const color = stepColors[i] || 'text-zinc-400';
            const active = i <= activeStep;

            return (
              <div key={i} className={`transition-all duration-300 ${active ? 'opacity-100' : 'opacity-30'}`}>
                <div className="flex items-start gap-4 p-4 rounded-lg border border-zinc-800 bg-zinc-800/30">
                  <div className={`mt-0.5 ${color}`}>
                    <Icon className="h-5 w-5" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-3 mb-2">
                      <span className="text-xs font-mono text-zinc-600">Step {step.step}</span>
                      <span className="text-sm font-medium text-zinc-200">{step.name}</span>
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                      {Object.entries(step).filter(([k]) => k !== 'step' && k !== 'name').map(([k, v]) => (
                        <div key={k} className="text-xs">
                          <span className="text-zinc-500">{k.replace(/_/g, ' ')}: </span>
                          <span className="text-zinc-300 font-mono break-all">
                            {typeof v === 'object' ? JSON.stringify(v).substring(0, 80) + '...' : String(v)}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Result details */}
      {flowResult && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-6">
            <h3 className="text-sm font-medium text-zinc-400 uppercase tracking-wider mb-4">Authenticated User</h3>
            <div className="flex items-center gap-3 mb-4">
              <div className="bg-violet-500/10 p-2.5 rounded-full">
                <User className="h-5 w-5 text-violet-400" />
              </div>
              <div>
                <p className="text-sm font-medium text-zinc-200">{flowResult.user.name}</p>
                <p className="text-xs text-zinc-500">{flowResult.user.email}</p>
              </div>
            </div>
            <div className="text-xs text-zinc-600 font-mono">sub: {flowResult.user.sub}</div>
          </div>

          <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-6">
            <h3 className="text-sm font-medium text-zinc-400 uppercase tracking-wider mb-4">Security Details</h3>
            <div className="space-y-2">
              {Object.entries(flowResult.security).map(([k, v]) => (
                <div key={k} className="flex justify-between items-center py-1">
                  <span className="text-xs text-zinc-500">{k.replace(/_/g, ' ')}</span>
                  <span className={`text-xs font-mono ${v === true ? 'text-emerald-400' : 'text-zinc-300'}`}>
                    {typeof v === 'boolean' ? (v ? 'Yes' : 'No') : String(v)}
                  </span>
                </div>
              ))}
            </div>
          </div>

          <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-6">
            <h3 className="text-sm font-medium text-zinc-400 uppercase tracking-wider mb-4">Token Verification</h3>
            <div className="space-y-3">
              {flowResult.steps[3] && (
                <>
                  <div className="flex items-center gap-2">
                    {flowResult.steps[3].id_token_valid
                      ? <CheckCircle className="h-4 w-4 text-emerald-400" />
                      : <XCircle className="h-4 w-4 text-red-400" />}
                    <span className="text-sm text-zinc-300">ID Token</span>
                  </div>
                  <div className="flex items-center gap-2">
                    {flowResult.steps[3].access_token_valid
                      ? <CheckCircle className="h-4 w-4 text-emerald-400" />
                      : <XCircle className="h-4 w-4 text-red-400" />}
                    <span className="text-sm text-zinc-300">Access Token</span>
                  </div>
                  <p className="text-xs text-zinc-600 mt-2">Signed with Dilithium3 (ML-DSA-65)</p>
                </>
              )}
            </div>
          </div>
        </div>
      )}

      {!flowResult && !loading && (
        <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-12 text-center">
          <Shield className="h-12 w-12 text-zinc-700 mx-auto mb-4" />
          <p className="text-zinc-500">Click "Run Auth Flow" to execute a complete OIDC authentication</p>
          <p className="text-xs text-zinc-600 mt-2">Demonstrates Authorization Code + PKCE with post-quantum token signing</p>
        </div>
      )}
    </div>
  );
}
