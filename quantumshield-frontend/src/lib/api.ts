const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

// Response types
interface StatusResponse {
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

interface HandshakeMessage {
  type: string;
  direction: string;
  size_bytes: number;
  timestamp: number;
  data: Record<string, string>;
}

interface HandshakeSession {
  session_id: string;
  kem_algorithm: string;
  sig_algorithm: string;
  cipher_suite: string;
  handshake_latency_ms: number;
  bytes_exchanged: number;
  state: string;
  messages: HandshakeMessage[];
}

interface HandshakeResponse {
  status: string;
  server_session: HandshakeSession;
  client_session: HandshakeSession;
  channel_test?: {
    plaintext_size: number;
    ciphertext_size: number;
    decryption_verified: boolean;
    cipher_suite: string;
  };
}

interface SessionsResponse {
  sessions: Array<{
    session_id: string;
    established: boolean;
    kem_algorithm: string;
  }>;
}

interface EncryptTestResponse {
  plaintext: string;
  ciphertext_hex: string;
  decrypted: string;
  success: boolean;
}

interface OIDCFlowStep {
  step: number;
  name: string;
  [key: string]: unknown;
}

interface OIDCFlowResponse {
  flow: string;
  steps: OIDCFlowStep[];
  user: { sub: string; name: string; email: string };
  security: Record<string, unknown>;
}

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

interface BenchmarkSuiteResponse {
  run_timestamp: number;
  total_duration_s: number;
  results: BenchmarkResult[];
}

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

interface ScanResponse {
  scan_count: number;
  results: ScanResult[];
  summary: Record<string, number>;
}

interface AlgorithmsResponse {
  kem: Record<string, string | number>;
  signature: Record<string, string | number>;
}

interface VerifyTokenResponse {
  valid: boolean;
  claims?: Record<string, string>;
  error?: string;
}

interface OpenIDConfigResponse {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  jwks_uri: string;
  response_types_supported: string[];
  grant_types_supported: string[];
}

interface JWKSResponse {
  keys: Array<Record<string, string>>;
}

interface CryptoDemoResponse {
  algorithm: string;
  operation: string;
  details: Record<string, string | number>;
}

async function fetchApi<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_URL}${path}`, {
    headers: { 'Content-Type': 'application/json', ...options?.headers },
    ...options,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || res.statusText);
  }
  return res.json();
}

export const api = {
  getStatus: () => fetchApi<StatusResponse>('/api/status'),
  performHandshake: () => fetchApi<HandshakeResponse>('/api/kemtls/handshake', { method: 'POST' }),
  getSessions: () => fetchApi<SessionsResponse>('/api/kemtls/sessions'),
  encryptTest: () => fetchApi<EncryptTestResponse>('/api/kemtls/encrypt-test', { method: 'POST' }),
  getOpenIDConfig: () => fetchApi<OpenIDConfigResponse>('/.well-known/openid-configuration'),
  getJWKS: () => fetchApi<JWKSResponse>('/jwks.json'),
  demoOIDCFlow: () => fetchApi<OIDCFlowResponse>('/api/oidc/demo-flow', { method: 'POST' }),
  getClients: () => fetchApi<Record<string, unknown>>('/api/oidc/clients'),
  getUsers: () => fetchApi<Record<string, unknown>>('/api/oidc/users'),
  verifyToken: (token: string) => fetchApi<VerifyTokenResponse>('/api/oidc/verify-token', { method: 'POST', body: JSON.stringify({ token }) }),
  runBenchmarks: (iterations: number = 100) => fetchApi<BenchmarkSuiteResponse>(`/api/benchmarks/run?iterations=${iterations}`, { method: 'POST' }),
  runQuickBenchmarks: () => fetchApi<BenchmarkSuiteResponse>('/api/benchmarks/quick', { method: 'POST' }),
  getBenchmarkResults: () => fetchApi<BenchmarkSuiteResponse>('/api/benchmarks/results'),
  scanDomains: (domains: string[]) => fetchApi<ScanResponse>('/api/scanner/scan', { method: 'POST', body: JSON.stringify({ domains }) }),
  getAlgorithms: () => fetchApi<AlgorithmsResponse>('/api/crypto/algorithms'),
  demoKEM: () => fetchApi<CryptoDemoResponse>('/api/crypto/demo-kem', { method: 'POST' }),
  demoSignature: () => fetchApi<CryptoDemoResponse>('/api/crypto/demo-signature', { method: 'POST' }),
};
