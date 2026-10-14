export type Detection = {
  id: string;
  name: string;
  platform: string;
  type: 'profile' | 'app' | 'url';
  score: number;
  tier: number;
  reasons: string[];
  time: string;
  components?: Record<string, number>;
  shap?: Record<string, number>;
  provenance?: string;
  case_id?: number;
  enrichment?: Record<string, unknown>;
};

export type BrandTwin = {
  id?: number;
  name: string;
  official_domains: string[];
  handles: string[];
  app_ids: string[];
  developers: string[];
  allowlist: string[];
  exec_names?: string[];
  official_app_description?: string;
  logo_hash?: string;
};

export type CaseItem = {
  id: number;
  status: 'open' | 'reviewing' | 'escalated' | 'closed';
  priority: 'low' | 'medium' | 'high';
  created_at: string | null;
  closed_at?: string | null;
  detection: {
    id: number | null;
    final_score: number;
    tier: number;
    tier_label: string;
    reason_codes: string[];
    component_scores?: Record<string, number>;
  } | null;
  asset: {
    id: number | null;
    value: string;
    type: string;
    source: string;
  } | null;
};

export type CampaignNode = {
  id: string;
  label: string;
  type: 'brand' | 'profile' | 'app';
  role: 'victim' | 'threat';
  risk_tier?: number;
  threat_score?: number;
  reason_codes?: string[];
};

export type CampaignEdge = {
  source: string;
  target: string;
  relationship: string;
  weight?: number;
};

export type CampaignItem = {
  id: string;
  title: string;
  description: string;
  category: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  status: string;
  asset_count: number;
  max_threat_score: number;
  first_seen: string;
  last_seen: string;
  nodes: CampaignNode[];
  edges: CampaignEdge[];
};

export type TyposquatEntry = {
  domain: string;
  mutation_type: string;
  threat_score: number;
  tier: number;
  tier_label: string;
  resolved: boolean;
  ip_address: string | null;
  has_mx: boolean;
  domain_age_days?: number | null;
  registration_date?: string | null;
  has_tls_cert?: boolean;
  cert_issuer?: string | null;
  abuse_score?: number | null;
  isp?: string | null;
  reason_codes?: string[];
};

export type FeedbackSummary = {
  total_reviews: number;
  confirmed_threats: number;
  false_positives: number;
  uncertain: number;
  false_positive_rate_pct: number;
  model_precision_pct: number;
};

export const demoDetections: Detection[] = [];
export const trend: number[] = [];

export const apiBase = (
  import.meta.env.VITE_API_BASE !== undefined
    ? import.meta.env.VITE_API_BASE
    : (typeof window !== 'undefined' && window.location.hostname !== 'localhost' && window.location.hostname !== '127.0.0.1' ? '' : 'http://127.0.0.1:8000')
).replace(/\/$/, '');
export const wsUrl = import.meta.env.VITE_WS_URL ?? (
  typeof window !== 'undefined' && window.location.protocol === 'https:'
    ? `wss://${window.location.host}/ws/feed`
    : 'ws://127.0.0.1:8000/ws/feed'
);

export function record(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' ? (value as Record<string, unknown>) : {};
}

export async function request<T = unknown>(path: string, init?: RequestInit): Promise<T> {
  const url = `${apiBase}${path}`;
  const response = await fetch(url, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...init?.headers },
    signal: AbortSignal.timeout(10000),
  });
  if (!response.ok) {
    throw new Error(`API error ${response.status}: ${response.statusText}`);
  }
  return response.json() as Promise<T>;
}

export function formatSource(source: string): string {
  const s = source.toLowerCase();
  if (s.includes('google_play') || s.includes('play')) return 'Google Play';
  if (s.includes('app_store') || s.includes('apple')) return 'App Store';
  if (s.includes('insta')) return 'Instagram';
  if (s.includes('twitter') || s.includes('x')) return 'X / Twitter';
  if (s.includes('facebook')) return 'Facebook';
  if (s.includes('telegram')) return 'Telegram';
  if (s.includes('tiktok')) return 'TikTok';
  if (s.includes('threat_intel') || s.includes('intel') || s.includes('url')) return 'Threat Intel Feed';
  return source.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase()) || 'Public Web';
}

export function normalizeDetection(value: unknown): Detection {
  const d = record(value);
  const asset = record(d.asset);
  const codes = d.reason_codes ?? d.reason_codes_json;
  const rawSource = String(d.asset_source ?? d.source ?? asset.source ?? 'Submitted data');
  const rawType = String(d.asset_type ?? d.type ?? asset.type ?? '');
  const type: Detection['type'] = rawType === 'app' ? 'app' : (rawType === 'url' ? 'url' : 'profile');

  return {
    id: String(d.id),
    name: String(d.asset_value ?? d.asset_name ?? d.name ?? asset.value ?? 'Unknown asset'),
    platform: formatSource(rawSource),
    type,
    score: Math.round(Number(d.final_score ?? d.score ?? 0) * 10) / 10,
    tier: Number(d.tier ?? 0),
    reasons: Array.isArray(codes) ? codes.map(String) : [],
    time: d.created_at ? new Date(String(d.created_at)).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : 'Just now',
    components: record(d.component_scores ?? d.component_scores_json ?? d.components) as Record<string, number>,
    shap: record(d.shap ?? d.shap_json) as Record<string, number>,
    provenance: String(d.provenance ?? asset.provenance ?? 'live'),
    case_id: d.case_id ? Number(d.case_id) : undefined,
    enrichment: record(d.enrichment),
  };
}

// ----------------- API Endpoints -----------------

export async function fetchDetections(): Promise<Detection[]> {
  try {
    const raw = await request<{ detections?: unknown[]; total?: number }>('/api/detections');
    const items = raw.detections ?? (Array.isArray(raw) ? raw : []);
    return items.map(normalizeDetection);
  } catch (error) {
    console.error('Backend detections fetch error:', error);
    return [];
  }
}

export async function fetchActiveBrand(): Promise<BrandTwin | null> {
  try {
    return await request<BrandTwin>('/api/brands/active');
  } catch (error) {
    console.warn('Backend active brand fetch failed:', error);
    return null;
  }
}

export async function saveBrand(brand: BrandTwin): Promise<BrandTwin> {
  return await request<BrandTwin>('/api/brands', {
    method: 'POST',
    body: JSON.stringify(brand),
  });
}

export async function analyzeProfile(data: {
  handle: string;
  name?: string;
  bio?: string;
  followers_count?: number;
  following_count?: number;
  posts_count?: number;
}): Promise<Record<string, unknown>> {
  return await request('/api/analyze/profile', {
    method: 'POST',
    body: JSON.stringify({ brand: 'Apex Global Bank', data }),
  });
}

export async function analyzeApp(data: {
  app_name: string;
  package_name: string;
  developer?: string;
  description?: string;
  permissions?: string[];
}): Promise<Record<string, unknown>> {
  return await request('/api/analyze/app', {
    method: 'POST',
    body: JSON.stringify({ brand: 'Apex Global Bank', data }),
  });
}

export async function analyzeUrl(url: string): Promise<Record<string, unknown>> {
  return await request('/api/analyze/url', {
    method: 'POST',
    body: JSON.stringify({ brand: 'Apex Global Bank', url }),
  });
}

export async function fetchCases(status?: string, priority?: string): Promise<CaseItem[]> {
  const params = new URLSearchParams();
  if (status && status !== 'All') params.set('status', status.toLowerCase());
  if (priority && priority !== 'All') params.set('priority', priority.toLowerCase());
  const q = params.toString() ? `?${params.toString()}` : '';
  const raw = await request<{ cases?: CaseItem[] }>(`/api/cases${q}`);
  return raw.cases ?? [];
}

export async function reviewCase(
  caseId: number,
  status: string,
  priority: string,
  reviewer: string = 'SOC Analyst'
): Promise<unknown> {
  return await request(`/api/cases/${caseId}/review`, {
    method: 'POST',
    body: JSON.stringify({ status: status.toLowerCase(), priority: priority.toLowerCase(), reviewer }),
  });
}

export async function submitVerdict(
  detectionId: number | string,
  verdict: 'confirmed_threat' | 'false_positive' | 'uncertain',
  notes: string = ''
): Promise<unknown> {
  return await request('/api/feedback', {
    method: 'POST',
    body: JSON.stringify({
      detection_id: Number(detectionId),
      verdict,
      notes,
    }),
  });
}

export async function fetchCampaigns(): Promise<CampaignItem[]> {
  try {
    const raw = await request<{ campaigns?: CampaignItem[] }>('/api/campaigns');
    return raw.campaigns ?? [];
  } catch (error) {
    console.warn('Backend campaigns fetch failed:', error);
    return [];
  }
}

export async function fetchTyposquats(domain: string): Promise<TyposquatEntry[]> {
  const raw = await request<{ lookalikes?: TyposquatEntry[] }>(`/api/typosquat/${encodeURIComponent(domain)}`);
  return raw.lookalikes ?? [];
}

export async function fetchFeedbackSummary(): Promise<FeedbackSummary | null> {
  try {
    return await request<FeedbackSummary>('/api/feedback/summary');
  } catch (error) {
    console.warn('Backend feedback summary fetch failed:', error);
    return null;
  }
}

export async function fetchDetectionDetail(id: number | string): Promise<Detection | null> {
  try {
    const raw = await request<Record<string, unknown>>(`/api/detections/${id}`);
    return normalizeDetection(raw);
  } catch (error) {
    console.warn(`Backend detection #${id} fetch failed:`, error);
    return null;
  }
}

export async function fetchBrandGithub(brandId: number = 1): Promise<{
  brand: string;
  configured: boolean;
  checked: boolean;
  total_matches: number;
  suspicious_repos: Array<{
    name: string;
    full_name: string;
    url: string;
    description: string;
    stars: number;
    updated_at: string;
    is_suspicious: boolean;
    flags: string[];
  }>;
  error?: string | null;
} | null> {
  try {
    return await request(`/api/brands/${brandId}/github`);
  } catch (error) {
    console.warn('Backend brand GitHub fetch failed:', error);
    return null;
  }
}

