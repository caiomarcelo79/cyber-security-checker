export interface ComponentHealth {
  name: string;
  status: "UP" | "DEGRADED" | "DOWN";
  latency_ms?: number | null;
  details: Record<string, unknown>;
}

export interface PlatformMetricsSummary {
  total_organizations: number;
  total_assets: number;
  verified_assets: number;
  total_scans_executed: number;
  scans_in_progress: number;
  open_vulnerabilities: number;
  critical_vulnerabilities: number;
  high_vulnerabilities: number;
  medium_vulnerabilities: number;
  low_vulnerabilities: number;
  info_vulnerabilities: number;
  treatment_status_counts: Record<string, number>;
  top_risky_assets: TopRiskyAssetItem[];
  owasp_category_distribution: CategoryDistributionItem[];
  cwe_distribution: CategoryDistributionItem[];
  recent_scans: RecentScanSummaryItem[];
  average_scan_duration_seconds: number;
  scan_status_counts: Record<string, number>;
  resolved_vulnerabilities: number;
}

export interface TopRiskyAssetItem {
  id: string;
  name: string;
  target_url: string;
  environment: string;
  asset_type: string;
  authorization_status: string;
  risk_score: number;
  open_findings_count: number;
  critical_count: number;
  high_count: number;
  last_scan_at?: string | null;
}

export interface CategoryDistributionItem {
  category: string;
  count: number;
}

export interface RecentScanSummaryItem {
  id: string;
  asset_id: string;
  asset_name: string;
  profile_type: string;
  status: string;
  progress_percent: number;
  total_checks_run: number;
  findings_count: number;
  created_at: string;
}

export interface SystemStatusResponse {
  status: string;
  app_name: string;
  version: string;
  environment: string;
  current_phase: string;
  timestamp: string;
  components: Record<string, ComponentHealth>;
  registered_modules_count: number;
  available_profiles_count: number;
  metrics: PlatformMetricsSummary;
}

export interface SecurityModuleDescriptor {
  module_id: string;
  code: string;
  name: string;
  description: string;
  category: string;
  impact_level: "PASSIVE" | "LOW_IMPACT_ACTIVE" | "CONTROLLED_ASSESSMENT";
  supported_asset_types: string[];
  owasp_references: string[];
  wstg_references: string[];
  asvs_references: string[];
  cwe_references: string[];
  enabled_by_default: boolean;
  requires_authentication: boolean;
  allow_in_production: boolean;
  checks_catalog: string[];
}

export interface ScanProfileDescriptor {
  profile_type: string;
  name: string;
  description: string;
  what_is_analyzed: string[];
  what_is_not_analyzed: string[];
  potential_impact: string;
  impact_level: string;
  default_max_rps: number;
  default_max_concurrency: number;
  default_timeout_seconds: number;
  prerequisites: string[];
  dependencies: string[];
  known_risks: string[];
  enabled_modules: string[];
  allowed_in_production: boolean;
}

export interface StackCodeExample {
  technology: string;
  language: string;
  description: string;
  code: string;
}

export interface RemediationGuidance {
  remediation_id: string;
  version: string;
  what_was_identified: string;
  why_it_is_dangerous: string;
  how_it_was_detected: string;
  how_to_fix: string;
  secure_examples: StackCodeExample[];
  how_to_validate: string;
  references: string[];
}

export interface ScopeValidationRequest {
  target_url: string;
  authorized_hosts: string[];
  allow_subdomains: boolean;
  excluded_paths: string[];
}

export interface ScopeValidationResponse {
  allowed: boolean;
  normalized_url?: string | null;
  hostname?: string | null;
  reason: string;
}

// --- Fase 2: Autenticação, Organizações, RBAC, Ativos e Autorizações ---

export type UserRole = "ADMIN" | "SECURITY_ANALYST" | "DEVELOPER" | "VIEWER";

export interface UserPublic {
  id: string;
  email: string;
  full_name: string;
  is_active: boolean;
  created_at: string;
}

export interface OrganizationPublic {
  id: string;
  name: string;
  slug: string;
  is_active: boolean;
  created_at: string;
}

export interface MembershipSummary {
  organization_id: string;
  organization_name: string;
  organization_slug: string;
  role: UserRole;
}

export interface AuthSessionResponse {
  access_token: string;
  token_type: string;
  expires_in_minutes: number;
  user: UserPublic;
  active_organization: OrganizationPublic;
  active_role: UserRole;
  memberships: MembershipSummary[];
}

export interface UserRegisterRequest {
  email: string;
  password: string;
  full_name: string;
  organization_name: string;
}

export interface UserLoginRequest {
  email: string;
  password: string;
}

export interface AssetResponse {
  id: string;
  organization_id: string;
  name: string;
  target_url: string;
  hostname: string;
  asset_type: "WEB_APP" | "REST_API" | "GRAPHQL_API" | "DOMAIN";
  environment: "PRODUCTION" | "STAGING" | "DEVELOPMENT" | "LAB";
  owner_name: string;
  owner_email: string;
  tags: string[];
  excluded_paths: string[];
  risk_score: number;
  authorization_status: "PENDING" | "VERIFIED" | "EXPIRED" | "REVOKED";
  created_at: string;
  updated_at: string;
}

export interface AssetCreateRequest {
  name: string;
  target_url: string;
  asset_type: "WEB_APP" | "REST_API" | "GRAPHQL_API" | "DOMAIN";
  environment: "PRODUCTION" | "STAGING" | "DEVELOPMENT" | "LAB";
  owner_name: string;
  owner_email: string;
  tags: string[];
  excluded_paths: string[];
}

export interface TargetAuthorizationResponse {
  id: string;
  asset_id: string;
  organization_id: string;
  method: "DNS_TXT" | "HTTP_WELL_KNOWN" | "LAB_INTERNAL";
  verification_token: string;
  status: "PENDING" | "VERIFIED" | "EXPIRED" | "REVOKED";
  verified_by_user_id?: string | null;
  scope_notes?: string | null;
  instructions: Record<string, string>;
  verified_at?: string | null;
  expires_at?: string | null;
  created_at: string;
}

export interface AuthorizationInitiateRequest {
  method: "DNS_TXT" | "HTTP_WELL_KNOWN" | "LAB_INTERNAL";
  scope_notes?: string;
  expires_in_days: number;
}

export interface OrganizationMemberResponse {
  membership_id: string;
  organization_id: string;
  user_id: string;
  email: string;
  full_name: string;
  role: UserRole;
  created_at: string;
}

export interface OrganizationMemberAddRequest {
  email: string;
  full_name: string;
  password?: string;
  role: UserRole;
}

export interface AuditLogResponse {
  id: string;
  organization_id?: string | null;
  user_id?: string | null;
  action: string;
  resource_type: string;
  resource_id?: string | null;
  ip_address?: string | null;
  metadata_json: Record<string, unknown>;
  created_at: string;
}

// --- Fase 3: Execução de Auditorias (Scans), Progresso, Checks e Findings ---

export interface ScanCreateRequest {
  asset_id: string;
  profile_type: string;
  enabled_modules?: string[];
  max_requests_per_second?: number;
  max_concurrency?: number;
  request_timeout_seconds?: number;
  max_redirects?: number;
  idempotency_key?: string;
  execute_synchronously?: boolean;
}

export interface ScanResponse {
  id: string;
  organization_id: string;
  asset_id: string;
  asset_name?: string | null;
  target_url?: string | null;
  initiated_by_user_id?: string | null;
  profile_type: string;
  status:
    | "PENDING"
    | "QUEUED"
    | "RUNNING"
    | "COMPLETED"
    | "PARTIALLY_COMPLETED"
    | "FAILED"
    | "CANCELLED"
    | "ABORTED_TARGET_DEGRADED";
  progress_percent: number;
  current_module?: string | null;
  enabled_modules: string[];
  completed_modules: string[];
  failed_modules: string[];
  policy_snapshot: Record<string, unknown>;
  total_checks_run: number;
  findings_summary: Record<string, number>;
  elapsed_seconds: number;
  error_message?: string | null;
  celery_task_id?: string | null;
  started_at?: string | null;
  completed_at?: string | null;
  created_at: string;
}

export interface ScanProgressResponse {
  scan_id: string;
  asset_id: string;
  status: string;
  progress_percent: number;
  current_module?: string | null;
  enabled_modules: string[];
  completed_modules: string[];
  failed_modules: string[];
  total_checks_run: number;
  findings_summary: Record<string, number>;
  elapsed_seconds: number;
  error_message?: string | null;
  started_at?: string | null;
  completed_at?: string | null;
}

export interface ScanCheckResultResponse {
  id: string;
  scan_id: string;
  module_id: string;
  check_id: string;
  title: string;
  status:
    | "PASSED"
    | "VULNERABILITY"
    | "POTENTIAL_VULNERABILITY"
    | "INCONCLUSIVE"
    | "NOT_APPLICABLE"
    | "EXECUTION_ERROR";
  duration_ms: number;
  summary: string;
  details: Record<string, unknown>;
  created_at: string;
}

export interface FindingResponse {
  id: string;
  organization_id: string;
  asset_id: string;
  scan_id: string;
  fingerprint: string;
  module_id: string;
  check_id: string;
  title: string;
  description: string;
  category: string;
  result_classification: "VULNERABILITY" | "POTENTIAL_VULNERABILITY";
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  confidence: "CERTAIN" | "FIRM" | "TENTATIVE";
  cvss_v4_vector?: string | null;
  cvss_v4_score?: number | null;
  cwe_ids: string[];
  owasp_categories: string[];
  affected_endpoint: string;
  evidence: {
    request_method?: string | null;
    request_url?: string | null;
    request_headers?: Record<string, string>;
    response_status_code?: number | null;
    response_headers?: Record<string, string>;
    response_body_Excerpt?: string | null;
    observed_value?: string | null;
    expected_baseline?: string | null;
    technical_notes?: string[];
    redacted_fields_count?: number;
  };
  impact: string;
  reproduction_steps: string[];
  remediation_data: RemediationGuidance;
  treatment_status: string;
  asset_name?: string | null;
  triage_note?: string | null;
  assigned_to_user_id?: string | null;
  priority?: string | null;
  sla_deadline?: string | null;
  revalidation_scan_id?: string | null;
  risk_acceptance_reason?: string | null;
  first_detected_at: string;
  last_confirmed_at: string;
  resolved_at?: string | null;
}

export interface ScanDetailedResultsResponse {
  scan: ScanResponse;
  checks: ScanCheckResultResponse[];
  findings: FindingResponse[];
}

function resolveApiBaseUrl(): string {
  if (typeof window !== "undefined") {
    const envUrl = process.env.NEXT_PUBLIC_API_URL;
    if (!envUrl || envUrl.includes("localhost:8000") || envUrl.includes("127.0.0.1:8000") || envUrl.startsWith("/")) {
      return "/api/v1";
    }
    return envUrl;
  }
  return process.env.INTERNAL_API_URL || process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";
}

const API_BASE_URL = resolveApiBaseUrl();

function authHeaders(token?: string | null): HeadersInit {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }
  return headers;
}

export class ApiError extends Error {
  readonly status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

async function parseOrThrow<T>(res: Response, fallbackMsg: string): Promise<T> {
  if (!res.ok) {
    let detail = fallbackMsg;
    try {
      const body = await res.json();
      if (typeof body?.detail === "string") {
        detail = body.detail;
      }
    } catch {
      // ignore json parse error
    }
    throw new ApiError(detail, res.status);
  }
  return res.json();
}

export async function fetchSystemStatus(): Promise<SystemStatusResponse> {
  const res = await fetch(`${API_BASE_URL}/system/status`, {
    cache: "no-store",
  });
  return parseOrThrow(res, `Falha ao consultar status da API (${res.status})`);
}

export async function fetchSecurityModules(): Promise<
  SecurityModuleDescriptor[]
> {
  const res = await fetch(`${API_BASE_URL}/modules`, { cache: "no-store" });
  return parseOrThrow(res, `Falha ao consultar módulos (${res.status})`);
}

export async function fetchScanProfiles(): Promise<ScanProfileDescriptor[]> {
  const res = await fetch(`${API_BASE_URL}/profiles`, { cache: "no-store" });
  return parseOrThrow(
    res,
    `Falha ao consultar perfis de auditoria (${res.status})`
  );
}

export async function fetchRemediationCatalog(): Promise<
  RemediationGuidance[]
> {
  const res = await fetch(`${API_BASE_URL}/remediation`, { cache: "no-store" });
  return parseOrThrow(
    res,
    `Falha ao consultar catálogo de correções (${res.status})`
  );
}

export async function validateScopePolicy(
  payload: ScopeValidationRequest
): Promise<ScopeValidationResponse> {
  const res = await fetch(`${API_BASE_URL}/scope/validate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  return parseOrThrow(res, `Falha na validação de escopo (${res.status})`);
}

export async function registerUser(
  payload: UserRegisterRequest
): Promise<AuthSessionResponse> {
  const res = await fetch(`${API_BASE_URL}/auth/register`, {
    method: "POST",
    headers: authHeaders(),
    credentials: "include",
    body: JSON.stringify(payload),
  });
  return parseOrThrow(res, "Falha ao registrar usuário e organização.");
}

export async function loginUser(
  payload: UserLoginRequest
): Promise<AuthSessionResponse> {
  const res = await fetch(`${API_BASE_URL}/auth/login`, {
    method: "POST",
    headers: authHeaders(),
    credentials: "include",
    body: JSON.stringify(payload),
  });
  return parseOrThrow(res, "Credenciais inválidas.");
}

export async function logoutUser(token: string): Promise<void> {
  await fetch(`${API_BASE_URL}/auth/logout`, {
    method: "POST",
    headers: authHeaders(token),
    credentials: "include",
  });
}

export async function fetchAssets(token: string): Promise<AssetResponse[]> {
  const res = await fetch(`${API_BASE_URL}/assets`, {
    headers: authHeaders(token),
    credentials: "include",
    cache: "no-store",
  });
  return parseOrThrow(res, "Falha ao listar ativos da organização.");
}

export interface SshAuditResponse {
  id: string;
  status: SshAuditStatus;
  password_authentication: "enabled" | "disabled" | "unknown" | "collection_error";
  permit_root_login: "yes" | "no" | "prohibit-password" | "forced-commands-only" | "unknown" | "collection_error" | null;
  permit_root_login_status: SshAuditStatus | null;
  created_at: string;
}

type SshAuditStatus = "PASSED" | "VULNERABILITY" | "INCONCLUSIVE" | "EXECUTION_ERROR";

export async function fetchLatestSshAudit(
  token: string,
  assetId: string
): Promise<SshAuditResponse | null> {
  const res = await fetch(`${API_BASE_URL}/assets/${assetId}/ssh-audit`, {
    headers: authHeaders(token),
    credentials: "include",
    cache: "no-store",
  });
  return parseOrThrow(res, "Falha ao carregar o resultado da auditoria SSH.");
}

export interface TelemetrySource {
  id: string;
  name: string;
  network: string;
  status: "ACTIVE" | "PAUSED" | "EXPIRED" | "REVOKED";
  paused_at?: string | null;
  collector_version?: string | null;
  desired_version?: string | null;
  poll_interval_seconds?: number;
  config_version?: number;
  applied_config_version?: number | null;
  token_generation?: number;
  update_status?: "UP_TO_DATE" | "UPDATE_AVAILABLE" | "UNKNOWN";
  last_heartbeat_at?: string | null;
  expires_at: string;
  last_received_at: string | null;
  latest_observed_at: string | null;
  connection_count: number;
}

export interface TelemetrySourceCreated extends TelemetrySource {
  collector_token: string;
}

export async function fetchTelemetrySources(token: string, assetId: string): Promise<TelemetrySource[]> {
  const res = await fetch(`${API_BASE_URL}/assets/${assetId}/telemetry-sources`, {
    headers: authHeaders(token),
    credentials: "include",
    cache: "no-store",
  });
  return parseOrThrow(res, "Falha ao carregar as fontes de telemetria.");
}

export async function registerTelemetrySource(
  token: string, assetId: string, payload: { name: string; network: string }
): Promise<TelemetrySourceCreated> {
  const res = await fetch(`${API_BASE_URL}/assets/${assetId}/telemetry-sources`, {
    method: "POST",
    headers: authHeaders(token),
    credentials: "include",
    body: JSON.stringify(payload),
  });
  return parseOrThrow(res, "Falha ao cadastrar a fonte. Confira o segmento e a autorização do ativo.");
}

export async function revokeTelemetrySource(token: string, assetId: string, sourceId: string): Promise<void> {
  const res = await fetch(`${API_BASE_URL}/assets/${assetId}/telemetry-sources/${sourceId}`, {
    method: "DELETE",
    headers: authHeaders(token),
    credentials: "include",
  });
  if (!res.ok) await parseOrThrow(res, "Falha ao revogar a credencial da fonte.");
}

export interface TelemetrySourceUpdateRequest {
  name?: string;
  network?: string;
  desired_version?: string;
  poll_interval_seconds?: number;
}

export async function pauseTelemetrySource(
  token: string, assetId: string, sourceId: string
): Promise<TelemetrySource> {
  const res = await fetch(`${API_BASE_URL}/assets/${assetId}/telemetry-sources/${sourceId}/pause`, {
    method: "POST",
    headers: authHeaders(token),
    credentials: "include",
  });
  return parseOrThrow(res, "Falha ao pausar a fonte de telemetria.");
}

export async function resumeTelemetrySource(
  token: string, assetId: string, sourceId: string
): Promise<TelemetrySource> {
  const res = await fetch(`${API_BASE_URL}/assets/${assetId}/telemetry-sources/${sourceId}/resume`, {
    method: "POST",
    headers: authHeaders(token),
    credentials: "include",
  });
  return parseOrThrow(res, "Falha ao retomar a fonte de telemetria.");
}

export async function updateTelemetrySource(
  token: string, assetId: string, sourceId: string, payload: TelemetrySourceUpdateRequest
): Promise<TelemetrySource> {
  const res = await fetch(`${API_BASE_URL}/assets/${assetId}/telemetry-sources/${sourceId}`, {
    method: "PATCH",
    headers: authHeaders(token),
    credentials: "include",
    body: JSON.stringify(payload),
  });
  return parseOrThrow(res, "Falha ao atualizar a fonte de telemetria.");
}

export async function recoverTelemetrySource(
  token: string, assetId: string, sourceId: string, expiresInDays = 30
): Promise<TelemetrySourceCreated> {
  const res = await fetch(`${API_BASE_URL}/assets/${assetId}/telemetry-sources/${sourceId}/recover`, {
    method: "POST",
    headers: authHeaders(token),
    credentials: "include",
    body: JSON.stringify({ expires_in_days: expiresInDays }),
  });
  return parseOrThrow(res, "Falha ao recuperar a credencial da fonte.");
}

export async function createAsset(
  token: string,
  payload: AssetCreateRequest
): Promise<AssetResponse> {
  const res = await fetch(`${API_BASE_URL}/assets`, {
    method: "POST",
    headers: authHeaders(token),
    credentials: "include",
    body: JSON.stringify(payload),
  });
  return parseOrThrow(res, "Falha ao cadastrar ativo.");
}

export async function initiateAssetAuthorization(
  token: string,
  assetId: string,
  payload: AuthorizationInitiateRequest
): Promise<TargetAuthorizationResponse> {
  const res = await fetch(
    `${API_BASE_URL}/assets/${assetId}/authorizations`,
    {
      method: "POST",
      headers: authHeaders(token),
      credentials: "include",
      body: JSON.stringify(payload),
    }
  );
  return parseOrThrow(res, "Falha ao iniciar desafio de autorização.");
}

export async function fetchAssetAuthorizations(
  token: string,
  assetId: string
): Promise<TargetAuthorizationResponse[]> {
  const res = await fetch(
    `${API_BASE_URL}/assets/${assetId}/authorizations`,
    {
      headers: authHeaders(token),
      credentials: "include",
      cache: "no-store",
    }
  );
  return parseOrThrow(res, "Falha ao carregar autorizações do ativo.");
}

export async function verifyAssetAuthorization(
  token: string,
  assetId: string,
  authId: string
): Promise<TargetAuthorizationResponse> {
  const res = await fetch(
    `${API_BASE_URL}/assets/${assetId}/authorizations/${authId}/verify`,
    {
      method: "POST",
      headers: authHeaders(token),
      credentials: "include",
    }
  );
  return parseOrThrow(
    res,
    "Comprovação técnica não validada para este desafio."
  );
}

export async function revokeAssetAuthorization(
  token: string,
  assetId: string,
  authId: string
): Promise<TargetAuthorizationResponse> {
  const res = await fetch(
    `${API_BASE_URL}/assets/${assetId}/authorizations/${authId}/revoke`,
    {
      method: "POST",
      headers: authHeaders(token),
      credentials: "include",
    }
  );
  return parseOrThrow(res, "Falha ao revogar autorização.");
}

export async function fetchOrganizationMembers(
  token: string
): Promise<OrganizationMemberResponse[]> {
  const res = await fetch(`${API_BASE_URL}/organizations/members`, {
    headers: authHeaders(token),
    credentials: "include",
    cache: "no-store",
  });
  return parseOrThrow(res, "Falha ao listar membros da organização.");
}

export async function addOrganizationMember(
  token: string,
  payload: OrganizationMemberAddRequest
): Promise<OrganizationMemberResponse> {
  const res = await fetch(`${API_BASE_URL}/organizations/members`, {
    method: "POST",
    headers: authHeaders(token),
    credentials: "include",
    body: JSON.stringify(payload),
  });
  return parseOrThrow(res, "Falha ao adicionar/atualizar membro.");
}

export async function fetchAuditLogs(
  token: string
): Promise<AuditLogResponse[]> {
  const res = await fetch(`${API_BASE_URL}/audit-logs`, {
    headers: authHeaders(token),
    credentials: "include",
    cache: "no-store",
  });
  return parseOrThrow(res, "Falha ao carregar trilha de auditoria.");
}

export async function createScan(
  token: string,
  payload: ScanCreateRequest
): Promise<ScanResponse> {
  const res = await fetch(`${API_BASE_URL}/scans`, {
    method: "POST",
    headers: authHeaders(token),
    credentials: "include",
    body: JSON.stringify(payload),
  });
  return parseOrThrow(res, "Falha ao iniciar auditoria de segurança.");
}

export async function fetchScans(
  token: string,
  assetId?: string | null
): Promise<ScanResponse[]> {
  const query = assetId ? `?asset_id=${encodeURIComponent(assetId)}` : "";
  const res = await fetch(`${API_BASE_URL}/scans${query}`, {
    headers: authHeaders(token),
    credentials: "include",
    cache: "no-store",
  });
  return parseOrThrow(res, "Falha ao listar auditorias da organização.");
}

export async function fetchScanProgress(
  token: string,
  scanId: string
): Promise<ScanProgressResponse> {
  const res = await fetch(`${API_BASE_URL}/scans/${scanId}/progress`, {
    headers: authHeaders(token),
    credentials: "include",
    cache: "no-store",
  });
  return parseOrThrow(res, "Falha ao consultar progresso da auditoria.");
}

export async function fetchScanDetailedResults(
  token: string,
  scanId: string
): Promise<ScanDetailedResultsResponse> {
  const res = await fetch(`${API_BASE_URL}/scans/${scanId}/results`, {
    headers: authHeaders(token),
    credentials: "include",
    cache: "no-store",
  });
  return parseOrThrow(
    res,
    "Falha ao carregar resultados detalhados da auditoria."
  );
}

export async function cancelScan(
  token: string,
  scanId: string
): Promise<ScanResponse> {
  const res = await fetch(`${API_BASE_URL}/scans/${scanId}/cancel`, {
    method: "POST",
    headers: authHeaders(token),
    credentials: "include",
  });
  return parseOrThrow(res, "Falha ao cancelar auditoria.");
}

export async function fetchFindings(
  token: string,
  assetId?: string | null
): Promise<FindingResponse[]> {
  const query = assetId ? `?asset_id=${encodeURIComponent(assetId)}` : "";
  const res = await fetch(`${API_BASE_URL}/findings${query}`, {
    headers: authHeaders(token),
    credentials: "include",
    cache: "no-store",
  });
  return parseOrThrow(
    res,
    "Falha ao carregar vulnerabilidades da organização."
  );
}


// ---------------------------------------------------------------------------
// Fase 4: dashboard, vulnerabilidades, auditorias paginadas e fluxo SSE
// ---------------------------------------------------------------------------

export interface PageResponse<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface TrendPoint {
  date: string;
  detected: number;
  resolved: number;
  scans: number;
}

export interface DashboardTrendsResponse {
  days: number;
  points: TrendPoint[];
}

export interface FindingFilters {
  asset_id?: string;
  scan_id?: string;
  severity?: string;
  treatment_status?: string;
  confidence?: string;
  category?: string;
  module_id?: string;
  cwe_id?: string;
  owasp_category?: string;
  search?: string;
  date_from?: string;
  date_to?: string;
  sort_by?: string;
  sort_desc?: boolean;
  limit?: number;
  offset?: number;
}

export interface ScanFilters {
  asset_id?: string;
  status?: string;
  search?: string;
  date_from?: string;
  date_to?: string;
  sort_by?: string;
  sort_desc?: boolean;
  limit?: number;
  offset?: number;
}

export interface FindingDetectionItem {
  finding_id: string;
  scan_id: string;
  severity: string;
  confidence: string;
  treatment_status: string;
  detected_at: string;
}

export interface FindingTriageEvent {
  id: string;
  user_id?: string | null;
  previous_status?: string | null;
  new_status?: string | null;
  triage_note?: string | null;
  created_at: string;
}

export interface FindingHistoryResponse {
  finding_id: string;
  detections: FindingDetectionItem[];
  triage_events: FindingTriageEvent[];
}

export interface ScanEventItem {
  id: string;
  action: string;
  user_id?: string | null;
  created_at: string;
  metadata: Record<string, unknown>;
}

export interface FindingTriageUpdateRequest {
  treatment_status: string;
  triage_note?: string | null;
  assigned_to_user_id?: string | null;
  priority?: string | null;
  sla_deadline?: string | null;
  risk_acceptance_reason?: string | null;
}

export interface AssetUpdateRequest {
  name?: string;
  target_url?: string;
  environment?: AssetResponse["environment"];
  owner_name?: string;
  owner_email?: string;
  tags?: string[];
  excluded_paths?: string[];
}

/** Serializa filtros ignorando valores vazios (função pura, testável). */
export function buildQueryString(params: object): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === "") continue;
    search.set(key, String(value));
  }
  const qs = search.toString();
  return qs ? `?${qs}` : "";
}

async function authedGet<T>(
  token: string,
  path: string,
  fallbackMsg: string
): Promise<T> {
  const res = await fetch(`${API_BASE_URL}${path}`, {
    headers: authHeaders(token),
    credentials: "include",
    cache: "no-store",
  });
  return parseOrThrow<T>(res, fallbackMsg);
}

export function fetchDashboardSummary(
  token: string
): Promise<PlatformMetricsSummary> {
  return authedGet(
    token,
    "/dashboard/summary",
    "Falha ao carregar indicadores do painel."
  );
}

export function fetchDashboardTrends(
  token: string,
  days = 30
): Promise<DashboardTrendsResponse> {
  return authedGet(
    token,
    `/dashboard/trends${buildQueryString({ days })}`,
    "Falha ao carregar a série histórica."
  );
}

export function fetchFindingsPage(
  token: string,
  filters: FindingFilters
): Promise<PageResponse<FindingResponse>> {
  return authedGet(
    token,
    `/findings/page${buildQueryString(filters)}`,
    "Falha ao carregar vulnerabilidades."
  );
}

export function fetchFinding(
  token: string,
  findingId: string
): Promise<FindingResponse> {
  return authedGet(
    token,
    `/findings/${encodeURIComponent(findingId)}`,
    "Falha ao carregar a vulnerabilidade."
  );
}

export function fetchFindingHistory(
  token: string,
  findingId: string
): Promise<FindingHistoryResponse> {
  return authedGet(
    token,
    `/findings/${encodeURIComponent(findingId)}/history`,
    "Falha ao carregar o histórico da vulnerabilidade."
  );
}

export async function updateFindingStatus(
  token: string,
  findingId: string,
  payload: FindingTriageUpdateRequest
): Promise<FindingResponse> {
  const res = await fetch(
    `${API_BASE_URL}/findings/${encodeURIComponent(findingId)}/status`,
    {
      method: "PATCH",
      headers: authHeaders(token),
      credentials: "include",
      body: JSON.stringify(payload),
    }
  );
  return parseOrThrow(res, "Falha ao atualizar a triagem da vulnerabilidade.");
}

export function fetchScansPage(
  token: string,
  filters: ScanFilters
): Promise<PageResponse<ScanResponse>> {
  return authedGet(
    token,
    `/scans/page${buildQueryString(filters)}`,
    "Falha ao listar auditorias."
  );
}

export function fetchScanEvents(
  token: string,
  scanId: string
): Promise<ScanEventItem[]> {
  return authedGet(
    token,
    `/scans/${encodeURIComponent(scanId)}/events`,
    "Falha ao carregar eventos da auditoria."
  );
}

export async function updateAsset(
  token: string,
  assetId: string,
  payload: AssetUpdateRequest
): Promise<AssetResponse> {
  const res = await fetch(
    `${API_BASE_URL}/assets/${encodeURIComponent(assetId)}`,
    {
      method: "PATCH",
      headers: authHeaders(token),
      credentials: "include",
      body: JSON.stringify(payload),
    }
  );
  return parseOrThrow(res, "Falha ao atualizar o ativo.");
}

export interface SseMessage {
  event: string;
  data: string;
}

/** Interpreta blocos SSE acumulados; devolve mensagens completas e o restante do buffer. */
export function parseSseBuffer(buffer: string): {
  messages: SseMessage[];
  rest: string;
} {
  const normalized = buffer.replace(/\r\n/g, "\n");
  const blocks = normalized.split("\n\n");
  const rest = blocks.pop() ?? "";
  const messages: SseMessage[] = [];
  for (const block of blocks) {
    let event = "message";
    const dataLines: string[] = [];
    for (const line of block.split("\n")) {
      if (line.startsWith(":")) continue;
      if (line.startsWith("event:")) event = line.slice(6).trim();
      else if (line.startsWith("data:")) dataLines.push(line.slice(5).trim());
    }
    if (dataLines.length > 0) {
      messages.push({ event, data: dataLines.join("\n") });
    }
  }
  return { messages, rest };
}

/**
 * Abre o fluxo SSE autenticado (fetch + Authorization, pois EventSource não envia cabeçalhos).
 * Resolve com "ended" quando o servidor encerra a auditoria; rejeita em erro de rede/HTTP.
 */
export async function streamScanProgress(
  token: string,
  scanId: string,
  onProgress: (progress: ScanProgressResponse) => void,
  signal: AbortSignal
): Promise<"ended" | "timeout"> {
  const res = await fetch(
    `${API_BASE_URL}/scans/${encodeURIComponent(scanId)}/stream`,
    {
      headers: { ...(authHeaders(token) as Record<string, string>), Accept: "text/event-stream" },
      credentials: "include",
      cache: "no-store",
      signal,
    }
  );
  if (!res.ok || !res.body) {
    throw new ApiError("Fluxo em tempo real indisponível.", res.status);
  }
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) throw new Error("Fluxo em tempo real encerrado inesperadamente.");
    buffer += decoder.decode(value, { stream: true });
    const parsed = parseSseBuffer(buffer);
    buffer = parsed.rest;
    for (const msg of parsed.messages) {
      if (msg.event === "progress") {
        onProgress(JSON.parse(msg.data) as ScanProgressResponse);
      } else if (msg.event === "end") {
        return "ended";
      } else if (msg.event === "timeout") {
        return "timeout";
      }
    }
  }
}

// =============================================================================
// FASE 6 — RELATÓRIOS, COMPARAÇÃO, REVALIDAÇÃO E EVOLUÇÃO
// =============================================================================

export type ReportType =
  | "EXECUTIVE"
  | "TECHNICAL"
  | "COMPARISON"
  | "REMEDIATION_TRACKING"
  | "ASSET"
  | "SCAN"
  | "FINDING";

export type ReportFormat = "PDF" | "HTML" | "JSON" | "CSV";

export type ReportStatus = "PENDING" | "GENERATING" | "COMPLETED" | "FAILED" | "EXPIRED";

export interface ReportCreateRequest {
  report_type: ReportType;
  format: ReportFormat;
  title?: string;
  asset_id?: string | null;
  scan_id?: string | null;
  finding_id?: string | null;
  comparison_scan_id_a?: string | null;
  comparison_scan_id_b?: string | null;
  filter_params?: Record<string, unknown>;
  execute_synchronously?: boolean;
}

export interface ReportResponse {
  id: string;
  organization_id: string;
  created_by_user_id?: string | null;
  report_type: ReportType;
  format: ReportFormat;
  status: ReportStatus;
  title: string;
  asset_id?: string | null;
  asset_name?: string | null;
  scan_id?: string | null;
  finding_id?: string | null;
  comparison_scan_id_a?: string | null;
  comparison_scan_id_b?: string | null;
  filter_params: Record<string, unknown>;
  summary_data: Record<string, unknown>;
  file_size_bytes: number;
  download_token?: string | null;
  download_url?: string | null;
  expires_at?: string | null;
  error_message?: string | null;
  created_at: string;
  completed_at?: string | null;
}

export interface ReportPageResponse {
  items: ReportResponse[];
  total: number;
  limit: number;
  offset: number;
}

export interface CoverageDiff {
  modules_a: string[];
  modules_b: string[];
  common_modules: string[];
  modules_added_in_b: string[];
  modules_removed_in_b: string[];
  checks_count_a: number;
  checks_count_b: number;
  duration_ms_a: number;
  duration_ms_b: number;
  profile_a: string;
  profile_b: string;
}

export interface FindingSeverityChange {
  fingerprint: string;
  title: string;
  previous_severity: string;
  current_severity: string;
  previous_confidence: string;
  current_confidence: string;
}

export interface ScanComparisonResponse {
  scan_a: ScanResponse;
  scan_b: ScanResponse;
  asset_id: string;
  asset_name?: string | null;
  total_findings_a: number;
  total_findings_b: number;
  new_findings: FindingResponse[];
  persistent_findings: FindingResponse[];
  confirmed_remediated: FindingResponse[];
  not_detected_again: FindingResponse[];
  not_verified_coverage: FindingResponse[];
  reopened_findings: FindingResponse[];
  severity_changes: FindingSeverityChange[];
  coverage_diff: CoverageDiff;
  comparison_summary: Record<string, unknown>;
}

export interface RevalidationRequest {
  triage_note?: string | null;
}

export interface RevalidationResponse {
  finding_id: string;
  scan_id: string;
  status: string;
  message: string;
  check_result?: ScanCheckResultResponse | null;
  previous_status: string;
  new_status: string;
  verified_at: string;
}

export interface EvolutionPoint {
  date: string;
  open_count: number;
  in_progress_count: number;
  resolved_count: number;
  accepted_risk_count: number;
  reopened_count: number;
  new_detected_count: number;
  scans_executed: number;
}

export interface DashboardEvolutionResponse {
  days: number;
  points: EvolutionPoint[];
  mttr_average_days?: number | null;
  total_resolved: number;
  total_reopened: number;
  total_accepted_risk: number;
  total_active_unresolved: number;
}

export async function createReport(
  token: string,
  payload: ReportCreateRequest
): Promise<ReportResponse> {
  const res = await fetch(`${API_BASE_URL}/reports`, {
    method: "POST",
    headers: authHeaders(token),
    credentials: "include",
    body: JSON.stringify(payload),
  });
  return parseOrThrow(res, "Falha ao gerar relatório.");
}

export async function listReports(
  token: string,
  params?: {
    asset_id?: string;
    scan_id?: string;
    report_type?: string;
    format?: string;
    status?: string;
    limit?: number;
    offset?: number;
  }
): Promise<ReportPageResponse> {
  const qs = params ? buildQueryString(params) : "";
  const res = await fetch(`${API_BASE_URL}/reports${qs}`, {
    headers: authHeaders(token),
    credentials: "include",
  });
  return parseOrThrow(res, "Falha ao listar relatórios.");
}

export async function getReport(
  token: string,
  reportId: string
): Promise<ReportResponse> {
  const res = await fetch(`${API_BASE_URL}/reports/${encodeURIComponent(reportId)}`, {
    headers: authHeaders(token),
    credentials: "include",
  });
  return parseOrThrow(res, "Falha ao consultar detalhes do relatório.");
}

export async function deleteReport(
  token: string,
  reportId: string
): Promise<void> {
  const res = await fetch(`${API_BASE_URL}/reports/${encodeURIComponent(reportId)}`, {
    method: "DELETE",
    headers: authHeaders(token),
    credentials: "include",
  });
  if (!res.ok) {
    throw new ApiError("Falha ao excluir relatório.", res.status);
  }
}

export async function compareScans(
  token: string,
  scanIdA: string,
  scanIdB: string
): Promise<ScanComparisonResponse> {
  const res = await fetch(
    `${API_BASE_URL}/scans/${encodeURIComponent(scanIdA)}/compare/${encodeURIComponent(scanIdB)}`,
    {
      headers: authHeaders(token),
      credentials: "include",
    }
  );
  return parseOrThrow(res, "Falha ao comparar auditorias.");
}

export async function revalidateFinding(
  token: string,
  findingId: string,
  payload: RevalidationRequest
): Promise<RevalidationResponse> {
  const res = await fetch(
    `${API_BASE_URL}/findings/${encodeURIComponent(findingId)}/revalidate`,
    {
      method: "POST",
      headers: authHeaders(token),
      credentials: "include",
      body: JSON.stringify(payload),
    }
  );
  return parseOrThrow(res, "Falha ao solicitar revalidação técnica da vulnerabilidade.");
}

export async function getDashboardEvolution(
  token: string,
  days: number = 30
): Promise<DashboardEvolutionResponse> {
  const res = await fetch(`${API_BASE_URL}/dashboard/evolution?days=${days}`, {
    headers: authHeaders(token),
    credentials: "include",
  });
  return parseOrThrow(res, "Falha ao carregar métricas de evolução temporal.");
}

// ============================================================================
// FASE 7: Automação, Agendamentos, Notificações, Webhooks, API Tokens e Templates
// ============================================================================

export interface ScanSchedule {
  id: string;
  organization_id: string;
  asset_id: string;
  asset_name?: string | null;
  profile_type: string;
  enabled_modules: string[];
  frequency: string;
  cron_expression: string;
  timezone: string;
  status: string;
  is_active: boolean;
  misfire_policy: string;
  consecutive_failures: number;
  last_run_at?: string | null;
  next_run_at?: string | null;
  last_scan_id?: string | null;
  created_at: string;
  updated_at?: string | null;
}

export interface ScanScheduleCreateRequest {
  asset_id: string;
  profile_type?: string;
  enabled_modules?: string[];
  frequency?: string;
  cron_expression?: string;
  timezone?: string;
  misfire_policy?: string;
}

export interface ScanScheduleUpdateRequest {
  profile_type?: string;
  enabled_modules?: string[];
  frequency?: string;
  cron_expression?: string;
  timezone?: string;
  misfire_policy?: string;
  status?: string;
}

export interface ScanSchedulePageResponse {
  items: ScanSchedule[];
  total: number;
  limit: number;
  offset: number;
}

export interface NotificationItem {
  id: string;
  organization_id: string;
  user_id?: string | null;
  event_type: string;
  severity: "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | string;
  title: string;
  message: string;
  link_url?: string | null;
  read_at?: string | null;
  metadata_json: Record<string, any>;
  created_at: string;
}

export interface NotificationPageResponse {
  items: NotificationItem[];
  total: number;
  unread_count: number;
  limit: number;
  offset: number;
}

export interface NotificationPreference {
  id: string;
  organization_id: string;
  user_id: string;
  email_enabled: boolean;
  email_destination?: string | null;
  channels: string[];
  min_severity: string;
  subscribed_events: string[];
  updated_at?: string | null;
}

export interface NotificationPreferenceUpdateRequest {
  email_enabled?: boolean;
  email_destination?: string | null;
  channels?: string[];
  min_severity?: string;
  subscribed_events?: string[];
}

export interface WebhookEndpoint {
  id: string;
  organization_id: string;
  url: string;
  description?: string | null;
  secret_token_prefix: string;
  subscribed_events: string[];
  is_active: boolean;
  consecutive_failures: number;
  created_at: string;
  updated_at?: string | null;
}

export interface WebhookEndpointCreateRequest {
  url: string;
  description?: string | null;
  subscribed_events?: string[];
}

export interface WebhookEndpointUpdateRequest {
  url?: string;
  description?: string | null;
  subscribed_events?: string[];
  is_active?: boolean;
}

export interface WebhookDelivery {
  id: string;
  webhook_id: string;
  organization_id: string;
  event_type: string;
  event_id: string;
  payload: Record<string, any>;
  status: string;
  status_code?: number | null;
  response_body?: string | null;
  duration_ms?: number | null;
  attempt_count: number;
  next_retry_at?: string | null;
  error_message?: string | null;
  created_at: string;
}

export interface WebhookDeliveryPageResponse {
  items: WebhookDelivery[];
  total: number;
  limit: number;
  offset: number;
}

export interface WebhookTestResponse {
  status: string;
  status_code?: number | null;
  response_summary?: string | null;
  duration_ms?: number | null;
  message: string;
}

export interface ApiToken {
  id: string;
  organization_id: string;
  user_id: string;
  name: string;
  token_prefix: string;
  scopes: string[];
  expires_at?: string | null;
  last_used_at?: string | null;
  is_revoked: boolean;
  created_at: string;
}

export interface ApiTokenCreated {
  id: string;
  name: string;
  token_prefix: string;
  raw_api_token: string;
  scopes: string[];
  expires_at?: string | null;
  created_at: string;
}

export interface ApiTokenCreateRequest {
  name: string;
  scopes?: string[];
  expires_in_days?: number | null;
}

export interface ApiTokenPageResponse {
  items: ApiToken[];
  total: number;
  limit: number;
  offset: number;
}

export interface ScanTemplate {
  id: string;
  organization_id: string;
  name: string;
  description?: string | null;
  profile_type: string;
  enabled_modules: string[];
  parameters: Record<string, any>;
  environment_type?: string | null;
  created_at: string;
  updated_at?: string | null;
}

export interface ScanTemplateCreateRequest {
  name: string;
  description?: string | null;
  profile_type?: string;
  enabled_modules?: string[];
  parameters?: Record<string, any>;
  environment_type?: string | null;
}

export interface ScanTemplateUpdateRequest {
  name?: string;
  description?: string | null;
  profile_type?: string;
  enabled_modules?: string[];
  parameters?: Record<string, any>;
  environment_type?: string | null;
}

export interface ScanTemplatePageResponse {
  items: ScanTemplate[];
  total: number;
  limit: number;
  offset: number;
}

// ============================================================================
// API Methods da Fase 7
// ============================================================================

export async function listSchedules(
  token: string,
  params?: { asset_id?: string; status?: string; limit?: number; offset?: number }
): Promise<ScanSchedulePageResponse> {
  const query = new URLSearchParams();
  if (params?.asset_id) query.set("asset_id", params.asset_id);
  if (params?.status) query.set("status", params.status);
  if (params?.limit) query.set("limit", String(params.limit));
  if (params?.offset) query.set("offset", String(params.offset));

  const res = await fetch(`${API_BASE_URL}/automations/schedules?${query.toString()}`, {
    headers: authHeaders(token),
    credentials: "include",
  });
  return parseOrThrow(res, "Falha ao carregar agendamentos de auditorias.");
}

export async function createSchedule(
  token: string,
  payload: ScanScheduleCreateRequest
): Promise<ScanSchedule> {
  const res = await fetch(`${API_BASE_URL}/automations/schedules`, {
    method: "POST",
    headers: authHeaders(token),
    credentials: "include",
    body: JSON.stringify(payload),
  });
  return parseOrThrow(res, "Falha ao criar agendamento de auditoria.");
}

export async function pauseSchedule(
  token: string,
  scheduleId: string
): Promise<ScanSchedule> {
  const res = await fetch(`${API_BASE_URL}/automations/schedules/${encodeURIComponent(scheduleId)}/pause`, {
    method: "POST",
    headers: authHeaders(token),
    credentials: "include",
  });
  return parseOrThrow(res, "Falha ao pausar agendamento.");
}

export async function resumeSchedule(
  token: string,
  scheduleId: string
): Promise<ScanSchedule> {
  const res = await fetch(`${API_BASE_URL}/automations/schedules/${encodeURIComponent(scheduleId)}/resume`, {
    method: "POST",
    headers: authHeaders(token),
    credentials: "include",
  });
  return parseOrThrow(res, "Falha ao retomar agendamento.");
}

export async function deleteSchedule(
  token: string,
  scheduleId: string
): Promise<void> {
  const res = await fetch(`${API_BASE_URL}/automations/schedules/${encodeURIComponent(scheduleId)}`, {
    method: "DELETE",
    headers: authHeaders(token),
    credentials: "include",
  });
  if (!res.ok) {
    throw new ApiError("Falha ao excluir agendamento.", res.status);
  }
}

export async function triggerDueSchedules(
  token: string
): Promise<{ triggered_scan_ids: string[] }> {
  const res = await fetch(`${API_BASE_URL}/automations/schedules/trigger-due`, {
    method: "POST",
    headers: authHeaders(token),
    credentials: "include",
  });
  return parseOrThrow(res, "Falha ao verificar agendamentos pendentes.");
}

export async function listNotifications(
  token: string,
  params?: { unread_only?: boolean; limit?: number; offset?: number }
): Promise<NotificationPageResponse> {
  const query = new URLSearchParams();
  if (params?.unread_only) query.set("unread_only", "true");
  if (params?.limit) query.set("limit", String(params.limit));
  if (params?.offset) query.set("offset", String(params.offset));

  const res = await fetch(`${API_BASE_URL}/automations/notifications?${query.toString()}`, {
    headers: authHeaders(token),
    credentials: "include",
  });
  return parseOrThrow(res, "Falha ao carregar notificações.");
}

export async function markNotificationRead(
  token: string,
  notificationId: string
): Promise<{ updated: number }> {
  const res = await fetch(`${API_BASE_URL}/automations/notifications/${encodeURIComponent(notificationId)}/read`, {
    method: "POST",
    headers: authHeaders(token),
    credentials: "include",
  });
  return parseOrThrow(res, "Falha ao marcar notificação como lida.");
}

export async function markAllNotificationsRead(
  token: string
): Promise<{ updated: number }> {
  const res = await fetch(`${API_BASE_URL}/automations/notifications/read-all`, {
    method: "POST",
    headers: authHeaders(token),
    credentials: "include",
  });
  return parseOrThrow(res, "Falha ao marcar notificações como lidas.");
}

export async function getNotificationPreferences(
  token: string
): Promise<NotificationPreference> {
  const res = await fetch(`${API_BASE_URL}/automations/notifications/preferences`, {
    headers: authHeaders(token),
    credentials: "include",
  });
  return parseOrThrow(res, "Falha ao consultar preferências de notificações.");
}

export async function updateNotificationPreferences(
  token: string,
  payload: NotificationPreferenceUpdateRequest
): Promise<NotificationPreference> {
  const res = await fetch(`${API_BASE_URL}/automations/notifications/preferences`, {
    method: "PUT",
    headers: authHeaders(token),
    credentials: "include",
    body: JSON.stringify(payload),
  });
  return parseOrThrow(res, "Falha ao atualizar preferências de notificações.");
}

export async function listWebhooks(
  token: string
): Promise<WebhookEndpoint[]> {
  const res = await fetch(`${API_BASE_URL}/automations/webhooks`, {
    headers: authHeaders(token),
    credentials: "include",
  });
  return parseOrThrow(res, "Falha ao listar webhooks.");
}

export async function createWebhook(
  token: string,
  payload: WebhookEndpointCreateRequest
): Promise<WebhookEndpoint> {
  const res = await fetch(`${API_BASE_URL}/automations/webhooks`, {
    method: "POST",
    headers: authHeaders(token),
    credentials: "include",
    body: JSON.stringify(payload),
  });
  return parseOrThrow(res, "Falha ao cadastrar webhook.");
}

export async function deleteWebhook(
  token: string,
  webhookId: string
): Promise<void> {
  const res = await fetch(`${API_BASE_URL}/automations/webhooks/${encodeURIComponent(webhookId)}`, {
    method: "DELETE",
    headers: authHeaders(token),
    credentials: "include",
  });
  if (!res.ok) {
    throw new ApiError("Falha ao excluir webhook.", res.status);
  }
}

export async function rotateWebhookSecret(
  token: string,
  webhookId: string
): Promise<{ id: string; new_secret_token: string; message: string }> {
  const res = await fetch(`${API_BASE_URL}/automations/webhooks/${encodeURIComponent(webhookId)}/rotate-secret`, {
    method: "POST",
    headers: authHeaders(token),
    credentials: "include",
  });
  return parseOrThrow(res, "Falha ao rotacionar chave secreta do webhook.");
}

export async function testWebhook(
  token: string,
  webhookId: string
): Promise<WebhookTestResponse> {
  const res = await fetch(`${API_BASE_URL}/automations/webhooks/${encodeURIComponent(webhookId)}/test`, {
    method: "POST",
    headers: authHeaders(token),
    credentials: "include",
  });
  return parseOrThrow(res, "Falha ao disparar teste de webhook.");
}

export async function listWebhookDeliveries(
  token: string,
  params?: { webhook_id?: string; limit?: number; offset?: number }
): Promise<WebhookDeliveryPageResponse> {
  const query = new URLSearchParams();
  if (params?.webhook_id) query.set("webhook_id", params.webhook_id);
  if (params?.limit) query.set("limit", String(params.limit));
  if (params?.offset) query.set("offset", String(params.offset));

  const res = await fetch(`${API_BASE_URL}/automations/webhooks/deliveries?${query.toString()}`, {
    headers: authHeaders(token),
    credentials: "include",
  });
  return parseOrThrow(res, "Falha ao carregar entregas de webhook.");
}

export async function listApiTokens(
  token: string,
  params?: { limit?: number; offset?: number }
): Promise<ApiTokenPageResponse> {
  const query = new URLSearchParams();
  if (params?.limit) query.set("limit", String(params.limit));
  if (params?.offset) query.set("offset", String(params.offset));

  const res = await fetch(`${API_BASE_URL}/automations/api-tokens?${query.toString()}`, {
    headers: authHeaders(token),
    credentials: "include",
  });
  return parseOrThrow(res, "Falha ao listar chaves de API.");
}

export async function createApiToken(
  token: string,
  payload: ApiTokenCreateRequest
): Promise<ApiTokenCreated> {
  const res = await fetch(`${API_BASE_URL}/automations/api-tokens`, {
    method: "POST",
    headers: authHeaders(token),
    credentials: "include",
    body: JSON.stringify(payload),
  });
  return parseOrThrow(res, "Falha ao gerar chave de API.");
}

export async function revokeApiToken(
  token: string,
  tokenId: string
): Promise<void> {
  const res = await fetch(`${API_BASE_URL}/automations/api-tokens/${encodeURIComponent(tokenId)}`, {
    method: "DELETE",
    headers: authHeaders(token),
    credentials: "include",
  });
  if (!res.ok) {
    throw new ApiError("Falha ao revogar chave de API.", res.status);
  }
}

export async function listTemplates(
  token: string,
  params?: { limit?: number; offset?: number }
): Promise<ScanTemplatePageResponse> {
  const query = new URLSearchParams();
  if (params?.limit) query.set("limit", String(params.limit));
  if (params?.offset) query.set("offset", String(params.offset));

  const res = await fetch(`${API_BASE_URL}/automations/templates?${query.toString()}`, {
    headers: authHeaders(token),
    credentials: "include",
  });
  return parseOrThrow(res, "Falha ao listar templates de auditoria.");
}

export async function createTemplate(
  token: string,
  payload: ScanTemplateCreateRequest
): Promise<ScanTemplate> {
  const res = await fetch(`${API_BASE_URL}/automations/templates`, {
    method: "POST",
    headers: authHeaders(token),
    credentials: "include",
    body: JSON.stringify(payload),
  });
  return parseOrThrow(res, "Falha ao cadastrar template.");
}

export async function deleteTemplate(
  token: string,
  templateId: string
): Promise<void> {
  const res = await fetch(`${API_BASE_URL}/automations/templates/${encodeURIComponent(templateId)}`, {
    method: "DELETE",
    headers: authHeaders(token),
    credentials: "include",
  });
  if (!res.ok) {
    throw new ApiError("Falha ao excluir template.", res.status);
  }
}

export async function seedTemplates(
  token: string
): Promise<ScanTemplate[]> {
  const res = await fetch(`${API_BASE_URL}/automations/templates/seed`, {
    method: "POST",
    headers: authHeaders(token),
    credentials: "include",
  });
  return parseOrThrow(res, "Falha ao inicializar templates padrões.");
}

export async function exportScanPdf(
  token: string,
  scanId: string
): Promise<Blob> {
  const res = await fetch(`${API_BASE_URL}/scans/${encodeURIComponent(scanId)}/export-pdf`, {
    headers: authHeaders(token),
    credentials: "include",
  });
  if (!res.ok) {
    throw new ApiError("Falha ao exportar PDF da auditoria.", res.status);
  }
  return res.blob();
}

export async function downloadScanPdfFile(
  token: string,
  scanId: string
): Promise<void> {
  const blob = await exportScanPdf(token, scanId);
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `csc-auditoria-${scanId.slice(0, 8)}.pdf`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  window.URL.revokeObjectURL(url);
}

export interface AvailabilityTimelineEvent {
  event: "DEGRADATION_START" | "ALERT_OPENED" | "RECOVERY_START" | "RECOVERY_DETECTED";
  expected_offset_ms: number;
  observed_offset_ms: number | null;
  delta_ms: number | null;
}

export interface AvailabilityMetricsSummary {
  peak_latency_ms: number | null;
  error_5xx_count: number;
  rate_limited_429_count: number;
  timeout_or_connection_error_count: number;
}

export interface AvailabilitySignal {
  id: string;
  source_type: "FIREWALL" | "CDN" | "PROVIDER";
  signal: "RATE_LIMITED" | "UPSTREAM_ERROR" | "SATURATION" | "MITIGATION_ACTIVE" | "RECOVERED";
  offset_ms: number;
  http_status: number | null;
  created_at: string;
}

export interface AvailabilityExercise {
  id: string;
  status: "RUNNING" | "FINISHED";
  scenario?: "LATENCY" | "ERRORS" | "SATURATION";
  state: "NORMAL" | "ALERT" | "RECOVERED";
  result: "PASSED" | "FAILED" | "INCONCLUSIVE" | "EXECUTION_ERROR" | null;
  hostname: string;
  threshold_ms: number;
  consecutive_samples: number;
  interval_ms: number;
  normal_ms: number;
  degraded_ms: number;
  planned_duration_ms: number;
  tolerance_ms: number;
  sample_count: number;
  metrics_summary?: AvailabilityMetricsSummary;
  timeline: AvailabilityTimelineEvent[];
  signals?: AvailabilitySignal[];
  alert_publication_ms: number | null;
  recovery_publication_ms: number | null;
  started_at: string;
  finished_at: string | null;
}

export async function fetchAvailabilityExercises(token: string, assetId: string): Promise<AvailabilityExercise[]> {
  const res = await fetch(`${API_BASE_URL}/assets/${assetId}/availability-exercises`, {
    headers: authHeaders(token),
    credentials: "include",
    cache: "no-store",
  });
  return parseOrThrow(res, "Falha ao carregar os exercícios de disponibilidade.");
}

export interface TrafficCoverage {
  observed_layers: string[];
  missing_layers: string[];
}

export interface SuspiciousTrafficAlert {
  id: string;
  rule_id: string;
  category: "CONNECTIONS" | "DNS" | "TLS";
  severity: "HIGH" | "MEDIUM" | "LOW";
  confidence: "HIGH" | "MEDIUM" | "LOW";
  title: string;
  explanation: string;
  evidence: Record<string, unknown>;
  observed_layers: string[];
  missing_layers: string[];
  created_at: string;
}

export interface TrafficTlsDecision {
  id: string;
  uid: string;
  server_name: string;
  responder_ip: string;
  responder_port: number;
  outcome: "BASELINE_ESTABLISHED" | "UNCHANGED" | "BENIGN_ROTATION" | "INTERCEPTION_ALERT";
  observed_cert_sha256: string;
  previous_cert_sha256: string | null;
  observed_issuer: string;
  previous_issuer: string | null;
  reason: string;
  observed_at: string;
}

export interface TrafficEdrSignal {
  id: string;
  uid: string;
  host_ip: string;
  source_type: "ANTIVIRUS" | "EDR";
  signal: "SUSPICIOUS_PROCESS" | "UNTRUSTED_ROOT_CA" | "BEACONING_DETECTED" | "MALWARE_QUARANTINED";
  process_name: string;
  detail: string | null;
  observed_at: string;
}

export interface TrafficAnalysisRun {
  id: string;
  asset_id: string;
  source_id: string;
  source_name: string;
  coverage: TrafficCoverage;
  connection_count: number;
  dns_count: number;
  tls_count: number;
  edr_count: number;
  alerts_count: number;
  benign_rotations_count: number;
  alerts: SuspiciousTrafficAlert[];
  tls_decisions: TrafficTlsDecision[];
  edr_signals: TrafficEdrSignal[];
  created_at: string;
}

export async function fetchTrafficAnalyses(token: string, assetId: string): Promise<TrafficAnalysisRun[]> {
  const res = await fetch(`${API_BASE_URL}/assets/${encodeURIComponent(assetId)}/traffic-analyses`, {
    headers: authHeaders(token),
    credentials: "include",
    cache: "no-store",
  });
  return parseOrThrow(res, "Falha ao carregar análises de tráfego suspeito.");
}

export interface EvidenceCitation {
  field: string;
  value_excerpt: string;
}

export interface AiTriageSuggestion {
  id: string;
  organization_id: string;
  asset_id: string;
  target_type: "TRAFFIC_ALERT" | "FINDING";
  traffic_alert_id?: string | null;
  finding_id?: string | null;
  generation_mode: "AI_PROVIDER" | "DETERMINISTIC_FALLBACK";
  ai_status: "AVAILABLE" | "UNAVAILABLE" | "UNCONFIGURED" | "INVALID_OUTPUT_FALLBACK";
  model_name: string;
  summary: string;
  explanation: string;
  recommended_action: "INVESTIGATE" | "CONTAIN" | "REMEDIATE" | "VERIFY_CHANGE";
  remediation_steps: string[];
  evidence_citations: EvidenceCitation[];
  sanitized_evidence_hash: string;
  review_status: "PENDING_REVIEW" | "APPROVED" | "REJECTED";
  requires_analyst_review: boolean;
  reviewer_user_id?: string | null;
  reviewer_notes?: string | null;
  reviewed_at?: string | null;
  created_at: string;
}

export interface AiTriageReviewRequest {
  decision: "APPROVED" | "REJECTED";
  reviewer_notes?: string | null;
}

export async function createTrafficAlertTriageSuggestion(
  token: string,
  assetId: string,
  runId: string,
  alertId: string
): Promise<AiTriageSuggestion> {
  const res = await fetch(
    `${API_BASE_URL}/assets/${encodeURIComponent(assetId)}/traffic-analyses/${encodeURIComponent(runId)}/alerts/${encodeURIComponent(alertId)}/triage-suggestion`,
    {
      method: "POST",
      headers: authHeaders(token),
      credentials: "include",
    }
  );
  return parseOrThrow(res, "Falha ao gerar sugestão de triagem para o alerta.");
}

export async function fetchTrafficAlertTriageSuggestion(
  token: string,
  assetId: string,
  runId: string,
  alertId: string
): Promise<AiTriageSuggestion | null> {
  return authedGet<AiTriageSuggestion | null>(
    token,
    `/assets/${encodeURIComponent(assetId)}/traffic-analyses/${encodeURIComponent(runId)}/alerts/${encodeURIComponent(alertId)}/triage-suggestion`,
    "Falha ao consultar sugestão de triagem para o alerta."
  );
}

export async function createFindingTriageSuggestion(
  token: string,
  findingId: string
): Promise<AiTriageSuggestion> {
  const res = await fetch(
    `${API_BASE_URL}/findings/${encodeURIComponent(findingId)}/triage-suggestion`,
    {
      method: "POST",
      headers: authHeaders(token),
      credentials: "include",
    }
  );
  return parseOrThrow(res, "Falha ao gerar sugestão de triagem para a vulnerabilidade.");
}

export async function fetchFindingTriageSuggestion(
  token: string,
  findingId: string
): Promise<AiTriageSuggestion | null> {
  return authedGet<AiTriageSuggestion | null>(
    token,
    `/findings/${encodeURIComponent(findingId)}/triage-suggestion`,
    "Falha ao consultar sugestão de triagem para a vulnerabilidade."
  );
}

export async function reviewTriageSuggestion(
  token: string,
  suggestionId: string,
  payload: AiTriageReviewRequest
): Promise<AiTriageSuggestion> {
  const res = await fetch(
    `${API_BASE_URL}/triage-suggestions/${encodeURIComponent(suggestionId)}/review`,
    {
      method: "PATCH",
      headers: authHeaders(token),
      credentials: "include",
      body: JSON.stringify(payload),
    }
  );
  return parseOrThrow(res, "Falha ao registrar decisão do analista.");
}

// ---------------------------------------------------------------------------
// Fase 6 pós-v1.0: Piloto, prontidão e expansão controlada para clientes
// ---------------------------------------------------------------------------

export type PilotStage = "OWN_ENVIRONMENT" | "AUTHORIZED_CLIENT";
export type PilotStatus = "ACTIVE" | "PAUSED" | "EXPIRED" | "REVOKED";
export type PilotCapability =
  | "TELEMETRY"
  | "TRAFFIC_ANALYSIS"
  | "AVAILABILITY"
  | "SSH_AUDIT"
  | "AI_TRIAGE";
export type PilotReviewDecision = "APPROVED_FOR_EXPANSION" | "NEEDS_ADJUSTMENT";

export interface PilotEnrollment {
  id: string;
  organization_id: string;
  asset_id: string;
  asset_name: string;
  asset_environment: string;
  asset_hostname: string;
  stage: PilotStage;
  status: PilotStatus;
  prerequisite_pilot_id: string | null;
  allowed_cidrs: string[];
  enabled_capabilities: PilotCapability[];
  max_sources: number;
  scope_notes: string | null;
  expires_at: string;
  paused_at: string | null;
  revoked_at: string | null;
  created_by_user_id: string | null;
  created_at: string;
  updated_at: string | null;
  latest_review_decision?: PilotReviewDecision | null;
}

export interface PilotEnrollmentCreateRequest {
  asset_id: string;
  stage: PilotStage;
  prerequisite_pilot_id?: string | null;
  allowed_cidrs: string[];
  enabled_capabilities: PilotCapability[];
  max_sources: number;
  expires_in_days: number;
  scope_notes?: string | null;
}

export interface PilotLifecycleChecklist {
  installation_demonstrated: boolean;
  pause_resume_demonstrated: boolean;
  update_demonstrated: boolean;
  revocation_demonstrated: boolean;
  recovery_demonstrated: boolean;
  all_demonstrated: boolean;
}

export interface PilotCoverage {
  total_sources: number;
  active_sources: number;
  paused_sources: number;
  revoked_sources: number;
  up_to_date_sources: number;
  traffic_runs_count: number;
  observed_layers: string[];
  missing_layers: string[];
  layer_coverage_percent: number;
  ssh_audits_count: number;
  availability_exercises_total: number;
  availability_exercises_passed: number;
}

export interface PilotLatency {
  telemetry_samples_count: number;
  telemetry_avg_delay_seconds: number | null;
  telemetry_max_delay_seconds: number | null;
  availability_alert_pub_avg_ms: number | null;
  availability_alert_pub_max_ms: number | null;
  availability_recovery_pub_avg_ms: number | null;
  availability_recovery_pub_max_ms: number | null;
}

export interface PilotFalsePositives {
  suspicious_alerts_total: number;
  benign_tls_rotations_ignored: number;
  triage_suggestions_total: number;
  triage_approved_count: number;
  triage_rejected_count: number;
  triage_pending_count: number;
  findings_total: number;
  findings_false_positive_count: number;
  findings_false_positive_rate_percent: number;
}

export interface PilotReview {
  id: string;
  pilot_id: string;
  organization_id: string;
  decision: PilotReviewDecision;
  coverage_ok: boolean;
  latency_ok: boolean;
  false_positives_ok: boolean;
  reviewer_user_id: string | null;
  notes: string | null;
  metrics_snapshot: Record<string, unknown>;
  created_at: string;
}

export interface PilotReadiness {
  pilot_id: string;
  asset_id: string;
  stage: PilotStage;
  status: PilotStatus;
  lifecycle: PilotLifecycleChecklist;
  coverage: PilotCoverage;
  latency: PilotLatency;
  false_positives: PilotFalsePositives;
  blocking_reasons: string[];
  ready_for_expansion_approval: boolean;
  latest_review: PilotReview | null;
}

export interface PilotReviewCreateRequest {
  decision: PilotReviewDecision;
  coverage_ok: boolean;
  latency_ok: boolean;
  false_positives_ok: boolean;
  notes?: string | null;
}

export function fetchPilots(token: string): Promise<PilotEnrollment[]> {
  return authedGet(token, "/pilots", "Falha ao carregar habilitações de piloto.");
}

export async function createPilot(
  token: string,
  payload: PilotEnrollmentCreateRequest
): Promise<PilotEnrollment> {
  const res = await fetch(`${API_BASE_URL}/pilots`, {
    method: "POST",
    headers: authHeaders(token),
    credentials: "include",
    body: JSON.stringify(payload),
  });
  return parseOrThrow(res, "Falha ao habilitar piloto controlado.");
}

export async function pausePilot(
  token: string,
  pilotId: string
): Promise<PilotEnrollment> {
  const res = await fetch(`${API_BASE_URL}/pilots/${encodeURIComponent(pilotId)}/pause`, {
    method: "POST",
    headers: authHeaders(token),
    credentials: "include",
  });
  return parseOrThrow(res, "Falha ao pausar o piloto.");
}

export async function resumePilot(
  token: string,
  pilotId: string
): Promise<PilotEnrollment> {
  const res = await fetch(`${API_BASE_URL}/pilots/${encodeURIComponent(pilotId)}/resume`, {
    method: "POST",
    headers: authHeaders(token),
    credentials: "include",
  });
  return parseOrThrow(res, "Falha ao retomar o piloto.");
}

export async function revokePilot(
  token: string,
  pilotId: string
): Promise<PilotEnrollment> {
  const res = await fetch(`${API_BASE_URL}/pilots/${encodeURIComponent(pilotId)}/revoke`, {
    method: "POST",
    headers: authHeaders(token),
    credentials: "include",
  });
  return parseOrThrow(res, "Falha ao revogar o piloto.");
}

export function fetchPilotReadiness(
  token: string,
  pilotId: string
): Promise<PilotReadiness> {
  return authedGet(
    token,
    `/pilots/${encodeURIComponent(pilotId)}/readiness`,
    "Falha ao consultar prontidão do piloto."
  );
}

export async function recordPilotReview(
  token: string,
  pilotId: string,
  payload: PilotReviewCreateRequest
): Promise<PilotReview> {
  const res = await fetch(`${API_BASE_URL}/pilots/${encodeURIComponent(pilotId)}/reviews`, {
    method: "POST",
    headers: authHeaders(token),
    credentials: "include",
    body: JSON.stringify(payload),
  });
  return parseOrThrow(res, "Falha ao registrar revisão do piloto.");
}

export function fetchPilotReviews(
  token: string,
  pilotId: string
): Promise<PilotReview[]> {
  return authedGet(
    token,
    `/pilots/${encodeURIComponent(pilotId)}/reviews`,
    "Falha ao consultar histórico de revisões do piloto."
  );
}

// --- Ferramentas Defensivas SOC (Pentest Assistant, Password, Forensics, Firewall, Malware, WiFi, DDoS) ---

export interface PentestPlanRequest {
  asset_id?: string | null;
  asset_type?: "WEB_APP" | "REST_API" | "GRAPHQL_API" | "DOMAIN";
  environment?: "PRODUCTION" | "STAGING" | "DEVELOPMENT" | "LAB";
  target_label?: string | null;
}

export interface PentestStepItem {
  step_id: string;
  wstg_ref: string;
  title: string;
  objective: string;
  safe_technique: string;
  mapped_checks: string[];
  allowed_in_production: boolean;
  automated_status:
    | "COVERED_PASSED"
    | "COVERED_WITH_FINDINGS"
    | "NOT_YET_RUN"
    | "BLOCKED_IN_PRODUCTION";
  related_findings_count: number;
}

export interface PentestPhase {
  phase_number: number;
  name: string;
  description: string;
  steps: PentestStepItem[];
}

export interface PentestPlanResponse {
  target_name: string;
  asset_type: string;
  environment: string;
  authorization_status: string;
  authorization_warning?: string | null;
  total_steps: number;
  automated_covered_steps: number;
  open_findings_count: number;
  phases: PentestPhase[];
}

export interface PasswordGenerateRequest {
  mode: "RANDOM" | "PASSPHRASE";
  length?: number;
  include_uppercase?: boolean;
  include_lowercase?: boolean;
  include_digits?: boolean;
  include_symbols?: boolean;
  exclude_ambiguous?: boolean;
  word_count?: number;
  separator?: string;
  include_number?: boolean;
}

export interface PasswordGenerateResponse {
  generated: string;
  mode: string;
  length: number;
  entropy_bits: number;
  strength_label: string;
}

export interface PasswordComplianceCheck {
  standard: string;
  passed: boolean;
  detail: string;
}

export interface PasswordAnalyzeResponse {
  length: number;
  score: number;
  classification: "CRITICAL_WEAK" | "WEAK" | "FAIR" | "STRONG" | "VERY_STRONG";
  pool_size: number;
  keyspace_entropy_bits: number;
  shannon_entropy_bits: number;
  crack_time_offline_slow: string;
  crack_time_offline_fast: string;
  detected_patterns: string[];
  compliance_checks: PasswordComplianceCheck[];
  recommendations: string[];
}

export interface ForensicsHashes {
  md5: string;
  sha1: string;
  sha256: string;
  sha512: string;
}

export interface ForensicsAnalyzeResponse {
  artifact_name: string;
  size_bytes: number;
  line_count: number;
  shannon_entropy: number;
  hashes: ForensicsHashes;
  iocs: {
    ipv4_public: string[];
    ipv4_private: string[];
    ipv6: string[];
    domains: string[];
    urls: string[];
    emails: string[];
    hashes: string[];
    cves: string[];
  };
  timeline: {
    events_detected: number;
    first_timestamp?: string | null;
    last_timestamp?: string | null;
    http_status_counts: Record<string, number>;
  };
  jwt_inspection: {
    detected: boolean;
    header?: Record<string, unknown> | null;
    payload_sanitized?: Record<string, unknown> | null;
    warnings: string[];
  };
  secret_leak_warnings: string[];
  summary: string;
}

export interface FirewallTestPacket {
  protocol: "TCP" | "UDP" | "ICMP";
  source_ip: string;
  destination_port: number;
}

export interface FirewallAnalyzeResponse {
  total_rules_parsed: number;
  unparsed_lines: number[];
  posture_score: number;
  has_default_deny: boolean;
  parsed_rules: Array<{
    line_number: number;
    raw: string;
    action: "ALLOW" | "DENY";
    protocol: string;
    source_cidr: string;
    port_spec: string;
  }>;
  findings: Array<{
    severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
    line_number?: number | null;
    title: string;
    description: string;
    cwe_id: string;
    remediation: string;
  }>;
  simulation?: {
    verdict: "ALLOW" | "DENY" | "DEFAULT_IMPLICIT";
    matched_line?: number | null;
    matched_rule?: string | null;
    explanation: string;
  } | null;
}

export interface MalwareAnalyzeResponse {
  filename: string;
  size_bytes: number;
  file_type_guess: string;
  hashes: ForensicsHashes;
  shannon_entropy: number;
  high_entropy_warning: boolean;
  risk_score: number;
  verdict: "CLEAN_NO_INDICATORS" | "SUSPICIOUS" | "HIGH_RISK_MALICIOUS_INDICATORS";
  signature_hits: Array<{
    rule_id: string;
    name: string;
    severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
    mitre_attack: string;
    matched_excerpt: string;
    description: string;
  }>;
  deobfuscated_previews: Array<{
    encoding: string;
    decoded_preview: string;
  }>;
  extracted_urls: string[];
  extracted_ips: string[];
  containment_recommendations: string[];
}

export interface WifiConnectedInterface {
  interface_name?: string | null;
  adapter_description?: string | null;
  state?: string | null;
  ssid?: string | null;
  bssid?: string | null;
  radio_type?: string | null;
  authentication?: string | null;
  encryption?: string | null;
  channel?: number | null;
  signal_percent?: number | null;
  receive_rate_mbps?: string | null;
  transmit_rate_mbps?: string | null;
}

export interface WifiNetworkInput {
  ssid: string;
  bssid?: string | null;
  authentication: string;
  encryption?: string;
  radio_type?: string | null;
  channel?: number | null;
  signal_percent?: number | null;
  wps_enabled?: boolean;
  pmf_enabled?: boolean | null;
}

export interface WifiAnalyzeResponse {
  total_networks: number;
  overall_score: number;
  evil_twin_suspected: boolean;
  connected_interface?: WifiConnectedInterface | null;
  assessments: Array<{
    ssid: string;
    bssid?: string | null;
    security_grade: "A" | "B" | "C" | "D" | "F";
    authentication: string;
    encryption: string;
    radio_type?: string | null;
    band?: string | null;
    channel?: number | null;
    signal_percent?: number | null;
    issues_count: number;
  }>;
  findings: Array<{
    severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
    ssid: string;
    bssid?: string | null;
    title: string;
    description: string;
    cwe_id: string;
    remediation: string;
  }>;
  hardening_checklist: string[];
}

export interface WifiLocalScanResponse {
  available: boolean;
  source: string;
  detail: string;
  captured_at?: string | null;
  raw_scan_output?: string | null;
  connected_interface_output?: string | null;
  audit?: WifiAnalyzeResponse | null;
}

export interface HostWifiBridgeScanResponse {
  available: boolean;
  host_os?: string;
  tool?: string;
  captured_at?: string | null;
  raw_scan_output?: string | null;
  connected_interface_output?: string | null;
  error?: string;
}

export interface DdosPostureConfig {
  has_cdn_waf: boolean;
  has_rate_limiting: boolean;
  has_syn_cookies: boolean;
  has_upstream_timeouts: boolean;
  has_autoscaling_or_anycast: boolean;
}

export interface DdosAnalyzeResponse {
  total_requests_parsed: number;
  unique_ips: number;
  peak_rps: number;
  error_5xx_429_rate_percent: number;
  resilience_score: number;
  risk_level: "LOW" | "MODERATE" | "HIGH" | "CRITICAL";
  top_ips: Array<{
    ip: string;
    request_count: number;
    share_percent: number;
    error_rate_percent: number;
  }>;
  top_paths: Array<{
    path: string;
    count: number;
    unique_query_variants: number;
  }>;
  anomalies: Array<{
    severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
    anomaly_type: string;
    title: string;
    description: string;
    evidence: string;
  }>;
  asset_module_f_context: string[];
  mitigation_snippets: Array<{
    platform: string;
    title: string;
    code: string;
  }>;
}

async function postSecurityTool<TReq, TRes>(
  path: string,
  payload: TReq,
  fallbackMsg: string,
  token?: string | null
): Promise<TRes> {
  const res = await fetch(`${API_BASE_URL}/security-tools${path}`, {
    method: "POST",
    headers: authHeaders(token),
    credentials: "include",
    body: JSON.stringify(payload),
  });
  return parseOrThrow(res, fallbackMsg);
}

export function fetchPentestPlan(
  payload: PentestPlanRequest,
  token?: string | null
): Promise<PentestPlanResponse> {
  return postSecurityTool(
    "/pentest-assistant/plan",
    payload,
    "Falha ao gerar plano de pentest guiado.",
    token
  );
}

export function generatePasswordTool(
  payload: PasswordGenerateRequest,
  token?: string | null
): Promise<PasswordGenerateResponse> {
  return postSecurityTool(
    "/password/generate",
    payload,
    "Falha ao gerar senha segura.",
    token
  );
}

export function analyzePasswordTool(
  password: string,
  token?: string | null
): Promise<PasswordAnalyzeResponse> {
  return postSecurityTool(
    "/password/analyze",
    { password },
    "Falha ao analisar força da senha.",
    token
  );
}

export function analyzeForensicsTool(
  payload: { content: string; artifact_name?: string | null; defang_iocs?: boolean },
  token?: string | null
): Promise<ForensicsAnalyzeResponse> {
  return postSecurityTool(
    "/forensics/analyze",
    payload,
    "Falha ao executar análise forense do artefato.",
    token
  );
}

export function analyzeFirewallTool(
  payload: { rules_text: string; test_packet?: FirewallTestPacket | null },
  token?: string | null
): Promise<FirewallAnalyzeResponse> {
  return postSecurityTool(
    "/firewall/test",
    payload,
    "Falha ao auditar regras de firewall.",
    token
  );
}

export function analyzeMalwareTool(
  payload: { payload: string; filename?: string | null; input_encoding?: "TEXT" | "BASE64" | "HEX" },
  token?: string | null
): Promise<MalwareAnalyzeResponse> {
  return postSecurityTool(
    "/malware/analyze",
    payload,
    "Falha na inspeção estática do payload.",
    token
  );
}

export function analyzeWifiTool(
  payload: {
    raw_scan_output?: string | null;
    connected_interface_output?: string | null;
    networks?: WifiNetworkInput[];
  },
  token?: string | null
): Promise<WifiAnalyzeResponse> {
  return postSecurityTool(
    "/wifi/audit",
    payload,
    "Falha na auditoria passiva de redes Wi-Fi.",
    token
  );
}

export function scanLocalWifiTool(
  token?: string | null
): Promise<WifiLocalScanResponse> {
  return postSecurityTool(
    "/wifi/scan-local",
    {},
    "Falha ao consultar placa Wi-Fi local.",
    token
  );
}

export async function fetchHostWifiBridgeScan(
  sensorUrl = "http://127.0.0.1:8765/scan"
): Promise<HostWifiBridgeScanResponse> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 5000);
  try {
    const res = await fetch(sensorUrl, {
      method: "GET",
      cache: "no-store",
      signal: controller.signal,
    });
    const data = (await res.json()) as HostWifiBridgeScanResponse;
    if (!res.ok) {
      return {
        available: false,
        error: data?.error || `Sensor local respondeu HTTP ${res.status}.`,
      };
    }
    return data;
  } catch (err) {
    return {
      available: false,
      error:
        err instanceof Error
          ? err.message
          : "Sensor local 127.0.0.1:8765 indisponível.",
    };
  } finally {
    clearTimeout(timeoutId);
  }
}

export function analyzeDdosTool(
  payload: { access_logs?: string | null; posture: DdosPostureConfig; asset_id?: string | null },
  token?: string | null
): Promise<DdosAnalyzeResponse> {
  return postSecurityTool(
    "/ddos/analyze",
    payload,
    "Falha ao analisar telemetria e postura anti-DDoS.",
    token
  );
}


export async function fetchCurrentSession(): Promise<AuthSessionResponse | null> {
  try {
    const res = await fetch(`${API_BASE_URL}/auth/me`, {
      method: "GET",
      headers: authHeaders(),
      credentials: "include",
      cache: "no-store",
    });
    if (!res.ok) {
      return null;
    }
    const data: unknown = await res.json();
    if (
      data &&
      typeof data === "object" &&
      "access_token" in data &&
      typeof (data as AuthSessionResponse).access_token === "string" &&
      "user" in data &&
      Boolean((data as AuthSessionResponse).user) &&
      "active_organization" in data &&
      Boolean((data as AuthSessionResponse).active_organization)
    ) {
      return data as AuthSessionResponse;
    }
    return null;
  } catch {
    return null;
  }
}
