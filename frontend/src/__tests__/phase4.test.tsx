import React from "react";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  buildQueryString,
  type FindingResponse,
  parseSseBuffer,
  type PlatformMetricsSummary,
  type ScanResponse,
  streamScanProgress,
} from "@/lib/api";
import {
  canManageScans,
  canTriage,
  riskLevel,
  RISK_METHODOLOGY,
} from "@/lib/soc-utils";
import {
  buildKpis,
  DashboardPanel,
  scanStatusChartData,
} from "@/components/dashboard-panel";
import {
  EMPTY_FINDING_FILTERS,
  FINDINGS_PAGE_SIZE,
  toApiFilters,
  validateTriage,
  VulnerabilitiesPanel,
} from "@/components/vulnerabilities-panel";
import { filterAssets } from "@/components/assets-directory";
import {
  countFindings,
  ScansHistoryPanel,
  scansPollInterval,
} from "@/components/scans-history-panel";

const metrics: PlatformMetricsSummary = {
  total_organizations: 1,
  total_assets: 3,
  verified_assets: 2,
  total_scans_executed: 5,
  scans_in_progress: 1,
  open_vulnerabilities: 7,
  critical_vulnerabilities: 1,
  high_vulnerabilities: 2,
  medium_vulnerabilities: 3,
  low_vulnerabilities: 1,
  info_vulnerabilities: 0,
  treatment_status_counts: { OPEN: 7, MITIGATED: 2 },
  top_risky_assets: [
    {
      id: "a1",
      name: "Portal Lab",
      target_url: "http://lab.local",
      environment: "LAB",
      asset_type: "WEB_APP",
      authorization_status: "VERIFIED",
      risk_score: 80,
      open_findings_count: 5,
      critical_count: 1,
      high_count: 2,
      last_scan_at: "2026-01-02T10:00:00Z",
    },
  ],
  owasp_category_distribution: [],
  cwe_distribution: [],
  recent_scans: [],
  average_scan_duration_seconds: 12,
  scan_status_counts: { COMPLETED: 3, FAILED: 1, ABORTED_TARGET_DEGRADED: 1 },
  resolved_vulnerabilities: 2,
};

function makeFinding(over: Partial<FindingResponse> = {}): FindingResponse {
  return {
    id: "f1",
    organization_id: "o1",
    asset_id: "a1",
    asset_name: "Portal Lab",
    scan_id: "s1",
    fingerprint: "fp1",
    module_id: "http_headers",
    check_id: "CHK-A03",
    title: "Content-Security-Policy ausente",
    description: "Cabeçalho CSP não encontrado.",
    category: "Security Headers",
    result_classification: "VULNERABILITY",
    severity: "MEDIUM",
    confidence: "CERTAIN",
    cwe_ids: ["CWE-693"],
    owasp_categories: ["A05:2021"],
    affected_endpoint: "http://lab.local/",
    evidence: {
      request_method: "GET",
      request_url: "http://lab.local/",
      response_status_code: 200,
      response_headers: { Server: "Apache", Authorization: "***REDACTED***" },
      observed_value: "<script>alert(1)</script>",
      technical_notes: ["nota"],
      redacted_fields_count: 1,
    },
    impact: "Maior superfície de XSS.",
    reproduction_steps: ["Requisitar a página e inspecionar cabeçalhos."],
    remediation_data: {
      remediation_id: "R1",
      version: "1",
      what_was_identified: "x",
      why_it_is_dangerous: "y",
      how_it_was_detected: "Inspeção de cabeçalhos.",
      how_to_fix: "Adicionar CSP restritiva.",
      secure_examples: [],
      how_to_validate: "Reexecutar a auditoria.",
      references: [],
    },
    treatment_status: "OPEN",
    first_detected_at: "2026-01-01T10:00:00Z",
    last_confirmed_at: "2026-01-02T10:00:00Z",
    ...over,
  };
}

function wrap(ui: React.ReactElement) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0 } },
  });
  return render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>);
}

function jsonResponse(body: unknown, status = 200) {
  return Promise.resolve({
    ok: status < 400,
    status,
    json: () => Promise.resolve(body),
  });
}

describe("Fase 4 — utilitários puros (TM-016)", () => {
  it("serializa filtros ignorando vazios e interpreta SSE em blocos parciais", () => {
    expect(buildQueryString({ a: "x", b: "", c: undefined, d: 0, e: false })).toBe(
      "?a=x&d=0&e=false"
    );
    expect(buildQueryString({})).toBe("");
    const first = parseSseBuffer('event: progress\ndata: {"a":1}\n\nevent: en');
    expect(first.messages).toEqual([{ event: "progress", data: '{"a":1}' }]);
    const second = parseSseBuffer(first.rest + 'd\ndata: {}\n\n: heartbeat\n\n');
    expect(second.messages).toEqual([{ event: "end", data: "{}" }]);
  });

  it("monta filtros de API com paginação no servidor e valida triagem", () => {
    const api = toApiFilters(
      { ...EMPTY_FINDING_FILTERS, severity: "HIGH", search: " csp ", date_from: "2026-01-01" },
      3
    );
    expect(api.severity).toBe("HIGH");
    expect(api.search).toBe("csp");
    expect(api.limit).toBe(FINDINGS_PAGE_SIZE);
    expect(api.offset).toBe(2 * FINDINGS_PAGE_SIZE);
    expect(api.date_from).toBeTruthy();
    expect(validateTriage("FALSE_POSITIVE", "")).toMatch(/justificativa/i);
    expect(validateTriage("FALSE_POSITIVE", "confirmado manualmente")).toBeNull();
    expect(validateTriage("MITIGATED", "")).toBeNull();
    expect(validateTriage("INVALIDO", "x")).toMatch(/estado/i);
  });

  it("deriva indicadores e gráficos dos dados persistidos", () => {
    const k = Object.fromEntries(buildKpis(metrics).map((i) => [i.key, i.value]));
    expect(k).toMatchObject({
      assets: 3, scans: 5, running: 1, completed: 3, failed: 2,
      critical: 1, high: 2, medium: 3, low: 1, open: 7, resolved: 2,
    });
    expect(scanStatusChartData(metrics)).toHaveLength(3);
    expect(riskLevel(80).variant).toBe("critical");
    expect(riskLevel(0).label).toMatch(/Sem pendências/);
    expect(RISK_METHODOLOGY).toMatch(/Não equivale a CVSS/);
  });

  it("aplica RBAC de interface, polling adaptativo e filtros de ativos", () => {
    expect(canTriage("VIEWER")).toBe(false);
    expect(canTriage("DEVELOPER")).toBe(true);
    expect(canManageScans("DEVELOPER")).toBe(false);
    expect(canManageScans("SECURITY_ANALYST")).toBe(true);
    const scan = (status: string) => ({ status }) as ScanResponse;
    expect(scansPollInterval([scan("COMPLETED")])).toBe(false);
    expect(scansPollInterval([scan("RUNNING")])).toBeGreaterThan(0);
    expect(scansPollInterval(undefined)).toBe(false);
    expect(countFindings({ HIGH: 2, LOW: 1 })).toBe(3);
    const assets = [
      { name: "Portal", target_url: "http://a", hostname: "a", owner_name: "X", tags: ["fin"], environment: "LAB", authorization_status: "VERIFIED" },
      { name: "API", target_url: "http://b", hostname: "b", owner_name: "Y", tags: [], environment: "PRODUCTION", authorization_status: "PENDING" },
    ] as never[];
    expect(filterAssets(assets, { search: "fin", environment: "", authorization: "" })).toHaveLength(1);
    expect(filterAssets(assets, { search: "", environment: "PRODUCTION", authorization: "" })).toHaveLength(1);
    expect(filterAssets(assets, { search: "", environment: "LAB", authorization: "PENDING" })).toHaveLength(0);
  });

  it("consome o fluxo SSE real e encerra no evento final", async () => {
    const enc = new TextEncoder();
    const chunks = [
      'event: progress\ndata: {"scan_id":"s1","status":"RUNNING","progress_percent":40}\n\nevent: pro',
      'gress\ndata: {"scan_id":"s1","status":"COMPLETED","progress_percent":100}\n\nevent: end\ndata: {}\n\n',
    ];
    let i = 0;
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      body: {
        getReader: () => ({
          read: () =>
            Promise.resolve(
              i < chunks.length
                ? { done: false, value: enc.encode(chunks[i++]) }
                : { done: true, value: undefined }
            ),
        }),
      },
    }) as never;
    const seen: number[] = [];
    const outcome = await streamScanProgress(
      "tok",
      "s1",
      (p) => seen.push(p.progress_percent),
      new AbortController().signal
    );
    expect(outcome).toBe("ended");
    expect(seen).toEqual([40, 100]);
    const call = (global.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(call[0]).toMatch(/\/scans\/s1\/stream$/);
    expect(call[1].headers.Authorization).toBe("Bearer tok");
  });

  it("falha quando o fluxo SSE recusa a conexão (ex.: limite de conexões)", async () => {
    global.fetch = vi.fn().mockResolvedValue({ ok: false, status: 429, body: null }) as never;
    await expect(
      streamScanProgress("tok", "s1", () => undefined, new AbortController().signal)
    ).rejects.toMatchObject({ status: 429 });
  });
});

describe("Fase 4 — painéis (TM-016)", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("dashboard exibe KPIs reais, ativos de maior risco e metodologia", async () => {
    global.fetch = vi.fn().mockImplementation((url: string) => {
      if (url.includes("/dashboard/summary")) return jsonResponse(metrics);
      if (url.includes("/dashboard/trends"))
        return jsonResponse({ days: 30, points: [{ date: "2026-01-01", detected: 2, resolved: 1, scans: 1 }] });
      return jsonResponse({}, 404);
    }) as never;
    wrap(<DashboardPanel token="t" onViewAssetFindings={vi.fn()} onViewAsset={vi.fn()} onOpenScan={vi.fn()} />);
    expect(await screen.findByTestId("kpi-open")).toHaveTextContent("7");
    expect(screen.getByTestId("kpi-failed")).toHaveTextContent("2");
    expect(screen.getByText("Portal Lab")).toBeInTheDocument();
    expect(screen.getByText(/80\/100/)).toBeInTheDocument();
    expect(screen.getByTestId("risk-methodology")).toHaveTextContent(/não equivale a CVSS/i);
  });

  it("dashboard trata estado vazio e erro de permissão", async () => {
    const empty = { ...metrics, total_scans_executed: 0, open_vulnerabilities: 0, top_risky_assets: [], scan_status_counts: {}, resolved_vulnerabilities: 0, scans_in_progress: 0 };
    global.fetch = vi.fn().mockImplementation((url: string) =>
      url.includes("/dashboard/summary") ? jsonResponse(empty) : jsonResponse({ days: 30, points: [] })
    ) as never;
    const { unmount } = wrap(<DashboardPanel token="t" onViewAssetFindings={vi.fn()} onViewAsset={vi.fn()} onOpenScan={vi.fn()} />);
    expect(await screen.findByText(/não comprova a inexistência/i)).toBeInTheDocument();
    expect(screen.getByText(/Nenhum ativo cadastrado/i)).toBeInTheDocument();
    unmount();

    global.fetch = vi.fn().mockImplementation(() => jsonResponse({ detail: "negado" }, 403)) as never;
    wrap(<DashboardPanel token="t" onViewAssetFindings={vi.fn()} onViewAsset={vi.fn()} onOpenScan={vi.fn()} />);
    expect(await screen.findByRole("alert")).toHaveTextContent(/permissão/i);
  });

  it("vulnerabilidades: lista, filtra no servidor, pagina e mostra evidência escapada", async () => {
    const urls: string[] = [];
    global.fetch = vi.fn().mockImplementation((url: string) => {
      urls.push(url);
      if (url.includes("/findings/page")) {
        return jsonResponse({ items: [makeFinding()], total: 31, limit: 15, offset: 0 });
      }
      if (url.includes("/history")) return jsonResponse({ finding_id: "f1", detections: [], triage_events: [] });
      if (url.includes("/findings/f1")) return jsonResponse(makeFinding());
      return jsonResponse({}, 404);
    }) as never;
    wrap(<VulnerabilitiesPanel token="t" role="VIEWER" assets={[]} />);
    expect(await screen.findByText("Content-Security-Policy ausente")).toBeInTheDocument();
    expect(screen.getByTestId("findings-total")).toHaveTextContent("31 resultado(s) · página 1 de 3");

    fireEvent.change(screen.getByLabelText("Filtrar por severidade"), { target: { value: "HIGH" } });
    await waitFor(() => expect(urls.some((u) => u.includes("severity=HIGH") && u.includes("offset=0"))).toBe(true));

    fireEvent.click(screen.getByRole("button", { name: "Próxima" }));
    await waitFor(() => expect(urls.some((u) => u.includes("offset=15"))).toBe(true));

    fireEvent.click(screen.getByRole("button", { name: /Ver detalhes de/ }));
    const evidence = await screen.findByTestId("evidence-view");
    // Conteúdo potencialmente malicioso aparece como texto, sem criar elementos HTML.
    expect(within(evidence).getByText("<script>alert(1)</script>")).toBeInTheDocument();
    expect(evidence.querySelector("script")).toBeNull();
    expect(screen.getByText(/mascarado/)).toBeInTheDocument();
    expect(screen.getByText(/somente leitura/i)).toBeInTheDocument();
    expect(screen.queryByLabelText("Estado de triagem")).toBeNull();
  });

  it("vulnerabilidades: estado vazio orientativo", async () => {
    global.fetch = vi.fn().mockImplementation(() =>
      jsonResponse({ items: [], total: 0, limit: 15, offset: 0 })
    ) as never;
    wrap(<VulnerabilitiesPanel token="t" role="ADMIN" assets={[]} />);
    expect(await screen.findByTestId("findings-empty")).toHaveTextContent(/não comprova/i);
  });

  it("triagem: valida justificativa e persiste via PATCH para perfil autorizado", async () => {
    const patches: { url: string; body: string }[] = [];
    global.fetch = vi.fn().mockImplementation((url: string, init?: { method?: string; body?: string }) => {
      if (init?.method === "PATCH") {
        patches.push({ url, body: init.body ?? "" });
        return jsonResponse(makeFinding({ treatment_status: "FALSE_POSITIVE", triage_note: "Confirmado" }));
      }
      if (url.includes("/findings/page")) return jsonResponse({ items: [makeFinding()], total: 1, limit: 15, offset: 0 });
      if (url.includes("/history")) return jsonResponse({ finding_id: "f1", detections: [], triage_events: [] });
      return jsonResponse(makeFinding());
    }) as never;
    wrap(<VulnerabilitiesPanel token="t" role="DEVELOPER" assets={[]} />);
    fireEvent.click(await screen.findByRole("button", { name: /Ver detalhes de/ }));
    const select = await screen.findByLabelText("Estado de triagem");
    fireEvent.change(select, { target: { value: "FALSE_POSITIVE" } });
    fireEvent.click(screen.getByRole("button", { name: "Registrar triagem" }));
    expect(await screen.findByText(/Informe uma justificativa/)).toBeInTheDocument();
    expect(patches).toHaveLength(0);

    fireEvent.change(screen.getByLabelText("Justificativa da triagem"), { target: { value: "Confirmado como FP" } });
    fireEvent.click(screen.getByRole("button", { name: "Registrar triagem" }));
    await waitFor(() => expect(patches).toHaveLength(1));
    expect(patches[0].url).toMatch(/\/findings\/f1\/status$/);
    expect(JSON.parse(patches[0].body)).toEqual({ treatment_status: "FALSE_POSITIVE", triage_note: "Confirmado como FP" });
    expect(await screen.findByText(/Triagem registrada com sucesso/)).toBeInTheDocument();
  });

  it("auditorias: lista paginada, cancelamento apenas para perfis autorizados", async () => {
    const scan = {
      id: "abcdef12-0000", organization_id: "o1", asset_id: "a1", asset_name: "Portal Lab",
      profile_type: "QUICK", status: "RUNNING", progress_percent: 40, enabled_modules: [],
      completed_modules: [], failed_modules: [], policy_snapshot: {}, total_checks_run: 3,
      findings_summary: { HIGH: 1, LOW: 2 }, elapsed_seconds: 5, created_at: "2026-01-01T10:00:00Z",
    };
    global.fetch = vi.fn().mockImplementation(() =>
      jsonResponse({ items: [scan], total: 12, limit: 10, offset: 0 })
    ) as never;
    const onCancel = vi.fn();
    const { unmount } = wrap(
      <ScansHistoryPanel token="t" role="SECURITY_ANALYST" assets={[]} selectedScanId={null} onSelect={vi.fn()} onCancel={onCancel} />
    );
    expect(await screen.findByText("abcdef12")).toBeInTheDocument();
    expect(screen.getByTestId("scans-total")).toHaveTextContent("12 auditoria(s) · página 1 de 2");
    fireEvent.click(screen.getByRole("button", { name: "Cancelar" }));
    expect(onCancel).toHaveBeenCalledWith("abcdef12-0000");
    unmount();

    wrap(<ScansHistoryPanel token="t" role="VIEWER" assets={[]} selectedScanId={null} onSelect={vi.fn()} onCancel={onCancel} />);
    await screen.findByText("abcdef12");
    expect(screen.queryByRole("button", { name: "Cancelar" })).toBeNull();
  });
});
