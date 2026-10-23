import React from "react";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  type AssetResponse,
  type ReportResponse,
  type ScanComparisonResponse,
  type ScanResponse,
} from "@/lib/api";
import { ReportsPanel } from "@/components/reports-panel";
import { ScanComparisonModal } from "@/components/scan-comparison-modal";
import { ScansHistoryPanel } from "@/components/scans-history-panel";
import { VulnerabilitiesPanel, validateTriage } from "@/components/vulnerabilities-panel";

function createTestQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: 0 },
    },
  });
}

function renderWithClient(ui: React.ReactElement) {
  const qc = createTestQueryClient();
  return render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>);
}

const mockAsset: AssetResponse = {
  id: "asset-123",
  organization_id: "org-1",
  name: "API Pagamentos Homolog",
  hostname: "10.0.0.5",
  target_url: "http://10.0.0.5:8000",
  asset_type: "REST_API",
  environment: "STAGING",
  owner_name: "AppSec Team",
  owner_email: "appsec@secops.local",
  risk_score: 45,
  authorization_status: "VERIFIED",
  created_at: "2026-10-20T10:00:00Z",
  updated_at: "2026-10-20T10:00:00Z",
  tags: ["api", "pagamentos"],
  excluded_paths: [],
};

const mockScanA: ScanResponse = {
  id: "scan-aaaa-1111",
  organization_id: "org-1",
  asset_id: "asset-123",
  asset_name: "API Pagamentos Homolog",
  profile_type: "FULL",
  status: "COMPLETED",
  progress_percent: 100,
  enabled_modules: ["cors_misconfiguration", "tls_ssl_checker"],
  completed_modules: ["cors_misconfiguration", "tls_ssl_checker"],
  failed_modules: [],
  policy_snapshot: {},
  total_checks_run: 6,
  findings_summary: { HIGH: 1, MEDIUM: 1 },
  error_message: null,
  created_at: "2026-10-21T09:00:00Z",
  started_at: "2026-10-21T09:00:01Z",
  completed_at: "2026-10-21T09:01:00Z",
  elapsed_seconds: 59,
};

const mockScanB: ScanResponse = {
  id: "scan-bbbb-2222",
  organization_id: "org-1",
  asset_id: "asset-123",
  asset_name: "API Pagamentos Homolog",
  profile_type: "FULL",
  status: "COMPLETED",
  progress_percent: 100,
  enabled_modules: ["cors_misconfiguration", "tls_ssl_checker"],
  completed_modules: ["cors_misconfiguration", "tls_ssl_checker"],
  failed_modules: [],
  policy_snapshot: {},
  total_checks_run: 6,
  findings_summary: { HIGH: 1 },
  error_message: null,
  created_at: "2026-10-22T09:00:00Z",
  started_at: "2026-10-22T09:00:01Z",
  completed_at: "2026-10-22T09:01:05Z",
  elapsed_seconds: 64,
};

const mockReport: ReportResponse = {
  id: "rep-001",
  organization_id: "org-1",
  report_type: "EXECUTIVE",
  format: "PDF",
  title: "Relatório Executivo de Segurança Q4",
  asset_id: "asset-123",
  asset_name: "API Pagamentos Homolog",
  scan_id: "scan-aaaa-1111",
  status: "COMPLETED",
  filter_params: {},
  summary_data: {},
  file_size_bytes: 45200,
  created_by_user_id: "user-admin",
  created_at: "2026-10-22T10:00:00Z",
  completed_at: "2026-10-22T10:00:05Z",
  error_message: null,
  download_url: "/api/v1/reports/rep-001/download",
};

describe("Fase 6 — Relatórios, Comparação e Gestão de Correções (TM-018)", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  describe("Validação de Triagem e Justificativas de Risco (validateTriage)", () => {
    it("exige justificativa formal para aceitação de risco (ACCEPTED_RISK)", () => {
      const errEmpty = validateTriage("ACCEPTED_RISK", "");
      expect(errEmpty).toMatch(/justificativa formal/i);

      const errTooShort = validateTriage("ACCEPTED_RISK", "ok", "ok");
      expect(errTooShort).toMatch(/mínimo de 5 caracteres/i);

      const validWithReason = validateTriage(
        "ACCEPTED_RISK",
        "",
        "Risco operacional aceito pelo CISO com controle compensatório de WAF ativo."
      );
      expect(validWithReason).toBeNull();
    });

    it("mantém validação rigorosa de falsos positivos", () => {
      expect(validateTriage("FALSE_POSITIVE", "")).toMatch(/justificativa/i);
      expect(validateTriage("FALSE_POSITIVE", "confirmado em lab")).toBeNull();
    });

    it("permite transições padrão de fluxo sem nota obrigatória", () => {
      expect(validateTriage("IN_PROGRESS", "")).toBeNull();
      expect(validateTriage("WAITING_VALIDATION", "")).toBeNull();
      expect(validateTriage("RESOLVED_VERIFIED", "")).toBeNull();
      expect(validateTriage("REOPENED", "")).toBeNull();
    });
  });

  describe("Painel de Relatórios (ReportsPanel)", () => {
    it("exibe lista de relatórios existentes com metadados e botão de novo relatório", async () => {
      vi.spyOn(global, "fetch").mockImplementation(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes("/reports")) {
          return new Response(
            JSON.stringify({
              items: [mockReport],
              total: 1,
              limit: 10,
              offset: 0,
            }),
            { status: 200, headers: { "Content-Type": "application/json" } }
          );
        }
        return new Response("Not found", { status: 404 });
      });

      renderWithClient(
        <ReportsPanel
          token="test-token"
          role="ADMIN"
          assets={[mockAsset]}
          scans={[mockScanA, mockScanB]}
        />
      );

      expect(await screen.findByText("Central de Relatórios & Exportações")).toBeInTheDocument();
      expect(await screen.findByText("Relatório Executivo de Segurança Q4")).toBeInTheDocument();
      expect(screen.getAllByText("PDF").length).toBeGreaterThanOrEqual(1);
      expect(screen.getByText("EXECUTIVE")).toBeInTheDocument();
      expect(screen.getByRole("button", { name: /Novo Relatório/i })).toBeInTheDocument();
    });

    it("abre formulário de criação ao clicar em Novo Relatório", async () => {
      vi.spyOn(global, "fetch").mockImplementation(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes("/reports")) {
          return new Response(
            JSON.stringify({
              items: [],
              total: 0,
              limit: 10,
              offset: 0,
            }),
            { status: 200, headers: { "Content-Type": "application/json" } }
          );
        }
        return new Response("Not found", { status: 404 });
      });

      renderWithClient(
        <ReportsPanel
          token="test-token"
          role="ADMIN"
          assets={[mockAsset]}
          scans={[mockScanA, mockScanB]}
        />
      );

      const generateBtn = await screen.findByRole("button", { name: /Novo Relatório/i });
      fireEvent.click(generateBtn);

      expect(await screen.findByText("Configurar Novo Relatório de Segurança")).toBeInTheDocument();
      expect(screen.getByText("Tipo de Relatório")).toBeInTheDocument();
      expect(screen.getByText("Formato de Exportação")).toBeInTheDocument();
      expect(screen.getByText("Título Personalizado (Opcional)")).toBeInTheDocument();
    });
  });

  describe("Modal de Comparação de Auditorias (ScanComparisonModal)", () => {
    it("carrega e renderiza o comparativo com métricas de novidades, correções e persistência", async () => {
      const mockComparison: ScanComparisonResponse = {
        scan_a: mockScanA,
        scan_b: mockScanB,
        asset_id: "asset-123",
        asset_name: "API Pagamentos Homolog",
        total_findings_a: 2,
        total_findings_b: 1,
        new_findings: [],
        persistent_findings: [
          {
            id: "find-persist-1",
            organization_id: "org-1",
            asset_id: "asset-123",
            scan_id: "scan-bbbb-2222",
            module_id: "cors_misconfiguration",
            check_id: "cors_wildcard",
            title: "CORS com Origem Irrestrita (*)",
            description: "Cabeçalho Access-Control-Allow-Origin configurado incorretamente.",
            affected_endpoint: "http://10.0.0.5:8000/api/v1/auth",
            severity: "HIGH",
            result_classification: "VULNERABILITY",
            treatment_status: "OPEN",
            confidence: "CERTAIN",
            cwe_ids: ["CWE-942"],
            owasp_categories: ["A01:2021-Broken Access Control"],
            cvss_v4_score: 7.1,
            cvss_v4_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
            remediation_data: {
              how_it_was_detected: "Teste CORS real",
              how_to_fix: "Restringir origens permitidas",
              how_to_validate: "Repetir request com header Origin",
              references: [],
            } as any,
            reproduction_steps: [],
            evidence: {
              request_url: "http://10.0.0.5:8000/api/v1/auth",
            },
            created_at: "2026-10-22T09:00:30Z",
          },
        ],
        confirmed_remediated: [
          {
            id: "find-resolved-1",
            organization_id: "org-1",
            asset_id: "asset-123",
            scan_id: "scan-aaaa-1111",
            module_id: "tls_ssl_checker",
            check_id: "weak_ciphers",
            title: "Ciphers TLS Obsoletos Habilitados",
            description: "Suporte a ciphers fracos.",
            affected_endpoint: "https://10.0.0.5:8000",
            severity: "MEDIUM",
            result_classification: "VULNERABILITY",
            treatment_status: "RESOLVED_VERIFIED",
            confidence: "CERTAIN",
            cwe_ids: ["CWE-327"],
            owasp_categories: ["A02:2021-Cryptographic Failures"],
            cvss_v4_score: 5.3,
            cvss_v4_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
            remediation_data: {
              how_it_was_detected: "Handshake TLS real",
              how_to_fix: "Desabilitar ciphers fracos",
              how_to_validate: "Repetir teste SSL",
              references: [],
            } as any,
            reproduction_steps: [],
            evidence: {},
            created_at: "2026-10-21T09:00:30Z",
          },
        ],
        not_detected_again: [],
        not_verified_coverage: [],
        reopened_findings: [],
        severity_changes: [],
        coverage_diff: {
          modules_a: ["cors_misconfiguration", "tls_ssl_checker"],
          modules_b: ["cors_misconfiguration", "tls_ssl_checker"],
          modules_only_a: [],
          modules_only_b: [],
          common_modules: ["cors_misconfiguration", "tls_ssl_checker"],
          coverage_parity: true,
        },
        comparison_summary: {},
      } as any;

      vi.spyOn(global, "fetch").mockImplementation(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes("/compare")) {
          return new Response(JSON.stringify(mockComparison), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        }
        return new Response("Not found", { status: 404 });
      });

      const handleClose = vi.fn();
      renderWithClient(
        <ScanComparisonModal
          token="test-token"
          scanIdA="scan-aaaa-1111"
          scanIdB="scan-bbbb-2222"
          onClose={handleClose}
        />
      );

      expect(
        await screen.findByText(/Comparativo de Auditorias — API Pagamentos Homolog/)
      ).toBeInTheDocument();

      // Verifica KPI de Correções Validadas e Persistentes
      expect(screen.getAllByText(/Correções Validadas/).length).toBeGreaterThanOrEqual(1);
      expect(screen.getAllByText(/Persistentes/).length).toBeGreaterThanOrEqual(1);

      // Navega para aba de Corrigidas
      const resolvedTabBtn = screen.getByRole("button", { name: /Correções Validadas/i });
      fireEvent.click(resolvedTabBtn);

      expect(await screen.findByText("Ciphers TLS Obsoletos Habilitados")).toBeInTheDocument();
    });
  });

  describe("Seleção e Comparação no Histórico de Auditorias (ScansHistoryPanel)", () => {
    it("permite selecionar 2 auditorias e dispara callback onCompare", async () => {
      vi.spyOn(global, "fetch").mockImplementation(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes("/scans/page")) {
          return new Response(
            JSON.stringify({
              items: [mockScanA, mockScanB],
              total: 2,
              limit: 10,
              offset: 0,
            }),
            { status: 200, headers: { "Content-Type": "application/json" } }
          );
        }
        return new Response("Not found", { status: 404 });
      });

      const onCompareMock = vi.fn();
      renderWithClient(
        <ScansHistoryPanel
          token="test-token"
          role="ADMIN"
          assets={[mockAsset]}
          selectedScanId={null}
          onSelect={vi.fn()}
          onCancel={vi.fn()}
          onCompare={onCompareMock}
        />
      );

      const checkboxes = await screen.findAllByRole("checkbox", { name: /Comparar auditoria/i });
      expect(checkboxes).toHaveLength(2);

      // Marca a primeira auditoria
      fireEvent.click(checkboxes[0]);
      expect(await screen.findByText(/1 auditoria\(s\) selecionada\(s\) para comparação/)).toBeInTheDocument();

      // Marca a segunda auditoria
      fireEvent.click(checkboxes[1]);
      expect(await screen.findByText(/2 auditoria\(s\) selecionada\(s\) para comparação/)).toBeInTheDocument();

      // Botão de Comparar Auditorias deve estar visível
      const compareBtn = screen.getByRole("button", { name: "Comparar Auditorias" });
      fireEvent.click(compareBtn);

      expect(onCompareMock).toHaveBeenCalledWith("scan-aaaa-1111", "scan-bbbb-2222");
    });
  });

  describe("Revalidação Técnica em Detalhes da Vulnerabilidade (VulnerabilitiesPanel)", () => {
    it("permite solicitar revalidação técnica diretamente no modal de detalhes", async () => {
      const mockFinding = {
        id: "find-rev-1",
        organization_id: "org-1",
        asset_id: "asset-123",
        asset_name: "API Pagamentos Homolog",
        scan_id: "scan-aaaa-1111",
        module_id: "cors_misconfiguration",
        check_id: "cors_wildcard",
        title: "CORS Misconfiguration em Produção",
        description: "Cabeçalho vulnerável a requisições com credenciais de qualquer origem.",
        affected_endpoint: "http://10.0.0.5:8000/api/v1/auth",
        severity: "HIGH",
        result_classification: "VULNERABILITY",
        treatment_status: "IN_PROGRESS",
        confidence: "CERTAIN",
        priority: "P1",
        sla_deadline: "2026-10-30T18:00:00Z",
        risk_acceptance_reason: null,
        revalidation_scan_id: null,
        cwe_ids: ["CWE-942"],
        owasp_categories: ["A01:2021"],
        cvss_v4_score: 7.2,
        cvss_v4_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
        remediation_data: {
          how_it_was_detected: "Teste real HTTP",
          how_to_fix: "Configurar Access-Control-Allow-Origin estrito",
          how_to_validate: "Repetir request",
          references: [],
        },
        reproduction_steps: ["curl -H 'Origin: evil.com' http://target/auth"],
        evidence: {},
        created_at: "2026-10-21T09:00:00Z",
      };

      vi.spyOn(global, "fetch").mockImplementation(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes("/findings/page")) {
          return new Response(
            JSON.stringify({
              items: [mockFinding],
              total: 1,
              limit: 15,
              offset: 0,
            }),
            { status: 200, headers: { "Content-Type": "application/json" } }
          );
        }
        if (url.includes("/findings/find-rev-1/revalidate")) {
          return new Response(
            JSON.stringify({
              finding_id: "find-rev-1",
              scan_id: "scan-reval-9999",
              status: "COMPLETED",
              message: "Correção verificada com sucesso via revalidação técnica: PASSED.",
              previous_status: "IN_PROGRESS",
              new_status: "RESOLVED_VERIFIED",
              verified_at: "2026-10-22T11:00:00Z",
            }),
            { status: 200, headers: { "Content-Type": "application/json" } }
          );
        }
        if (url.includes("/findings/find-rev-1/history")) {
          return new Response(
            JSON.stringify({
              finding_id: "find-rev-1",
              detections: [],
              triage_events: [],
            }),
            { status: 200, headers: { "Content-Type": "application/json" } }
          );
        }
        if (url.includes("/findings/find-rev-1")) {
          return new Response(JSON.stringify(mockFinding), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        }
        return new Response("Not found", { status: 404 });
      });

      renderWithClient(
        <VulnerabilitiesPanel
          token="test-token"
          role="ADMIN"
          assets={[mockAsset]}
        />
      );

      const detailsBtn = await screen.findByRole("button", { name: /Ver detalhes de CORS Misconfiguration/i });
      fireEvent.click(detailsBtn);

      expect(await screen.findByText("Prazo de SLA de Remediação")).toBeInTheDocument();
      expect(screen.getAllByText("P1 — Crítica").length).toBeGreaterThanOrEqual(1);

      const revalidateBtn = screen.getByRole("button", { name: "Solicitar Revalidação Técnica" });
      fireEvent.click(revalidateBtn);

      await waitFor(() => {
        expect(screen.getByText(/Revalidação finalizada: Corrigida e validada/)).toBeInTheDocument();
      });
    });
  });
});
