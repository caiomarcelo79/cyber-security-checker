import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";

import { AiTriageCard } from "@/components/ai-triage-card";
import { SuspiciousTrafficPanel } from "@/components/suspicious-traffic-panel";
import type { AiTriageSuggestion, TrafficAnalysisRun } from "@/lib/api";

const baseSuggestion: AiTriageSuggestion = {
  id: "sug-1",
  organization_id: "org-1",
  asset_id: "lab-asset",
  target_type: "TRAFFIC_ALERT",
  traffic_alert_id: "alert-1",
  finding_id: null,
  generation_mode: "DETERMINISTIC_FALLBACK",
  ai_status: "UNAVAILABLE",
  model_name: "csc-deterministic-triage-v1",
  summary: "[Alta | Confiança Alta] Varredura de portas. Evidências observadas: origin_ip=192.168.50.10.",
  explanation: "Conexões para 8 portas distintas em janela única.",
  recommended_action: "CONTAIN",
  remediation_steps: [
    "Validar autorização do host de origem.",
    "Restringir portas expostas no firewall.",
  ],
  evidence_citations: [
    { field: "origin_ip", value_excerpt: "192.168.50.10" },
    { field: "distinct_ports_count", value_excerpt: "8" },
  ],
  sanitized_evidence_hash: "a".repeat(64),
  review_status: "PENDING_REVIEW",
  requires_analyst_review: true,
  reviewer_user_id: null,
  reviewer_notes: null,
  reviewed_at: null,
  created_at: "2026-11-20T14:50:00Z",
};

const sampleRun: TrafficAnalysisRun = {
  id: "run-1",
  asset_id: "lab-asset",
  source_id: "src-1",
  source_name: "Zeek Sensor Lab",
  coverage: { observed_layers: ["CONNECTIONS"], missing_layers: ["DNS", "TLS", "EDR"] },
  connection_count: 8,
  dns_count: 0,
  tls_count: 0,
  edr_count: 0,
  alerts_count: 1,
  benign_rotations_count: 0,
  tls_decisions: [],
  edr_signals: [],
  alerts: [
    {
      id: "alert-1",
      rule_id: "CONNECTION_PORT_SWEEP",
      category: "CONNECTIONS",
      severity: "HIGH",
      confidence: "HIGH",
      title: "Varredura de portas detectada",
      explanation: "8 portas distintas testadas.",
      evidence: { origin_ip: "192.168.50.10", distinct_ports_count: 8 },
      observed_layers: ["CONNECTIONS"],
      missing_layers: ["DNS", "TLS", "EDR"],
      created_at: "2026-11-20T14:50:00Z",
    },
  ],
  created_at: "2026-11-20T14:50:00Z",
};

afterEach(() => vi.unstubAllGlobals());

it("gera sugestão em alerta de tráfego suspeito e aprova revisão humana", async () => {
  const fetchMock = vi.fn(async (url: string, init?: { method?: string }) => {
    if (url.endsWith("/traffic-analyses")) {
      return Response.json([sampleRun]);
    }
    if (url.endsWith("/triage-suggestion") && init?.method === "POST") {
      return Response.json(baseSuggestion, { status: 201 });
    }
    if (url.endsWith("/triage-suggestions/sug-1/review") && init?.method === "PATCH") {
      return Response.json({
        ...baseSuggestion,
        review_status: "APPROVED",
        requires_analyst_review: false,
        reviewer_user_id: "analyst-1",
        reviewer_notes: "Contenção confirmada.",
        reviewed_at: "2026-11-20T14:52:00Z",
      });
    }
    return Response.json({}, { status: 404 });
  });
  vi.stubGlobal("fetch", fetchMock);

  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <SuspiciousTrafficPanel token="session" assetId="lab-asset" />
    </QueryClientProvider>
  );

  const generateBtn = await screen.findByRole("button", { name: "Gerar triagem assistida" });
  fireEvent.click(generateBtn);

  expect(await screen.findByText(/IA indisponível — fallback ativo/)).toBeInTheDocument();
  expect(screen.getByText(/Citações da evidência:/)).toBeInTheDocument();
  expect(screen.getByText(/Restringir portas expostas no firewall/)).toBeInTheDocument();

  fireEvent.change(screen.getByLabelText("Nota de revisão da triagem assistida"), {
    target: { value: "Contenção confirmada." },
  });
  fireEvent.click(screen.getByRole("button", { name: "Aprovar sugestão" }));

  expect(await screen.findByText(/Aprovada pelo analista/)).toBeInTheDocument();
  expect(screen.getByText(/Nota: Contenção confirmada\./)).toBeInTheDocument();
  expect(fetchMock).toHaveBeenCalledWith(
    expect.stringContaining("/triage-suggestions/sug-1/review"),
    expect.objectContaining({
      method: "PATCH",
      body: JSON.stringify({ decision: "APPROVED", reviewer_notes: "Contenção confirmada." }),
    })
  );
});

it("rejeita sugestão e exibe erro quando a API falha na geração", async () => {
  const fetchMock = vi.fn(async () =>
    Response.json({
      ...baseSuggestion,
      review_status: "REJECTED",
      requires_analyst_review: false,
      reviewed_at: "2026-11-20T14:53:00Z",
    })
  );
  vi.stubGlobal("fetch", fetchMock);

  const failingGenerate = vi
    .fn()
    .mockRejectedValueOnce(new Error("Falha simulada"))
    .mockResolvedValueOnce(baseSuggestion);

  render(<AiTriageCard token="session" targetLabel="CHK-A05" onGenerate={failingGenerate} />);

  fireEvent.click(screen.getByRole("button", { name: "Gerar triagem assistida" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("Falha simulada");

  fireEvent.click(screen.getByRole("button", { name: "Gerar triagem assistida" }));
  await screen.findByText(/Pendente de revisão do analista/);

  fireEvent.click(screen.getByRole("button", { name: "Rejeitar sugestão" }));
  await waitFor(() => expect(screen.getByText(/Rejeitada pelo analista/)).toBeInTheDocument());
});
