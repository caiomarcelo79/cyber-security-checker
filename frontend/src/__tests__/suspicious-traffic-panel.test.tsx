import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";

import { SuspiciousTrafficPanel } from "@/components/suspicious-traffic-panel";
import type { TrafficAnalysisRun } from "@/lib/api";

const sampleRun: TrafficAnalysisRun = {
  id: "run-1",
  asset_id: "lab-asset",
  source_id: "src-1",
  source_name: "Zeek Sensor Lab",
  coverage: {
    observed_layers: ["CONNECTIONS", "DNS", "TLS", "EDR"],
    missing_layers: [],
  },
  connection_count: 8,
  dns_count: 5,
  tls_count: 1,
  edr_count: 1,
  alerts_count: 1,
  benign_rotations_count: 1,
  tls_decisions: [
    {
      id: "dec-1",
      uid: "TT2",
      server_name: "api.lab.internal",
      responder_ip: "198.51.100.30",
      responder_port: 443,
      outcome: "BENIGN_ROTATION",
      observed_cert_sha256: "b".repeat(64),
      previous_cert_sha256: "a".repeat(64),
      observed_issuer: "CN=R11, O=Let's Encrypt",
      previous_issuer: "CN=R10, O=Let's Encrypt",
      reason: "valid_renewal_same_ca",
      observed_at: "2026-11-20T12:00:00Z",
    },
  ],
  edr_signals: [
    {
      id: "edr-1",
      uid: "EDR1",
      host_ip: "192.168.50.10",
      source_type: "EDR",
      signal: "BEACONING_DETECTED",
      process_name: "python3",
      detail: "Fluxo repetitivo externo",
      observed_at: "2026-11-20T12:00:00Z",
    },
  ],
  alerts: [
    {
      id: "alert-1",
      rule_id: "CONNECTION_PORT_SWEEP",
      category: "CONNECTIONS",
      severity: "HIGH",
      confidence: "HIGH",
      title: "Varredura de portas detectada de 192.168.50.10 para 198.51.100.40",
      explanation:
        "O host iniciou conexões para 8 portas distintas. Correlacionado com 1 sinal(is) de EDR no host.",
      evidence: {
        origin_ip: "192.168.50.10",
        distinct_ports_count: 8,
      },
      observed_layers: ["CONNECTIONS", "DNS", "TLS", "EDR"],
      missing_layers: [],
      created_at: "2026-11-20T12:00:01Z",
    },
  ],
  created_at: "2026-11-20T12:00:01Z",
};

afterEach(() => vi.unstubAllGlobals());

function renderPanel() {
  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <SuspiciousTrafficPanel token="session" assetId="lab-asset" />
    </QueryClientProvider>
  );
}

it("exibe cobertura, rotação legítima TLS, sinais AV/EDR e alertas com evidência e confiança", async () => {
  vi.stubGlobal("fetch", vi.fn(async () => Response.json([sampleRun])));
  renderPanel();

  expect(await screen.findByText(/Zeek Sensor Lab/)).toBeInTheDocument();
  expect(
    screen.getByText(/Cobertura observada: Conexões, DNS, Identidade TLS, Antivírus\/EDR · Ausente: nenhuma/)
  ).toBeInTheDocument();
  expect(screen.getByText(/Rotação legítima · api\.lab\.internal/)).toBeInTheDocument();
  expect(screen.getByText(/EDR · Comunicação periódica \(beaconing\) · 192\.168\.50\.10/)).toBeInTheDocument();
  expect(screen.getByText(/Varredura de portas detectada/)).toBeInTheDocument();
  expect(screen.getByText(/Severidade Alta · Confiança Alta/)).toBeInTheDocument();
  expect(screen.getByText(/"distinct_ports_count":8/)).toBeInTheDocument();
});

it("mostra estado vazio quando não há análises de tráfego", async () => {
  vi.stubGlobal("fetch", vi.fn(async () => Response.json([])));
  renderPanel();
  expect(await screen.findByText(/Nenhuma análise de tráfego suspeito registrada/)).toBeInTheDocument();
});

it("exibe erro operacional quando a API falha", async () => {
  vi.stubGlobal("fetch", vi.fn(async () => Response.json({ detail: "Acesso negado" }, { status: 403 })));
  renderPanel();
  expect(await screen.findByRole("alert")).toBeInTheDocument();
});
