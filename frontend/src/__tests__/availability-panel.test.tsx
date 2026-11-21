import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";

import { AvailabilityPanel } from "@/components/availability-panel";
import type { AvailabilityExercise } from "@/lib/api";

const exercise: AvailabilityExercise = {
  id: "ex-1",
  status: "FINISHED",
  state: "RECOVERED",
  result: "PASSED",
  hostname: "lab-target",
  threshold_ms: 500,
  consecutive_samples: 3,
  interval_ms: 1000,
  normal_ms: 5000,
  degraded_ms: 5000,
  planned_duration_ms: 15000,
  tolerance_ms: 1000,
  sample_count: 15,
  timeline: [
    { event: "DEGRADATION_START", expected_offset_ms: 5000, observed_offset_ms: 5000, delta_ms: 0 },
    { event: "ALERT_OPENED", expected_offset_ms: 8000, observed_offset_ms: 7000, delta_ms: -1000 },
    { event: "RECOVERY_START", expected_offset_ms: 10000, observed_offset_ms: 10000, delta_ms: 0 },
    { event: "RECOVERY_DETECTED", expected_offset_ms: 13000, observed_offset_ms: null, delta_ms: null },
  ],
  alert_publication_ms: 12,
  recovery_publication_ms: null,
  started_at: "2026-11-20T12:00:00Z",
  finished_at: "2026-11-20T12:00:16Z",
};

afterEach(() => vi.unstubAllGlobals());

function renderPanel() {
  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <AvailabilityPanel token="session" assetId="lab-asset" />
    </QueryClientProvider>
  );
}

it("compara a linha do tempo esperada com a observada", async () => {
  vi.stubGlobal("fetch", vi.fn(async () => Response.json([exercise])));
  renderPanel();

  expect(await screen.findByText("Aprovado")).toBeInTheDocument();
  expect(screen.getByText("Alerta aberto")).toBeInTheDocument();
  expect(screen.getByText("−1.0 s")).toBeInTheDocument();
  expect(screen.getByText(/15 amostras/)).toBeInTheDocument();
  expect(screen.getByText(/alerta 12 ms/)).toBeInTheDocument();
  expect(screen.getAllByText("—").length).toBeGreaterThanOrEqual(2);
});

it("mostra estado vazio quando não há exercícios", async () => {
  vi.stubGlobal("fetch", vi.fn(async () => Response.json([])));
  renderPanel();
  expect(await screen.findByText(/Nenhum exercício de disponibilidade/)).toBeInTheDocument();
});

it("exibe erro operacional da API", async () => {
  vi.stubGlobal("fetch", vi.fn(async () => Response.json({ detail: "Acesso negado" }, { status: 403 })));
  renderPanel();
  expect(await screen.findByRole("alert")).toBeInTheDocument();
});

it("exibe cenário, métricas ampliadas e sinais de borda ou provedor", async () => {
  const enriched: AvailabilityExercise = {
    ...exercise,
    scenario: "SATURATION",
    metrics_summary: {
      peak_latency_ms: 820.5,
      error_5xx_count: 2,
      rate_limited_429_count: 4,
      timeout_or_connection_error_count: 1,
    },
    signals: [
      {
        id: "sig-1",
        source_type: "CDN",
        signal: "RATE_LIMITED",
        offset_ms: 5000,
        http_status: 429,
        created_at: "2026-11-20T12:00:05Z",
      },
      {
        id: "sig-2",
        source_type: "CDN",
        signal: "RECOVERED",
        offset_ms: 10000,
        http_status: 200,
        created_at: "2026-11-20T12:00:10Z",
      },
    ],
  };
  vi.stubGlobal("fetch", vi.fn(async () => Response.json([enriched])));
  renderPanel();

  expect(await screen.findByText(/Saturação \(429\)/)).toBeInTheDocument();
  expect(screen.getByText(/Pico de latência 820\.5 ms/)).toBeInTheDocument();
  expect(screen.getByText(/Erros 5xx: 2 · Saturação 429: 4 · Timeouts\/falhas: 1/)).toBeInTheDocument();
  expect(screen.getByText(/CDN · Limitação de taxa · 5\.0 s \(HTTP 429\)/)).toBeInTheDocument();
  expect(screen.getByText(/CDN · Normalizado · 10\.0 s \(HTTP 200\)/)).toBeInTheDocument();
});
