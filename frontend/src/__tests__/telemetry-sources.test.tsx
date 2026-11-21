import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";

import { TelemetrySourcesPanel } from "@/components/telemetry-sources-panel";
import type { TelemetrySource } from "@/lib/api";

const assetId = "lab-asset";
const sourceRoute = `/assets/${assetId}/telemetry-sources`;
const source: TelemetrySource = {
  id: "zeek-lab",
  name: "Zeek do laboratório",
  network: "192.168.50.0/24",
  status: "ACTIVE",
  expires_at: "2026-12-20T12:00:00Z",
  last_received_at: "2026-11-20T12:00:00Z",
  latest_observed_at: "2026-11-20T11:59:00Z",
  connection_count: 12,
};

afterEach(() => vi.unstubAllGlobals());

function renderPanel(canManage: boolean) {
  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <TelemetrySourcesPanel token="session" assetId={assetId} canManage={canManage} authorized />
    </QueryClientProvider>
  );
}

it("mostra cobertura e recebimento reais para um leitor", async () => {
  vi.stubGlobal("fetch", vi.fn(async () => Response.json([source])));
  renderPanel(false);

  expect(await screen.findByText(/Zeek do laboratório/)).toBeInTheDocument();
  expect(screen.getByText(/192\.168\.50\.0\/24/)).toBeInTheDocument();
  expect(screen.getByText(/12 conexões armazenadas/)).toBeInTheDocument();
  expect(screen.getByText(/Último envio/)).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: /revogar/i })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: /cadastrar fonte/i })).not.toBeInTheDocument();
});

it("cadastra a fonte, mostra a credencial retornada uma vez e revoga a instalação", async () => {
  let sources: TelemetrySource[] = [];
  const fetchMock = vi.fn(async (url: string, options: RequestInit) => {
    if (options.method === "POST" && url.endsWith(sourceRoute)) {
      sources = [source];
      return Response.json({ ...source, collector_token: "fixture-token" }, { status: 201 });
    }
    if (options.method === "DELETE" && url.endsWith(`${sourceRoute}/${source.id}`)) {
      sources = [{ ...source, status: "REVOKED" }];
      return new Response(null, { status: 204 });
    }
    return Response.json(sources);
  });
  vi.stubGlobal("fetch", fetchMock);
  renderPanel(true);
  expect(await screen.findByText(/Nenhuma fonte cadastrada/)).toBeInTheDocument();

  fireEvent.change(screen.getByLabelText("Nome da fonte"), { target: { value: source.name } });
  fireEvent.change(screen.getByLabelText("Segmento autorizado"), { target: { value: source.network } });
  fireEvent.click(screen.getByRole("button", { name: "Cadastrar fonte" }));
  expect(await screen.findByLabelText("Credencial da fonte")).toHaveValue("fixture-token");

  fireEvent.click(await screen.findByRole("button", { name: /Revogar credencial de/ }));
  expect(await screen.findByText(/Credencial revogada/)).toBeInTheDocument();
  await waitFor(() => expect(screen.queryByLabelText("Credencial da fonte")).not.toBeInTheDocument());
  expect(fetchMock).toHaveBeenCalledWith(
    expect.stringContaining(sourceRoute),
    expect.objectContaining({ method: "POST", body: JSON.stringify({ name: source.name, network: source.network }) })
  );
});

it("executa pausa, retomada, atualização e recuperação de credencial no painel", async () => {
  let current: TelemetrySource = {
    ...source,
    config_version: 1,
    poll_interval_seconds: 2,
    update_status: "UNKNOWN",
    token_generation: 1,
  };
  const fetchMock = vi.fn(async (url: string, options?: RequestInit) => {
    const method = options?.method ?? "GET";
    if (method === "POST" && url.endsWith(`${sourceRoute}/${source.id}/pause`)) {
      current = { ...current, status: "PAUSED" };
      return Response.json(current);
    }
    if (method === "POST" && url.endsWith(`${sourceRoute}/${source.id}/resume`)) {
      current = { ...current, status: "ACTIVE" };
      return Response.json(current);
    }
    if (method === "PATCH" && url.endsWith(`${sourceRoute}/${source.id}`)) {
      current = {
        ...current,
        config_version: 2,
        desired_version: "1.1.0",
        poll_interval_seconds: 5,
        update_status: "UPDATE_AVAILABLE",
      };
      return Response.json(current);
    }
    if (method === "DELETE" && url.endsWith(`${sourceRoute}/${source.id}`)) {
      current = { ...current, status: "REVOKED" };
      return new Response(null, { status: 204 });
    }
    if (method === "POST" && url.endsWith(`${sourceRoute}/${source.id}/recover`)) {
      current = {
        ...current,
        status: "ACTIVE",
        token_generation: 2,
        config_version: 3,
      };
      return Response.json({ ...current, collector_token: "recovered-token" });
    }
    return Response.json([current]);
  });
  vi.stubGlobal("fetch", fetchMock);
  renderPanel(true);

  expect(await screen.findByRole("button", { name: `Pausar ${source.name}` })).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: `Pausar ${source.name}` }));
  expect(await screen.findByText(/Credencial pausada/)).toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: `Retomar ${source.name}` }));
  expect(await screen.findByRole("button", { name: `Pausar ${source.name}` })).toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: `Atualizar ${source.name}` }));
  fireEvent.click(screen.getByRole("button", { name: "Salvar atualização" }));
  expect(await screen.findByText("Config v2")).toBeInTheDocument();
  expect(screen.getByText("Atualização pendente")).toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: `Revogar credencial de ${source.name}` }));
  const recoverBtn = await screen.findByRole("button", {
    name: `Recuperar credencial de ${source.name}`,
  });
  fireEvent.click(recoverBtn);
  expect(await screen.findByLabelText("Credencial da fonte")).toHaveValue("recovered-token");
});
