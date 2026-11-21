import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";

import { AssetsDirectory } from "@/components/assets-directory";
import type { AssetResponse } from "@/lib/api";

const timestamp = "2026-11-20T12:00:00Z";
const baseAsset: AssetResponse = {
  id: "asset-edit-1",
  organization_id: "org-1",
  name: "Portal Alvo",
  target_url: "https://contracteconsultoria.com.br/",
  hostname: "contracteconsultoria.com.br",
  asset_type: "WEB_APP",
  environment: "LAB",
  owner_name: "Equipe AppSec",
  owner_email: "appsec@lab.local",
  tags: ["laboratorio"],
  excluded_paths: ["/logout"],
  risk_score: 0,
  authorization_status: "VERIFIED",
  created_at: timestamp,
  updated_at: timestamp,
};

afterEach(() => vi.unstubAllGlobals());

function renderDirectory(asset: AssetResponse = baseAsset) {
  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <AssetsDirectory
        token="test-session"
        role="ADMIN"
        orgName="Org Teste"
        assets={[asset]}
        selectedAssetId={null}
        onManageAuthorization={vi.fn()}
        onAudit={vi.fn()}
        onViewFindings={vi.fn()}
        onOpenScan={vi.fn()}
      />
    </QueryClientProvider>
  );
}

it("permite editar o domínio/URL do ativo e envia PATCH com target_url", async () => {
  const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
    if (init?.method === "PATCH" && url.includes(`/assets/${baseAsset.id}`)) {
      const body = JSON.parse(String(init.body));
      return new Response(
        JSON.stringify({
          ...baseAsset,
          ...body,
          hostname: "localhost",
          authorization_status: "PENDING",
        }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      );
    }
    if (url.endsWith("/ssh-audit")) {
      return new Response("null", { status: 200, headers: { "Content-Type": "application/json" } });
    }
    if (
      url.endsWith("/telemetry-sources") ||
      url.endsWith("/availability-exercises") ||
      url.endsWith("/traffic-analyses")
    ) {
      return new Response("[]", { status: 200, headers: { "Content-Type": "application/json" } });
    }
    return new Response(JSON.stringify({ total: 0, items: [] }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  });
  vi.stubGlobal("fetch", fetchMock);

  renderDirectory();

  fireEvent.click(screen.getByRole("button", { name: "Ver detalhes" }));
  fireEvent.click(screen.getByRole("button", { name: "Editar ativo / domínio" }));

  const urlInput = screen.getByLabelText("URL ou domínio do ativo");
  expect(urlInput).toHaveValue("https://contracteconsultoria.com.br/");

  fireEvent.change(urlInput, { target: { value: "http://localhost:8080/" } });
  expect(
    screen.getByText(/Alterar o domínio\/origem redefine a autorização para PENDING e exige nova comprovação\./)
  ).toBeInTheDocument();

  const saveButton = screen.getByRole("button", { name: "Salvar" });
  expect(saveButton).not.toBeDisabled();
  fireEvent.click(saveButton);

  await waitFor(() => {
    const patchCall = fetchMock.mock.calls.find(
      ([u, opts]) => String(u).includes(`/assets/${baseAsset.id}`) && opts?.method === "PATCH"
    );
    expect(patchCall).toBeDefined();
    expect(JSON.parse(String(patchCall?.[1]?.body))).toMatchObject({
      target_url: "http://localhost:8080/",
    });
  });

  expect(
    await screen.findByText(
      /Ativo atualizado\. Como o domínio\/ambiente foi alterado, valide novamente a comprovação de autorização\./
    )
  ).toBeInTheDocument();
});

it("bloqueia envio e exibe alerta para URL inválida ou com credenciais", () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => {
      if (url.endsWith("/ssh-audit")) return new Response("null");
      if (
        url.endsWith("/telemetry-sources") ||
        url.endsWith("/availability-exercises") ||
        url.endsWith("/traffic-analyses")
      ) {
        return new Response("[]");
      }
      return new Response(JSON.stringify({ total: 0, items: [] }));
    })
  );

  renderDirectory();

  fireEvent.click(screen.getByRole("button", { name: "Ver detalhes" }));
  fireEvent.click(screen.getByRole("button", { name: "Editar ativo / domínio" }));

  const urlInput = screen.getByLabelText("URL ou domínio do ativo");

  fireEvent.change(urlInput, { target: { value: "ftp://lab.local" } });
  expect(screen.getByRole("button", { name: "Salvar" })).toBeDisabled();
  expect(screen.getByRole("alert")).toHaveTextContent(
    "Informe nome, URL http(s) válida sem credenciais, responsável e e-mail válidos."
  );

  fireEvent.change(urlInput, { target: { value: "http://user:pass@localhost" } });
  expect(screen.getByRole("button", { name: "Salvar" })).toBeDisabled();
  expect(screen.getByRole("alert")).toHaveTextContent(
    "Informe nome, URL http(s) válida sem credenciais, responsável e e-mail válidos."
  );
});
