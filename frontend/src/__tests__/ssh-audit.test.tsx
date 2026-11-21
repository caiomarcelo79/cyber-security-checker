import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";

import { AssetsDirectory } from "@/components/assets-directory";
import type { AssetResponse, SshAuditResponse } from "@/lib/api";

const timestamp = "2026-11-20T12:00:00Z";
const asset: AssetResponse = {
  id: "lab-asset",
  organization_id: "lab",
  name: "OpenSSH de laboratÃ³rio",
  target_url: "http://lab-target",
  hostname: "lab-target",
  asset_type: "DOMAIN",
  environment: "LAB",
  owner_name: "Equipe SOC",
  owner_email: "soc@lab.local",
  tags: [],
  excluded_paths: [],
  risk_score: 0,
  authorization_status: "VERIFIED",
  created_at: timestamp,
  updated_at: timestamp,
};

afterEach(() => vi.unstubAllGlobals());

it.each([
  ["PASSED", "disabled", "Conforme", "desabilitada", "no", "bloqueado"],
  ["VULNERABILITY", "enabled", "DivergÃªncia de polÃ­tica", "habilitada", "prohibit-password", "permitido sem senha"],
  ["INCONCLUSIVE", "unknown", "EvidÃªncia insuficiente", "indeterminada", "unknown", "indeterminado"],
  ["EXECUTION_ERROR", "collection_error", "Erro de coleta", "indisponÃ­vel", "collection_error", "indisponÃ­vel"],
] as const)("mostra a evidÃªncia de SSH para %s", async (status, observation, label, evidence, root, rootLabel) => {
  const sshAudit: SshAuditResponse = {
    id: "lab-audit",
    created_at: timestamp,
    status,
    password_authentication: observation,
    permit_root_login: root,
    permit_root_login_status: status,
  };
  const fetchMock = vi.fn(async (url: string) =>
    new Response(
      JSON.stringify(
        url.endsWith("/ssh-audit") ? sshAudit
          : url.endsWith("/telemetry-sources") || url.endsWith("/availability-exercises") || url.endsWith("/traffic-analyses") ? [] : { total: 0, items: [] }
      )
    )
  );
  vi.stubGlobal("fetch", fetchMock);

  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <AssetsDirectory
        token="test-session"
        orgName="LaboratÃ³rio"
        assets={[asset]}
        selectedAssetId={null}
        onManageAuthorization={vi.fn()}
        onAudit={vi.fn()}
        onViewFindings={vi.fn()}
        onOpenScan={vi.fn()}
      />
    </QueryClientProvider>
  );

  fireEvent.click(screen.getByRole("button", { name: "Ver detalhes" }));
  expect(
    await screen.findByText(new RegExp(`${label} Â· Diretiva global PasswordAuthentication ${evidence}`))
  ).toBeInTheDocument();
  expect(screen.getByText(`${label} Â· Diretiva global de acesso de root ${rootLabel}`)).toBeInTheDocument();
  expect(fetchMock).toHaveBeenCalledWith(
    expect.stringContaining("/assets/lab-asset/ssh-audit"),
    expect.objectContaining({ credentials: "include" })
  );
});
