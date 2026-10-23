import React from "react";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  type AssetResponse,
  type NotificationPageResponse,
  type ScanSchedulePageResponse,
  type WebhookEndpoint,
} from "@/lib/api";
import { AutomationsPanel } from "@/components/automations-panel";

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
  id: "asset-1",
  organization_id: "org-1",
  name: "Portal Web Homolog",
  hostname: "portal.local",
  target_url: "https://portal.local",
  asset_type: "WEB_APP",
  environment: "STAGING",
  owner_name: "SecOps Team",
  owner_email: "secops@portal.local",
  risk_score: 30,
  authorization_status: "VERIFIED",
  created_at: "2026-10-20T10:00:00Z",
  updated_at: "2026-10-20T10:00:00Z",
  tags: ["portal"],
  excluded_paths: [],
};

const mockSchedules: ScanSchedulePageResponse = {
  items: [
    {
      id: "sched-1",
      organization_id: "org-1",
      asset_id: "asset-1",
      asset_name: "Portal Web Homolog",
      profile_type: "QUICK",
      enabled_modules: ["security_headers"],
      frequency: "DAILY",
      cron_expression: "0 2 * * *",
      timezone: "America/Sao_Paulo",
      status: "ACTIVE",
      is_active: true,
      misfire_policy: "SKIP",
      consecutive_failures: 0,
      next_run_at: "2026-10-23T05:00:00Z",
      created_at: "2026-10-22T10:00:00Z",
    },
  ],
  total: 1,
  limit: 50,
  offset: 0,
};

const mockNotifications: NotificationPageResponse = {
  items: [
    {
      id: "notif-1",
      organization_id: "org-1",
      event_type: "finding.created",
      severity: "CRITICAL",
      title: "Injeção SQL Detectada",
      message: "Evidência confirmada em /login no parâmetro user.",
      read_at: null,
      metadata_json: {},
      created_at: "2026-10-22T11:00:00Z",
    },
  ],
  total: 1,
  unread_count: 1,
  limit: 50,
  offset: 0,
};

const mockWebhooks: WebhookEndpoint[] = [
  {
    id: "wh-1",
    organization_id: "org-1",
    url: "https://siem.empresa.com/events",
    description: "SIEM Splunk SOC",
    secret_token_prefix: "whsec_abcd1234***",
    subscribed_events: ["scan.completed", "finding.created"],
    is_active: true,
    consecutive_failures: 0,
    created_at: "2026-10-22T11:00:00Z",
  },
];

describe("AutomationsPanel (Fase 7)", () => {
  beforeEach(() => {
    vi.restoreAllMocks();

    vi.stubGlobal(
      "fetch",
      vi.fn((url: string) => {
        if (url.includes("/automations/schedules")) {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve(mockSchedules),
          });
        }
        if (url.includes("/automations/notifications/preferences")) {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () =>
              Promise.resolve({
                id: "pref-1",
                organization_id: "org-1",
                user_id: "user-1",
                email_enabled: false,
                email_destination: null,
                channels: ["IN_APP"],
                min_severity: "MEDIUM",
                subscribed_events: [],
              }),
          });
        }
        if (url.includes("/automations/notifications")) {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve(mockNotifications),
          });
        }
        if (url.includes("/automations/webhooks")) {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve(mockWebhooks),
          });
        }
        if (url.includes("/automations/api-tokens")) {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () =>
              Promise.resolve({
                items: [
                  {
                    id: "token-1",
                    organization_id: "org-1",
                    user_id: "user-1",
                    name: "CI/CD Pipeline",
                    token_prefix: "csc_live_1234",
                    scopes: ["scans:read", "findings:read"],
                    is_revoked: false,
                    created_at: "2026-10-22T11:00:00Z",
                  },
                ],
                total: 1,
                limit: 50,
                offset: 0,
              }),
          });
        }
        if (url.includes("/automations/templates")) {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () =>
              Promise.resolve({
                items: [
                  {
                    id: "tpl-1",
                    organization_id: "org-1",
                    name: "Auditoria Rápida OWASP",
                    profile_type: "QUICK",
                    enabled_modules: ["security_headers", "ssl_tls"],
                    parameters: {},
                    created_at: "2026-10-22T11:00:00Z",
                  },
                ],
                total: 1,
                limit: 50,
                offset: 0,
              }),
          });
        }
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve({}),
        });
      })
    );
  });

  it("renderiza a aba de Agendamentos e exibe tabela com agendamento mockado", async () => {
    renderWithClient(
      <AutomationsPanel token="test-token" role="SECURITY_ANALYST" assets={[mockAsset]} />
    );

    expect(screen.getByText(/Automações, Agendamentos e Integrações/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Novo Agendamento/i })).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getByText("Portal Web Homolog")).toBeInTheDocument();
      expect(screen.getByText(/DAILY/i)).toBeInTheDocument();
      expect(screen.getByText("ATIVO")).toBeInTheDocument();
    });
  });

  it("permite alternar para a sub-aba de Notificações e exibe alertas", async () => {
    renderWithClient(
      <AutomationsPanel token="test-token" role="SECURITY_ANALYST" assets={[mockAsset]} />
    );

    const notifTab = screen.getByRole("button", { name: /Notificações/i });
    fireEvent.click(notifTab);

    await waitFor(() => {
      expect(screen.getByText("Injeção SQL Detectada")).toBeInTheDocument();
      expect(screen.getByText("CRÍTICO")).toBeInTheDocument();
      expect(screen.getByRole("button", { name: /Marcar Todas como Lidas/i })).toBeInTheDocument();
    });
  });

  it("permite alternar para a sub-aba de Webhooks e exibe endpoints", async () => {
    renderWithClient(
      <AutomationsPanel token="test-token" role="SECURITY_ANALYST" assets={[mockAsset]} />
    );

    const webhookTab = screen.getByRole("button", { name: /Webhooks/i });
    fireEvent.click(webhookTab);

    await waitFor(() => {
      expect(screen.getByText("https://siem.empresa.com/events")).toBeInTheDocument();
      expect(screen.getByText("SIEM Splunk SOC")).toBeInTheDocument();
      expect(screen.getByRole("button", { name: /Cadastrar Webhook/i })).toBeInTheDocument();
    });
  });

  it("permite alternar para a sub-aba de Chaves de API e exibe chaves cadastradas", async () => {
    renderWithClient(
      <AutomationsPanel token="test-token" role="SECURITY_ANALYST" assets={[mockAsset]} />
    );

    const tokensTab = screen.getByRole("button", { name: /Chaves de API/i });
    fireEvent.click(tokensTab);

    await waitFor(() => {
      expect(screen.getByText("CI/CD Pipeline")).toBeInTheDocument();
      expect(screen.getByText("csc_live_1234...")).toBeInTheDocument();
      expect(screen.getByRole("button", { name: /Gerar Nova Chave de API/i })).toBeInTheDocument();
    });
  });

  it("permite alternar para a sub-aba de Templates de Auditoria", async () => {
    renderWithClient(
      <AutomationsPanel token="test-token" role="SECURITY_ANALYST" assets={[mockAsset]} />
    );

    const templatesTab = screen.getByRole("button", { name: /Templates/i });
    fireEvent.click(templatesTab);

    await waitFor(() => {
      expect(screen.getByText("Auditoria Rápida OWASP")).toBeInTheDocument();
      expect(screen.getByRole("button", { name: /Carregar Padrões da Indústria/i })).toBeInTheDocument();
    });
  });
});
