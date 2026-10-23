import React from "react";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { Providers } from "@/components/providers";
import { SocConsole } from "@/components/soc-console";

describe("SOC Console - Cyber-Security-Checker (TM-009 & TM-013)", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    global.fetch = vi.fn().mockImplementation((url: string) => {
      if (url.includes("/system/status")) {
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve({
              status: "UP",
              app_name: "cyber-security-checker",
              version: "0.1.0",
              environment: "test",
              current_phase:
                "FASE 2 — Autenticação, RBAC e Gestão de Ativos Autorizados",
              timestamp: new Date().toISOString(),
              components: {
                database: {
                  name: "PostgreSQL Database",
                  status: "UP",
                  latency_ms: 1.2,
                  details: {},
                },
                redis: {
                  name: "Redis Broker & Cache",
                  status: "UP",
                  latency_ms: 0.8,
                  details: {},
                },
                security_engine: {
                  name: "Security Engine",
                  status: "UP",
                  latency_ms: 0.3,
                  details: {},
                },
              },
              registered_modules_count: 8,
              available_profiles_count: 6,
              metrics: {
                total_organizations: 1,
                total_assets: 1,
                verified_assets: 1,
                total_scans_executed: 0,
                scans_in_progress: 0,
                open_vulnerabilities: 0,
                critical_vulnerabilities: 0,
                high_vulnerabilities: 0,
                medium_vulnerabilities: 0,
                low_vulnerabilities: 0,
                info_vulnerabilities: 0,
              },
            }),
        });
      }
      if (url.includes("/auth/register")) {
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve({
              access_token: "jwt_test_token_123",
              token_type: "bearer",
              expires_in_minutes: 60,
              user: {
                id: "usr-1",
                email: "admin@secops.local",
                full_name: "Admin SecOps",
                is_active: true,
                created_at: new Date().toISOString(),
              },
              active_organization: {
                id: "org-1",
                name: "SecOps Brasil",
                slug: "secops-brasil",
                is_active: true,
                created_at: new Date().toISOString(),
              },
              active_role: "ADMIN",
              memberships: [],
            }),
        });
      }
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve([]),
      });
    });
  });

  it("renderiza o painel SOC com telemetria real da API e zero dados fictícios", async () => {
    render(
      <Providers>
        <SocConsole />
      </Providers>
    );

    expect(screen.getByText("Cyber-Security-Checker")).toBeInTheDocument();
    expect(screen.getByText("Sistemas Cadastrados")).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getByText("ONLINE (UP)")).toBeInTheDocument();
    });

    expect(
      screen.getByText("Política Zero Dados Fictícios Ativa")
    ).toBeInTheDocument();
  });

  it("exibe abas de Autenticação, Sistemas/Ativos e RBAC/Audit Log da Fase 2", async () => {
    render(
      <Providers>
        <SocConsole />
      </Providers>
    );

    const authTabBtn = screen.getByText("Autenticação & Sessão");
    fireEvent.click(authTabBtn);

    expect(
      screen.getByText("Registrar Nova Organização e Administrador")
    ).toBeInTheDocument();

    const assetsTabBtn = screen.getByText("Sistemas / Ativos & Autorização");
    fireEvent.click(assetsTabBtn);

    expect(
      screen.getByText(
        "Sistemas / Ativos e Comprovação de Autorização (Fase 2)"
      )
    ).toBeInTheDocument();

    const scansTabBtn = screen.getByText("Auditorias & Vulnerabilidades");
    fireEvent.click(scansTabBtn);

    expect(
      screen.getByText(
        "Execução de Auditorias em Tempo Real & Resultados Técnicos (Fase 3)"
      )
    ).toBeInTheDocument();
  });
});
