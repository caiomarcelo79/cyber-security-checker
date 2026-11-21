import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";

import { PilotRolloutPanel } from "@/components/pilot-rollout-panel";
import type {
  AssetResponse,
  PilotEnrollment,
  PilotReadiness,
  PilotReview,
} from "@/lib/api";

const timestamp = "2026-11-20T15:00:00Z";
const labAsset: AssetResponse = {
  id: "asset-lab-1",
  organization_id: "org-1",
  name: "Sensor Interno Lab",
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

const pilotFixture: PilotEnrollment = {
  id: "pilot-1",
  organization_id: "org-1",
  asset_id: labAsset.id,
  asset_name: labAsset.name,
  asset_environment: "LAB",
  asset_hostname: labAsset.hostname,
  stage: "OWN_ENVIRONMENT",
  status: "ACTIVE",
  prerequisite_pilot_id: null,
  allowed_cidrs: ["192.168.50.0/24"],
  enabled_capabilities: ["TELEMETRY", "TRAFFIC_ANALYSIS"],
  max_sources: 2,
  scope_notes: "Piloto inicial em segmento isolado",
  expires_at: "2026-12-20T15:00:00Z",
  paused_at: null,
  revoked_at: null,
  created_by_user_id: "usr-1",
  created_at: timestamp,
  updated_at: timestamp,
  latest_review_decision: null,
};

const readinessFixture: PilotReadiness = {
  pilot_id: pilotFixture.id,
  asset_id: labAsset.id,
  stage: "OWN_ENVIRONMENT",
  status: "ACTIVE",
  lifecycle: {
    installation_demonstrated: true,
    pause_resume_demonstrated: true,
    update_demonstrated: true,
    revocation_demonstrated: true,
    recovery_demonstrated: true,
    all_demonstrated: true,
  },
  coverage: {
    total_sources: 1,
    active_sources: 1,
    paused_sources: 0,
    revoked_sources: 0,
    up_to_date_sources: 1,
    traffic_runs_count: 2,
    observed_layers: ["CONNECTIONS", "DNS", "TLS"],
    missing_layers: ["EDR"],
    layer_coverage_percent: 75,
    ssh_audits_count: 1,
    availability_exercises_total: 1,
    availability_exercises_passed: 1,
  },
  latency: {
    telemetry_samples_count: 5,
    telemetry_avg_delay_seconds: 1.2,
    telemetry_max_delay_seconds: 2.4,
    availability_alert_pub_avg_ms: 15,
    availability_alert_pub_max_ms: 18,
    availability_recovery_pub_avg_ms: 12,
    availability_recovery_pub_max_ms: 12,
  },
  false_positives: {
    suspicious_alerts_total: 2,
    benign_tls_rotations_ignored: 1,
    triage_suggestions_total: 2,
    triage_approved_count: 1,
    triage_rejected_count: 0,
    triage_pending_count: 1,
    findings_total: 0,
    findings_false_positive_count: 0,
    findings_false_positive_rate_percent: 0,
  },
  blocking_reasons: [],
  ready_for_expansion_approval: true,
  latest_review: null,
};

function renderPanel(role: string) {
  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <PilotRolloutPanel token="session" role={role} assets={[labAsset]} />
    </QueryClientProvider>
  );
}

afterEach(() => vi.unstubAllGlobals());

it("mostra estado vazio, habilita piloto, exibe prontidão e registra revisão formal", async () => {
  let pilots: PilotEnrollment[] = [];
  let reviews: PilotReview[] = [];

  const fetchMock = vi.fn(async (url: string, options?: RequestInit) => {
    const method = options?.method ?? "GET";
    if (method === "POST" && url.endsWith("/pilots")) {
      pilots = [pilotFixture];
      return Response.json(pilotFixture, { status: 201 });
    }
    if (url.endsWith(`/pilots/${pilotFixture.id}/readiness`)) {
      return Response.json(readinessFixture);
    }
    if (method === "POST" && url.endsWith(`/pilots/${pilotFixture.id}/reviews`)) {
      const review: PilotReview = {
        id: "rev-1",
        pilot_id: pilotFixture.id,
        organization_id: "org-1",
        decision: "APPROVED_FOR_EXPANSION",
        coverage_ok: true,
        latency_ok: true,
        false_positives_ok: true,
        reviewer_user_id: "usr-1",
        notes: "Aprovado após validação de laboratório.",
        metrics_snapshot: {},
        created_at: timestamp,
      };
      reviews = [review];
      pilots = [{ ...pilotFixture, latest_review_decision: "APPROVED_FOR_EXPANSION" }];
      return Response.json(review, { status: 201 });
    }
    if (url.endsWith(`/pilots/${pilotFixture.id}/reviews`)) {
      return Response.json(reviews);
    }
    return Response.json(pilots);
  });
  vi.stubGlobal("fetch", fetchMock);

  renderPanel("ADMIN");
  expect(await screen.findByTestId("pilots-empty")).toBeInTheDocument();

  fireEvent.change(screen.getByLabelText("Ativo autorizado"), {
    target: { value: labAsset.id },
  });
  fireEvent.click(screen.getByRole("button", { name: "Habilitar piloto" }));

  expect(await screen.findByText(/Prontidão e Revisão do Piloto/)).toBeInTheDocument();
  expect(await screen.findByText(/Camadas \(75%\): CONNECTIONS, DNS, TLS/)).toBeInTheDocument();
  expect(screen.getByText(/Atraso médio: 1\.2 s/)).toBeInTheDocument();
  expect(screen.getByText(/Rotações TLS benignas isoladas: 1/)).toBeInTheDocument();

  fireEvent.change(screen.getByLabelText("Notas da revisão"), {
    target: { value: "Aprovado após validação de laboratório." },
  });
  fireEvent.click(screen.getByRole("button", { name: "Registrar revisão" }));
  expect(await screen.findByText(/Histórico de revisões/)).toBeInTheDocument();
  expect(screen.getByText(/Revisão registrada: Aprovado para expansão/)).toBeInTheDocument();
  expect(screen.getAllByText("Aprovado para expansão").length).toBeGreaterThanOrEqual(3);
});

it("mantém visualização somente leitura para perfil VIEWER", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => {
      if (url.endsWith("/readiness")) return Response.json(readinessFixture);
      if (url.endsWith("/reviews")) return Response.json([]);
      return Response.json([pilotFixture]);
    })
  );

  renderPanel("VIEWER");
  expect(await screen.findByText(/Visualização somente leitura/)).toBeInTheDocument();
  expect(await screen.findByText(/Critérios operacionais atendidos/)).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Habilitar piloto" })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Registrar revisão" })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Revogar piloto" })).not.toBeInTheDocument();
});
