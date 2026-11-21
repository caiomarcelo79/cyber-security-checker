"use client";

import React, { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, Clock, ShieldCheck, XCircle } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  type AssetResponse,
  type PilotCapability,
  type PilotEnrollment,
  type PilotReviewDecision,
  type PilotStage,
  createPilot,
  fetchPilotReadiness,
  fetchPilotReviews,
  fetchPilots,
  pausePilot,
  recordPilotReview,
  resumePilot,
  revokePilot,
} from "@/lib/api";
import { canManageScans, errorMessage, formatDateTime } from "@/lib/soc-utils";

const ALL_CAPABILITIES: { id: PilotCapability; label: string }[] = [
  { id: "TELEMETRY", label: "Telemetria passiva" },
  { id: "TRAFFIC_ANALYSIS", label: "Tráfego suspeito" },
  { id: "AVAILABILITY", label: "Disponibilidade sintética" },
  { id: "SSH_AUDIT", label: "Auditoria SSH" },
  { id: "AI_TRIAGE", label: "Triagem assistida por IA" },
];

const STAGE_LABEL: Record<PilotStage, string> = {
  OWN_ENVIRONMENT: "Ambiente próprio",
  AUTHORIZED_CLIENT: "Cliente autorizado",
};

const STATUS_LABEL: Record<PilotEnrollment["status"], string> = {
  ACTIVE: "Ativo",
  PAUSED: "Pausado",
  EXPIRED: "Expirado",
  REVOKED: "Revogado",
};

const DECISION_LABEL: Record<PilotReviewDecision, string> = {
  APPROVED_FOR_EXPANSION: "Aprovado para expansão",
  NEEDS_ADJUSTMENT: "Requer ajustes",
};

const inputClass =
  "w-full rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-1.5 text-xs";

interface PilotRolloutPanelProps {
  token: string;
  role?: string | null;
  assets: AssetResponse[];
}

export function PilotRolloutPanel({ token, role, assets }: PilotRolloutPanelProps) {
  const queryClient = useQueryClient();
  const canManage = canManageScans(role);
  const isAdmin = role === "ADMIN";

  const [selectedPilotId, setSelectedPilotId] = useState<string | null>(null);
  const [stage, setStage] = useState<PilotStage>("OWN_ENVIRONMENT");
  const [assetId, setAssetId] = useState<string>("");
  const [prereqPilotId, setPrereqPilotId] = useState<string>("");
  const [allowedCidrsCsv, setAllowedCidrsCsv] = useState<string>("192.168.50.0/24");
  const [capabilities, setCapabilities] = useState<PilotCapability[]>([
    "TELEMETRY",
    "TRAFFIC_ANALYSIS",
    "AI_TRIAGE",
  ]);
  const [maxSources, setMaxSources] = useState<string>("2");
  const [expiresInDays, setExpiresInDays] = useState<string>("30");
  const [scopeNotes, setScopeNotes] = useState<string>("");
  const [feedback, setFeedback] = useState<string | null>(null);

  const [reviewDecision, setReviewDecision] =
    useState<PilotReviewDecision>("APPROVED_FOR_EXPANSION");
  const [coverageOk, setCoverageOk] = useState<boolean>(true);
  const [latencyOk, setLatencyOk] = useState<boolean>(true);
  const [falsePositivesOk, setFalsePositivesOk] = useState<boolean>(true);
  const [reviewNotes, setReviewNotes] = useState<string>("");

  const pilotsQuery = useQuery({
    queryKey: ["pilots", token],
    queryFn: () => fetchPilots(token),
  });

  const activePilotId = selectedPilotId ?? pilotsQuery.data?.[0]?.id ?? null;

  const readinessQuery = useQuery({
    queryKey: ["pilot-readiness", token, activePilotId],
    queryFn: () => fetchPilotReadiness(token, activePilotId!),
    enabled: Boolean(activePilotId),
  });

  const reviewsQuery = useQuery({
    queryKey: ["pilot-reviews", token, activePilotId],
    queryFn: () => fetchPilotReviews(token, activePilotId!),
    enabled: Boolean(activePilotId),
  });

  const invalidatePilotQueries = (pilotId?: string) => {
    void queryClient.invalidateQueries({ queryKey: ["pilots"] });
    if (pilotId) {
      void queryClient.invalidateQueries({ queryKey: ["pilot-readiness", token, pilotId] });
      void queryClient.invalidateQueries({ queryKey: ["pilot-reviews", token, pilotId] });
    }
  };

  const createMutation = useMutation({
    mutationFn: () => {
      const cidrs = allowedCidrsCsv
        .split(",")
        .map((c) => c.trim())
        .filter(Boolean);
      return createPilot(token, {
        asset_id: assetId,
        stage,
        prerequisite_pilot_id:
          stage === "AUTHORIZED_CLIENT" && prereqPilotId.trim()
            ? prereqPilotId.trim()
            : null,
        allowed_cidrs: cidrs,
        enabled_capabilities: capabilities,
        max_sources: Number.parseInt(maxSources, 10) || 2,
        expires_in_days: Number.parseInt(expiresInDays, 10) || 30,
        scope_notes: scopeNotes.trim() || null,
      });
    },
    onSuccess: (created) => {
      setSelectedPilotId(created.id);
      setScopeNotes("");
      setFeedback(`Piloto habilitado para ${created.asset_name} (${STAGE_LABEL[created.stage]}).`);
      invalidatePilotQueries(created.id);
    },
    onError: (err) => setFeedback(errorMessage(err)),
  });

  const lifecycleAction = useMutation({
    mutationFn: ({ id, action }: { id: string; action: "pause" | "resume" | "revoke" }) => {
      if (action === "pause") return pausePilot(token, id);
      if (action === "resume") return resumePilot(token, id);
      return revokePilot(token, id);
    },
    onSuccess: (updated) => {
      setFeedback(`Estado do piloto atualizado para ${STATUS_LABEL[updated.status]}.`);
      invalidatePilotQueries(updated.id);
    },
    onError: (err) => setFeedback(errorMessage(err)),
  });

  const reviewMutation = useMutation({
    mutationFn: (pilotId: string) =>
      recordPilotReview(token, pilotId, {
        decision: reviewDecision,
        coverage_ok: coverageOk,
        latency_ok: latencyOk,
        false_positives_ok: falsePositivesOk,
        notes: reviewNotes.trim() || null,
      }),
    onSuccess: (saved) => {
      setReviewNotes("");
      setFeedback(`Revisão registrada: ${DECISION_LABEL[saved.decision]}.`);
      invalidatePilotQueries(saved.pilot_id);
    },
    onError: (err) => setFeedback(errorMessage(err)),
  });

  const toggleCapability = (cap: PilotCapability) => {
    setCapabilities((prev) =>
      prev.includes(cap) ? prev.filter((item) => item !== cap) : [...prev, cap]
    );
  };

  const approvedOwnPilots = (pilotsQuery.data ?? []).filter(
    (p) =>
      p.stage === "OWN_ENVIRONMENT" && p.latest_review_decision === "APPROVED_FOR_EXPANSION"
  );

  const readiness = readinessQuery.data;

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <ShieldCheck className="h-4 w-4 text-sky-500" />
              Habilitação de Piloto e Escopo Controlado
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 text-xs">
            {!canManage ? (
              <p className="text-slate-500">
                Visualização somente leitura. Apenas analistas ou administradores podem habilitar ou revisar pilotos.
              </p>
            ) : (
              <form
                aria-label="Habilitar piloto controlado"
                className="space-y-3"
                onSubmit={(e) => {
                  e.preventDefault();
                  setFeedback(null);
                  createMutation.mutate();
                }}
              >
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                  <div>
                    <label htmlFor="pilot_stage" className="mb-1 block font-semibold">
                      Estágio do piloto
                    </label>
                    <select
                      id="pilot_stage"
                      className={inputClass}
                      value={stage}
                      onChange={(e) => setStage(e.target.value as PilotStage)}
                    >
                      <option value="OWN_ENVIRONMENT">Ambiente próprio (Laboratório)</option>
                      {isAdmin && (
                        <option value="AUTHORIZED_CLIENT">
                          Cliente autorizado (após aprovação)
                        </option>
                      )}
                    </select>
                  </div>
                  <div>
                    <label htmlFor="pilot_asset" className="mb-1 block font-semibold">
                      Ativo autorizado
                    </label>
                    <select
                      id="pilot_asset"
                      className={inputClass}
                      value={assetId}
                      onChange={(e) => setAssetId(e.target.value)}
                      required
                    >
                      <option value="">Selecione um ativo…</option>
                      {assets.map((asset) => (
                        <option key={asset.id} value={asset.id}>
                          {asset.name} ({asset.environment} · {asset.authorization_status})
                        </option>
                      ))}
                    </select>
                  </div>
                </div>

                {stage === "AUTHORIZED_CLIENT" && (
                  <div>
                    <label htmlFor="pilot_prereq" className="mb-1 block font-semibold">
                      ID do piloto aprovado em ambiente próprio
                    </label>
                    <input
                      id="pilot_prereq"
                      list="approved-own-pilots"
                      placeholder="UUID do piloto OWN_ENVIRONMENT aprovado"
                      className={inputClass}
                      value={prereqPilotId}
                      onChange={(e) => setPrereqPilotId(e.target.value)}
                      required
                    />
                    <datalist id="approved-own-pilots">
                      {approvedOwnPilots.map((item) => (
                        <option key={item.id} value={item.id}>
                          {item.asset_name}
                        </option>
                      ))}
                    </datalist>
                  </div>
                )}

                <div>
                  <label htmlFor="pilot_cidrs" className="mb-1 block font-semibold">
                    Segmentos CIDR autorizados (separados por vírgula)
                  </label>
                  <input
                    id="pilot_cidrs"
                    className={inputClass}
                    value={allowedCidrsCsv}
                    onChange={(e) => setAllowedCidrsCsv(e.target.value)}
                    placeholder="192.168.50.0/24"
                    required
                  />
                </div>

                <div>
                  <p className="mb-1 font-semibold">Capacidades liberadas no escopo</p>
                  <div className="flex flex-wrap gap-3">
                    {ALL_CAPABILITIES.map((cap) => (
                      <label key={cap.id} className="flex items-center gap-1.5">
                        <input
                          type="checkbox"
                          checked={capabilities.includes(cap.id)}
                          onChange={() => toggleCapability(cap.id)}
                        />
                        <span>{cap.label}</span>
                      </label>
                    ))}
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label htmlFor="pilot_max_sources" className="mb-1 block font-semibold">
                      Máximo de fontes
                    </label>
                    <input
                      id="pilot_max_sources"
                      type="number"
                      min={1}
                      max={20}
                      className={inputClass}
                      value={maxSources}
                      onChange={(e) => setMaxSources(e.target.value)}
                    />
                  </div>
                  <div>
                    <label htmlFor="pilot_expires_days" className="mb-1 block font-semibold">
                      Validade (dias)
                    </label>
                    <input
                      id="pilot_expires_days"
                      type="number"
                      min={1}
                      max={90}
                      className={inputClass}
                      value={expiresInDays}
                      onChange={(e) => setExpiresInDays(e.target.value)}
                    />
                  </div>
                </div>

                <div>
                  <label htmlFor="pilot_notes" className="mb-1 block font-semibold">
                    Observações de escopo (opcional)
                  </label>
                  <input
                    id="pilot_notes"
                    className={inputClass}
                    value={scopeNotes}
                    onChange={(e) => setScopeNotes(e.target.value)}
                    placeholder="Ex.: Piloto inicial em segmento isolado sem impacto em produção"
                  />
                </div>

                <Button
                  type="submit"
                  size="sm"
                  disabled={!assetId || capabilities.length === 0 || createMutation.isPending}
                >
                  {createMutation.isPending ? "Habilitando..." : "Habilitar piloto"}
                </Button>
              </form>
            )}
            {feedback && (
              <p role="status" className="rounded border border-slate-200 p-2 dark:border-slate-800">
                {feedback}
              </p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle className="text-base">Pilotos Cadastrados</CardTitle>
            <Button
              size="sm"
              variant="outline"
              disabled={pilotsQuery.isFetching}
              onClick={() => void pilotsQuery.refetch()}
            >
              Atualizar
            </Button>
          </CardHeader>
          <CardContent className="space-y-3 text-xs">
            {pilotsQuery.isPending && <p>Carregando habilitações de piloto…</p>}
            {pilotsQuery.isError && <p role="alert">{errorMessage(pilotsQuery.error)}</p>}
            {pilotsQuery.data?.length === 0 && (
              <p data-testid="pilots-empty" className="text-slate-500">
                Nenhum piloto habilitado nesta organização. Cadastre um piloto em ambiente próprio para demonstrar o ciclo operacional e revisar cobertura, latência e falsos positivos antes de expandir.
              </p>
            )}
            {pilotsQuery.data?.map((pilot) => (
              <div
                key={pilot.id}
                className={`space-y-1.5 rounded-md border p-3 ${
                  activePilotId === pilot.id
                    ? "border-sky-500 bg-sky-500/5"
                    : "border-slate-200 dark:border-slate-800"
                }`}
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="font-semibold">
                    {pilot.asset_name} ({pilot.asset_environment})
                  </span>
                  <div className="flex flex-wrap gap-1.5">
                    <Badge variant="outline">{STAGE_LABEL[pilot.stage]}</Badge>
                    <Badge
                      variant={
                        pilot.status === "ACTIVE"
                          ? "success"
                          : pilot.status === "PAUSED"
                          ? "warning"
                          : "critical"
                      }
                    >
                      {STATUS_LABEL[pilot.status]}
                    </Badge>
                    {pilot.latest_review_decision && (
                      <Badge
                        variant={
                          pilot.latest_review_decision === "APPROVED_FOR_EXPANSION"
                            ? "success"
                            : "warning"
                        }
                      >
                        {DECISION_LABEL[pilot.latest_review_decision]}
                      </Badge>
                    )}
                  </div>
                </div>
                <p className="font-mono text-slate-500">
                  CIDRs: {pilot.allowed_cidrs.join(", ")} · Máx. fontes: {pilot.max_sources}
                </p>
                <p className="text-slate-500">
                  Capacidades: {pilot.enabled_capabilities.join(", ")} · Expira em{" "}
                  {formatDateTime(pilot.expires_at)}
                </p>
                {pilot.scope_notes && <p className="text-slate-500">Escopo: {pilot.scope_notes}</p>}
                <div className="flex flex-wrap gap-2 pt-1">
                  <Button
                    size="sm"
                    variant="secondary"
                    onClick={() => setSelectedPilotId(pilot.id)}
                  >
                    Ver prontidão
                  </Button>
                  {canManage && pilot.status === "ACTIVE" && (
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={lifecycleAction.isPending}
                      onClick={() => lifecycleAction.mutate({ id: pilot.id, action: "pause" })}
                    >
                      Pausar piloto
                    </Button>
                  )}
                  {canManage && pilot.status === "PAUSED" && (
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={lifecycleAction.isPending}
                      onClick={() => lifecycleAction.mutate({ id: pilot.id, action: "resume" })}
                    >
                      Retomar piloto
                    </Button>
                  )}
                  {canManage && pilot.status !== "REVOKED" && (
                    <Button
                      size="sm"
                      variant="outline"
                      className="text-red-600 dark:text-red-400"
                      disabled={lifecycleAction.isPending}
                      onClick={() => lifecycleAction.mutate({ id: pilot.id, action: "revoke" })}
                    >
                      Revogar piloto
                    </Button>
                  )}
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      {activePilotId && readiness && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center justify-between text-base">
              <span>Prontidão e Revisão do Piloto</span>
              <Badge variant={readiness.ready_for_expansion_approval ? "success" : "warning"}>
                {readiness.ready_for_expansion_approval
                  ? "Critérios operacionais atendidos"
                  : "Pendências abertas"}
              </Badge>
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4 text-xs">
            <div>
              <p className="mb-2 font-semibold">Marcos operacionais demonstrados</p>
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-5">
                {[
                  ["Instalação", readiness.lifecycle.installation_demonstrated],
                  ["Pausa e retomada", readiness.lifecycle.pause_resume_demonstrated],
                  ["Atualização", readiness.lifecycle.update_demonstrated],
                  ["Revogação", readiness.lifecycle.revocation_demonstrated],
                  ["Recuperação", readiness.lifecycle.recovery_demonstrated],
                ].map(([label, ok]) => (
                  <div
                    key={String(label)}
                    className="flex items-center gap-2 rounded border border-slate-200 p-2 dark:border-slate-800"
                  >
                    {ok ? (
                      <CheckCircle2 className="h-4 w-4 text-emerald-500" />
                    ) : (
                      <Clock className="h-4 w-4 text-amber-500" />
                    )}
                    <span>{String(label)}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
              <div className="space-y-1 rounded border border-slate-200 p-3 dark:border-slate-800">
                <p className="font-semibold">Cobertura observada</p>
                <p>
                  Camadas ({readiness.coverage.layer_coverage_percent}%):{" "}
                  {readiness.coverage.observed_layers.join(", ") || "nenhuma"}
                </p>
                <p className="text-slate-500">
                  Ausentes: {readiness.coverage.missing_layers.join(", ") || "nenhuma"}
                </p>
                <p>
                  Fontes ativas: {readiness.coverage.active_sources}/{readiness.coverage.total_sources}{" "}
                  · Atualizadas: {readiness.coverage.up_to_date_sources}
                </p>
                <p>
                  Análises de tráfego: {readiness.coverage.traffic_runs_count} · Exercícios disp.:{" "}
                  {readiness.coverage.availability_exercises_passed}/
                  {readiness.coverage.availability_exercises_total}
                </p>
              </div>

              <div className="space-y-1 rounded border border-slate-200 p-3 dark:border-slate-800">
                <p className="font-semibold">Latência real</p>
                <p>Amostras de telemetria: {readiness.latency.telemetry_samples_count}</p>
                <p>
                  Atraso médio:{" "}
                  {readiness.latency.telemetry_avg_delay_seconds !== null
                    ? `${readiness.latency.telemetry_avg_delay_seconds} s`
                    : "—"}
                </p>
                <p>
                  Atraso máximo:{" "}
                  {readiness.latency.telemetry_max_delay_seconds !== null
                    ? `${readiness.latency.telemetry_max_delay_seconds} s`
                    : "—"}
                </p>
                <p>
                  Publicação de alerta disp.:{" "}
                  {readiness.latency.availability_alert_pub_avg_ms !== null
                    ? `${readiness.latency.availability_alert_pub_avg_ms} ms`
                    : "—"}
                </p>
              </div>

              <div className="space-y-1 rounded border border-slate-200 p-3 dark:border-slate-800">
                <p className="font-semibold">Revisão de falsos positivos</p>
                <p>Alertas de tráfego: {readiness.false_positives.suspicious_alerts_total}</p>
                <p>
                  Rotações TLS benignas isoladas:{" "}
                  {readiness.false_positives.benign_tls_rotations_ignored}
                </p>
                <p>
                  Sugestões IA: {readiness.false_positives.triage_approved_count} aprovadas ·{" "}
                  {readiness.false_positives.triage_rejected_count} rejeitadas
                </p>
                <p>
                  Taxa FP em achados:{" "}
                  {readiness.false_positives.findings_false_positive_rate_percent}% (
                  {readiness.false_positives.findings_false_positive_count}/
                  {readiness.false_positives.findings_total})
                </p>
              </div>
            </div>

            {readiness.blocking_reasons.length > 0 && (
              <div className="rounded border border-amber-500/40 bg-amber-500/10 p-3">
                <p className="mb-1 font-semibold">Bloqueios para aprovação da expansão:</p>
                <ul className="list-disc pl-4">
                  {readiness.blocking_reasons.map((reason) => (
                    <li key={reason}>{reason}</li>
                  ))}
                </ul>
              </div>
            )}

            {canManage && (
              <form
                aria-label="Registrar revisão do piloto"
                className="space-y-3 rounded border border-slate-200 p-3 dark:border-slate-800"
                onSubmit={(e) => {
                  e.preventDefault();
                  setFeedback(null);
                  reviewMutation.mutate(activePilotId);
                }}
              >
                <p className="font-semibold">Registrar revisão formal de expansão</p>
                <div className="flex flex-wrap gap-4">
                  <label className="flex items-center gap-1.5">
                    <input
                      type="checkbox"
                      checked={coverageOk}
                      onChange={(e) => setCoverageOk(e.target.checked)}
                    />
                    <span>Cobertura revisada</span>
                  </label>
                  <label className="flex items-center gap-1.5">
                    <input
                      type="checkbox"
                      checked={latencyOk}
                      onChange={(e) => setLatencyOk(e.target.checked)}
                    />
                    <span>Latência aceitável</span>
                  </label>
                  <label className="flex items-center gap-1.5">
                    <input
                      type="checkbox"
                      checked={falsePositivesOk}
                      onChange={(e) => setFalsePositivesOk(e.target.checked)}
                    />
                    <span>Falsos positivos revisados</span>
                  </label>
                </div>
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                  <div>
                    <label htmlFor="review_decision" className="mb-1 block font-semibold">
                      Decisão
                    </label>
                    <select
                      id="review_decision"
                      className={inputClass}
                      value={reviewDecision}
                      onChange={(e) => setReviewDecision(e.target.value as PilotReviewDecision)}
                    >
                      <option value="APPROVED_FOR_EXPANSION">Aprovado para expansão</option>
                      <option value="NEEDS_ADJUSTMENT">Requer ajustes</option>
                    </select>
                  </div>
                  <div>
                    <label htmlFor="review_notes" className="mb-1 block font-semibold">
                      Notas da revisão
                    </label>
                    <input
                      id="review_notes"
                      className={inputClass}
                      value={reviewNotes}
                      onChange={(e) => setReviewNotes(e.target.value)}
                      placeholder="Parecer técnico sobre cobertura, latência e ruído"
                    />
                  </div>
                </div>
                <Button type="submit" size="sm" disabled={reviewMutation.isPending}>
                  {reviewMutation.isPending ? "Salvando..." : "Registrar revisão"}
                </Button>
              </form>
            )}

            {(reviewsQuery.data ?? []).length > 0 && (
              <div className="space-y-1.5">
                <p className="font-semibold">Histórico de revisões</p>
                {reviewsQuery.data!.map((rev) => (
                  <div
                    key={rev.id}
                    className="flex flex-wrap items-center justify-between gap-2 rounded border border-slate-200 p-2 dark:border-slate-800"
                  >
                    <div className="flex items-center gap-2">
                      {rev.decision === "APPROVED_FOR_EXPANSION" ? (
                        <CheckCircle2 className="h-4 w-4 text-emerald-500" />
                      ) : (
                        <XCircle className="h-4 w-4 text-amber-500" />
                      )}
                      <span className="font-semibold">{DECISION_LABEL[rev.decision]}</span>
                      {rev.notes && <span className="text-slate-500">· {rev.notes}</span>}
                    </div>
                    <span className="text-slate-500">{formatDateTime(rev.created_at)}</span>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
