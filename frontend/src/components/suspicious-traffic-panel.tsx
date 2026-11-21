"use client";

import { useQuery } from "@tanstack/react-query";

import { AiTriageCard } from "@/components/ai-triage-card";
import { Button } from "@/components/ui/button";
import {
  createTrafficAlertTriageSuggestion,
  fetchTrafficAnalyses,
  type TrafficAnalysisRun,
} from "@/lib/api";
import { errorMessage, formatDateTime } from "@/lib/soc-utils";

const layerLabels: Record<string, string> = {
  CONNECTIONS: "Conexões",
  DNS: "DNS",
  TLS: "Identidade TLS",
  EDR: "Antivírus/EDR",
};

const tlsOutcomeLabels: Record<string, string> = {
  BASELINE_ESTABLISHED: "Baseline estabelecido",
  UNCHANGED: "Certificado inalterado",
  BENIGN_ROTATION: "Rotação legítima",
  INTERCEPTION_ALERT: "Alerta de interceptação",
};

const edrSourceLabels: Record<string, string> = {
  ANTIVIRUS: "Antivírus",
  EDR: "EDR",
};

const edrSignalLabels: Record<string, string> = {
  SUSPICIOUS_PROCESS: "Processo suspeito",
  UNTRUSTED_ROOT_CA: "Autoridade certificadora não confiável",
  BEACONING_DETECTED: "Comunicação periódica (beaconing)",
  MALWARE_QUARANTINED: "Malware em quarentena",
};

const levelLabels: Record<string, string> = {
  HIGH: "Alta",
  MEDIUM: "Média",
  LOW: "Baixa",
};

function formatLayers(layers: string[]): string {
  if (layers.length === 0) return "nenhuma";
  return layers.map((layer) => layerLabels[layer] ?? layer).join(", ");
}

function RunCard({
  run,
  token,
  canManage,
}: {
  run: TrafficAnalysisRun;
  token: string;
  canManage: boolean;
}) {
  return (
    <div className="space-y-2 rounded border border-slate-200 p-2 dark:border-slate-800">
      <p className="font-semibold">
        {run.source_name}{" "}
        <span className="font-normal">· {formatDateTime(run.created_at)}</span>
      </p>
      <p>
        {run.connection_count} conexões · {run.dns_count} DNS · {run.tls_count} TLS ·{" "}
        {run.edr_count} AV/EDR · {run.benign_rotations_count} rotação(ões) legítima(s) ·{" "}
        {run.alerts_count} alerta(s)
      </p>
      <p>
        Cobertura observada: {formatLayers(run.coverage.observed_layers)} · Ausente:{" "}
        {formatLayers(run.coverage.missing_layers)}
      </p>

      {run.tls_decisions.length > 0 && (
        <div className="space-y-1">
          <p className="font-semibold">Decisões de identidade TLS:</p>
          <ul className="list-disc pl-5">
            {run.tls_decisions.map((decision) => (
              <li key={decision.id}>
                {tlsOutcomeLabels[decision.outcome] ?? decision.outcome} · {decision.server_name} (
                {decision.responder_ip}:{decision.responder_port}) · cert{" "}
                <code>{decision.observed_cert_sha256.slice(0, 12)}</code> · {decision.reason}
              </li>
            ))}
          </ul>
        </div>
      )}

      {run.edr_signals.length > 0 && (
        <div className="space-y-1">
          <p className="font-semibold">Sinais de antivírus/EDR:</p>
          <ul className="list-disc pl-5">
            {run.edr_signals.map((sig) => (
              <li key={sig.id}>
                {edrSourceLabels[sig.source_type] ?? sig.source_type} ·{" "}
                {edrSignalLabels[sig.signal] ?? sig.signal} · {sig.host_ip} · processo{" "}
                <code>{sig.process_name}</code>
                {sig.detail ? ` (${sig.detail})` : ""}
              </li>
            ))}
          </ul>
        </div>
      )}

      {run.alerts.length > 0 && (
        <div className="space-y-1">
          <p className="font-semibold">Alertas explicáveis:</p>
          <ul className="space-y-1">
            {run.alerts.map((alert) => (
              <li key={alert.id} className="rounded bg-slate-50 p-2 dark:bg-slate-900">
                <p className="font-semibold">
                  {alert.title}{" "}
                  <span className="font-normal">
                    · {alert.rule_id} · Severidade {levelLabels[alert.severity] ?? alert.severity} · Confiança{" "}
                    {levelLabels[alert.confidence] ?? alert.confidence}
                  </span>
                </p>
                <p>{alert.explanation}</p>
                <p className="text-xs text-slate-600 dark:text-slate-400">
                  Evidência: <code>{JSON.stringify(alert.evidence)}</code>
                </p>
                <AiTriageCard
                  token={token}
                  targetLabel={alert.rule_id}
                  canReview={canManage}
                  onGenerate={() =>
                    createTrafficAlertTriageSuggestion(token, run.asset_id, run.id, alert.id)
                  }
                />
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

export function SuspiciousTrafficPanel({
  token,
  assetId,
  canManage = true,
}: {
  token: string;
  assetId: string;
  canManage?: boolean;
}) {
  const analyses = useQuery({
    queryKey: ["suspicious-traffic", token, assetId],
    queryFn: () => fetchTrafficAnalyses(token, assetId),
  });

  return (
    <section aria-label="Tráfego suspeito" className="space-y-2">
      <div className="flex items-center justify-between">
        <p className="font-semibold">Tráfego suspeito</p>
        <Button
          size="sm"
          variant="outline"
          disabled={analyses.isFetching}
          onClick={() => void analyses.refetch()}
        >
          Atualizar análises
        </Button>
      </div>
      {analyses.isPending && <p>Carregando análises…</p>}
      {analyses.isError && <p role="alert">{errorMessage(analyses.error)}</p>}
      {analyses.data?.length === 0 && (
        <p className="text-slate-500">
          Nenhuma análise de tráfego suspeito registrada. Use{" "}
          <code>scripts/analyze_traffic.py</code> em laboratório.
        </p>
      )}
      {analyses.data?.map((run) => (
        <RunCard key={run.id} run={run} token={token} canManage={canManage} />
      ))}
    </section>
  );
}
