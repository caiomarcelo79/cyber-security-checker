"use client";

import { useQuery } from "@tanstack/react-query";

import { Button } from "@/components/ui/button";
import { fetchAvailabilityExercises, type AvailabilityExercise } from "@/lib/api";
import { errorMessage, formatDateTime } from "@/lib/soc-utils";

const resultLabels = {
  PASSED: "Aprovado",
  FAILED: "Reprovado",
  INCONCLUSIVE: "Inconclusivo",
  EXECUTION_ERROR: "Erro de execução",
} as const;
const statusLabels = { NORMAL: "Normal", ALERT: "Alerta aberto", RECOVERED: "Recuperado" } as const;
const scenarioLabels = {
  LATENCY: "Latência",
  ERRORS: "Erros HTTP (5xx)",
  SATURATION: "Saturação (429)",
} as const;
const sourceLabels = {
  FIREWALL: "Firewall",
  CDN: "CDN",
  PROVIDER: "Provedor",
} as const;
const signalLabels = {
  RATE_LIMITED: "Limitação de taxa",
  UPSTREAM_ERROR: "Erro de origem",
  SATURATION: "Saturação de capacidade",
  MITIGATION_ACTIVE: "Mitigação ativa",
  RECOVERED: "Normalizado",
} as const;
const eventLabels = {
  DEGRADATION_START: "Início da degradação",
  ALERT_OPENED: "Alerta aberto",
  RECOVERY_START: "Início da recuperação",
  RECOVERY_DETECTED: "Recuperação detectada",
} as const;

function seconds(valueMs: number | null): string {
  return valueMs === null ? "—" : `${(valueMs / 1000).toFixed(1)} s`;
}

function signedSeconds(valueMs: number | null): string {
  if (valueMs === null) return "—";
  return `${valueMs >= 0 ? "+" : "−"}${(Math.abs(valueMs) / 1000).toFixed(1)} s`;
}

function headline(exercise: AvailabilityExercise): string {
  if (exercise.status === "RUNNING") return `Em andamento · ${statusLabels[exercise.state]}`;
  return exercise.result ? resultLabels[exercise.result] : "Encerrado";
}

export function AvailabilityPanel({ token, assetId }: { token: string; assetId: string }) {
  const exercises = useQuery({
    queryKey: ["availability-exercises", token, assetId],
    queryFn: () => fetchAvailabilityExercises(token, assetId),
  });

  return (
    <section aria-label="Disponibilidade" className="space-y-2">
      <div className="flex items-center justify-between">
        <p className="font-semibold">Disponibilidade</p>
        <Button size="sm" variant="outline" disabled={exercises.isFetching} onClick={() => void exercises.refetch()}>
          Atualizar exercícios
        </Button>
      </div>
      {exercises.isPending && <p>Carregando exercícios…</p>}
      {exercises.isError && <p role="alert">{errorMessage(exercises.error)}</p>}
      {exercises.data?.length === 0 && (
        <p className="text-slate-500">
          Nenhum exercício de disponibilidade executado. Use <code>scripts/availability_exercise.py</code> em laboratório.
        </p>
      )}
      {exercises.data?.map((exercise) => (
        <div key={exercise.id} className="space-y-1 rounded border border-slate-200 p-2 dark:border-slate-800">
          <p className="font-semibold">
            {headline(exercise)} <span className="font-normal">· {scenarioLabels[exercise.scenario ?? "LATENCY"]} · {formatDateTime(exercise.started_at)}</span>
          </p>
          <p>
            Limiar {exercise.threshold_ms} ms · {exercise.consecutive_samples} amostras consecutivas · intervalo{" "}
            {seconds(exercise.interval_ms)} · {exercise.sample_count} amostras
          </p>
          {exercise.metrics_summary && (
            <p>
              Pico de latência{" "}
              {exercise.metrics_summary.peak_latency_ms === null
                ? "—"
                : `${exercise.metrics_summary.peak_latency_ms.toFixed(1)} ms`}{" "}
              · Erros 5xx: {exercise.metrics_summary.error_5xx_count} · Saturação 429:{" "}
              {exercise.metrics_summary.rate_limited_429_count} · Timeouts/falhas:{" "}
              {exercise.metrics_summary.timeout_or_connection_error_count}
            </p>
          )}
          <table className="w-full text-left" aria-label="Linha do tempo do exercício">
            <thead>
              <tr>
                <th scope="col">Evento</th>
                <th scope="col">Esperado</th>
                <th scope="col">Observado</th>
                <th scope="col">Diferença</th>
              </tr>
            </thead>
            <tbody>
              {exercise.timeline.map((event) => (
                <tr key={event.event}>
                  <td>{eventLabels[event.event]}</td>
                  <td>{seconds(event.expected_offset_ms)}</td>
                  <td>{seconds(event.observed_offset_ms)}</td>
                  <td>{signedSeconds(event.delta_ms)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {exercise.signals && exercise.signals.length > 0 && (
            <div className="space-y-1">
              <p className="font-semibold">Sinais de borda/provedor:</p>
              <ul className="list-disc pl-5">
                {exercise.signals.map((sig) => (
                  <li key={sig.id}>
                    {sourceLabels[sig.source_type]} · {signalLabels[sig.signal]} · {seconds(sig.offset_ms)}
                    {sig.http_status !== null && ` (HTTP ${sig.http_status})`}
                  </li>
                ))}
              </ul>
            </div>
          )}
          {exercise.alert_publication_ms !== null && (
            <p>
              Publicação na caixa de notificações: alerta {exercise.alert_publication_ms} ms
              {exercise.recovery_publication_ms !== null && `, recuperação ${exercise.recovery_publication_ms} ms`}
            </p>
          )}
        </div>
      ))}
    </section>
  );
}
