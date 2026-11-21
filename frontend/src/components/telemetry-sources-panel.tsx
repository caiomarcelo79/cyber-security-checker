"use client";

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import { z } from "zod";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  fetchTelemetrySources,
  pauseTelemetrySource,
  recoverTelemetrySource,
  registerTelemetrySource,
  resumeTelemetrySource,
  revokeTelemetrySource,
  updateTelemetrySource,
  type TelemetrySource,
  type TelemetrySourceCreated,
  type TelemetrySourceUpdateRequest,
} from "@/lib/api";
import { errorMessage, formatDateTime } from "@/lib/soc-utils";

const sourceForm = z.object({
  name: z.string().trim().min(2, "Informe um nome para a fonte.").max(100),
  network: z
    .string()
    .trim()
    .max(49)
    .regex(/^[0-9a-f:.]+\/\d{1,3}$/i, "Informe um segmento em formato CIDR."),
});
type SourceForm = z.infer<typeof sourceForm>;

const statusLabels: Record<TelemetrySource["status"], string> = {
  ACTIVE: "Ativa",
  PAUSED: "Pausada",
  EXPIRED: "Expirada",
  REVOKED: "Revogada",
};

const updateLabels: Record<NonNullable<TelemetrySource["update_status"]>, string> = {
  UP_TO_DATE: "Atualizado",
  UPDATE_AVAILABLE: "Atualização pendente",
  UNKNOWN: "Sem heartbeat",
};

const inputClass =
  "w-full rounded-md border border-slate-300 bg-transparent px-2 py-1.5 dark:border-slate-700";

interface TelemetrySourcesPanelProps {
  token: string;
  assetId: string;
  canManage: boolean;
  authorized: boolean;
}

export function TelemetrySourcesPanel({
  token,
  assetId,
  canManage,
  authorized,
}: TelemetrySourcesPanelProps) {
  const queryClient = useQueryClient();
  const queryKey = ["telemetry-sources", token, assetId];
  const sources = useQuery({ queryKey, queryFn: () => fetchTelemetrySources(token, assetId) });
  const [created, setCreated] = useState<TelemetrySourceCreated | null>(null);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editNetwork, setEditNetwork] = useState("");
  const [editDesiredVersion, setEditDesiredVersion] = useState("");
  const [editInterval, setEditInterval] = useState("2");
  const [lifecycleFeedback, setLifecycleFeedback] = useState<string | null>(null);

  const form = useForm<SourceForm>({
    resolver: zodResolver(sourceForm),
    defaultValues: { name: "", network: "" },
  });

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey });
    void queryClient.invalidateQueries({ queryKey: ["pilots"] });
  };

  const create = useMutation({
    mutationFn: (values: SourceForm) => registerTelemetrySource(token, assetId, values),
    onMutate: () => {
      setCreated(null);
      setLifecycleFeedback(null);
    },
    onSuccess: (result) => {
      setCreated(result);
      form.reset();
      invalidate();
    },
  });

  const pause = useMutation({
    mutationFn: (sourceId: string) => pauseTelemetrySource(token, assetId, sourceId),
    onSuccess: () => {
      setLifecycleFeedback("Fonte pausada.");
      invalidate();
    },
  });

  const resume = useMutation({
    mutationFn: (sourceId: string) => resumeTelemetrySource(token, assetId, sourceId),
    onSuccess: () => {
      setLifecycleFeedback("Fonte retomada.");
      invalidate();
    },
  });

  const update = useMutation({
    mutationFn: ({ sourceId, payload }: { sourceId: string; payload: TelemetrySourceUpdateRequest }) =>
      updateTelemetrySource(token, assetId, sourceId, payload),
    onSuccess: (updated) => {
      setEditingId(null);
      setLifecycleFeedback(`Configuração v${updated.config_version ?? 1} registrada.`);
      invalidate();
    },
  });

  const recover = useMutation({
    mutationFn: (sourceId: string) => recoverTelemetrySource(token, assetId, sourceId),
    onMutate: () => {
      setCreated(null);
      setLifecycleFeedback(null);
    },
    onSuccess: (result) => {
      setCreated(result);
      setLifecycleFeedback(`Credencial recuperada (geração ${result.token_generation ?? 1}).`);
      invalidate();
    },
  });

  const revoke = useMutation({
    mutationFn: (sourceId: string) => revokeTelemetrySource(token, assetId, sourceId),
    onSuccess: (_result, sourceId) => {
      setCreated((current) => (current?.id === sourceId ? null : current));
      setEditingId((current) => (current === sourceId ? null : current));
      invalidate();
    },
  });

  const beginEdit = (source: TelemetrySource) => {
    setEditingId(source.id);
    setEditNetwork(source.network);
    setEditDesiredVersion(source.desired_version ?? source.collector_version ?? "1.1.0");
    setEditInterval(String(source.poll_interval_seconds ?? 2));
    setLifecycleFeedback(null);
  };

  const submitUpdate = (sourceId: string) => {
    const payload: TelemetrySourceUpdateRequest = {};
    if (editNetwork.trim()) payload.network = editNetwork.trim();
    if (editDesiredVersion.trim()) payload.desired_version = editDesiredVersion.trim();
    const intervalNum = Number.parseInt(editInterval, 10);
    if (Number.isFinite(intervalNum) && intervalNum >= 1 && intervalNum <= 300) {
      payload.poll_interval_seconds = intervalNum;
    }
    update.mutate({ sourceId, payload });
  };

  const actionError =
    pause.error || resume.error || update.error || recover.error || revoke.error;

  return (
    <section aria-label="Telemetria de rede" className="space-y-2">
      <div className="flex items-center justify-between">
        <p className="font-semibold">Telemetria de rede</p>
        <Button size="sm" variant="outline" disabled={sources.isFetching} onClick={() => void sources.refetch()}>
          Atualizar fontes
        </Button>
      </div>
      {sources.isPending && <p>Carregando fontes…</p>}
      {sources.isError && <p role="alert">{errorMessage(sources.error)}</p>}
      {sources.data?.length === 0 && (
        <p className="text-slate-500">Nenhuma fonte cadastrada para este ativo.</p>
      )}
      {sources.data?.map((source) => (
        <div
          key={source.id}
          className="space-y-1.5 rounded border border-slate-200 p-2 dark:border-slate-800"
        >
          <div className="flex flex-wrap items-center justify-between gap-2">
            <p className="font-semibold">
              {source.name} <span className="font-normal">· {source.network}</span>
            </p>
            <div className="flex flex-wrap items-center gap-1">
              {source.config_version !== undefined && (
                <Badge variant="outline">Config v{source.config_version}</Badge>
              )}
              {source.update_status && (
                <Badge
                  variant={
                    source.update_status === "UP_TO_DATE"
                      ? "success"
                      : source.update_status === "UPDATE_AVAILABLE"
                      ? "warning"
                      : "outline"
                  }
                >
                  {updateLabels[source.update_status]}
                </Badge>
              )}
            </div>
          </div>
          <p>
            Credencial {statusLabels[source.status].toLowerCase()} · {source.connection_count} conexões armazenadas
            {source.collector_version ? ` · coletor ${source.collector_version}` : ""}
          </p>
          <p>
            Último envio {source.last_received_at ? formatDateTime(source.last_received_at) : "aguardando dados"}
          </p>
          {source.latest_observed_at && <p>Último evento {formatDateTime(source.latest_observed_at)}</p>}
          {canManage && (
            <div className="flex flex-wrap gap-1.5 pt-1">
              {source.status === "ACTIVE" && (
                <Button
                  size="sm"
                  variant="outline"
                  disabled={pause.isPending}
                  onClick={() => pause.mutate(source.id)}
                  aria-label={`Pausar ${source.name}`}
                >
                  Pausar
                </Button>
              )}
              {source.status === "PAUSED" && (
                <Button
                  size="sm"
                  variant="secondary"
                  disabled={resume.isPending}
                  onClick={() => resume.mutate(source.id)}
                  aria-label={`Retomar ${source.name}`}
                >
                  Retomar
                </Button>
              )}
              {(source.status === "ACTIVE" || source.status === "PAUSED") && (
                <>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => (editingId === source.id ? setEditingId(null) : beginEdit(source))}
                    aria-label={`Atualizar ${source.name}`}
                  >
                    Atualizar
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={revoke.isPending}
                    onClick={() => revoke.mutate(source.id)}
                    aria-label={`Revogar credencial de ${source.name}`}
                  >
                    Revogar credencial
                  </Button>
                </>
              )}
              {(source.status === "REVOKED" || source.status === "EXPIRED") && (
                <Button
                  size="sm"
                  variant="default"
                  disabled={recover.isPending}
                  onClick={() => recover.mutate(source.id)}
                  aria-label={`Recuperar credencial de ${source.name}`}
                >
                  Recuperar credencial
                </Button>
              )}
            </div>
          )}
          {canManage && editingId === source.id && (
            <div
              className="mt-2 grid grid-cols-1 gap-2 rounded border border-slate-200 p-2 dark:border-slate-800 sm:grid-cols-3"
              aria-label={`Atualizar fonte ${source.name}`}
            >
              <label>
                Segmento
                <input
                  className={inputClass}
                  value={editNetwork}
                  onChange={(e) => setEditNetwork(e.target.value)}
                />
              </label>
              <label>
                Versão desejada
                <input
                  className={inputClass}
                  value={editDesiredVersion}
                  onChange={(e) => setEditDesiredVersion(e.target.value)}
                />
              </label>
              <label>
                Intervalo (s)
                <input
                  type="number"
                  min={1}
                  max={300}
                  className={inputClass}
                  value={editInterval}
                  onChange={(e) => setEditInterval(e.target.value)}
                />
              </label>
              <div className="flex gap-2 sm:col-span-3">
                <Button
                  size="sm"
                  disabled={update.isPending}
                  onClick={() => submitUpdate(source.id)}
                >
                  Salvar atualização
                </Button>
                <Button size="sm" variant="ghost" onClick={() => setEditingId(null)}>
                  Cancelar
                </Button>
              </div>
            </div>
          )}
        </div>
      ))}
      {actionError && <p role="alert">{errorMessage(actionError)}</p>}
      {lifecycleFeedback && <p role="status">{lifecycleFeedback}</p>}
      {canManage && authorized && (
        <form
          className="flex flex-wrap items-start gap-2"
          aria-label="Cadastrar fonte de telemetria"
          onSubmit={form.handleSubmit((values) => create.mutate(values))}
        >
          <label>
            Nome da fonte
            <input className={inputClass} {...form.register("name")} />
            {form.formState.errors.name && (
              <span role="alert" className="block">
                {form.formState.errors.name.message}
              </span>
            )}
          </label>
          <label>
            Segmento autorizado
            <input
              className={inputClass}
              placeholder="192.168.50.0/24"
              {...form.register("network")}
            />
            {form.formState.errors.network && (
              <span role="alert" className="block">
                {form.formState.errors.network.message}
              </span>
            )}
          </label>
          <Button size="sm" type="submit" className="mt-4" disabled={create.isPending}>
            Cadastrar fonte
          </Button>
          {create.isError && <p role="alert">{errorMessage(create.error)}</p>}
        </form>
      )}
      {created && (
        <div className="space-y-1 rounded border border-slate-200 p-2 dark:border-slate-800">
          <p>Guarde a credencial da instalação. Ela aparece apenas após o cadastro ou recuperação.</p>
          <p>
            Identificador da fonte <code>{created.id}</code>
          </p>
          <label>
            Credencial da fonte
            <input
              className={`${inputClass} font-mono`}
              readOnly
              value={created.collector_token}
              onFocus={(event) => event.target.select()}
            />
          </label>
          <Button size="sm" variant="outline" onClick={() => setCreated(null)}>
            Ocultar credencial
          </Button>
        </div>
      )}
    </section>
  );
}
