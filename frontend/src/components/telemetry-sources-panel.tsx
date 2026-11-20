"use client";

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import { z } from "zod";

import { Button } from "@/components/ui/button";
import {
  fetchTelemetrySources,
  registerTelemetrySource,
  revokeTelemetrySource,
  type TelemetrySourceCreated,
} from "@/lib/api";
import { errorMessage, formatDateTime } from "@/lib/soc-utils";

const sourceForm = z.object({
  name: z.string().trim().min(2, "Informe um nome para a fonte.").max(100),
  network: z.string().trim().max(49).regex(/^[0-9a-f:.]+\/\d{1,3}$/i, "Informe um segmento em formato CIDR."),
});
type SourceForm = z.infer<typeof sourceForm>;

const statusLabels = { ACTIVE: "Ativa", EXPIRED: "Expirada", REVOKED: "Revogada" } as const;
const inputClass =
  "w-full rounded-md border border-slate-300 bg-transparent px-2 py-1.5 dark:border-slate-700";

interface TelemetrySourcesPanelProps {
  token: string;
  assetId: string;
  canManage: boolean;
  authorized: boolean;
}

export function TelemetrySourcesPanel({ token, assetId, canManage, authorized }: TelemetrySourcesPanelProps) {
  const queryClient = useQueryClient();
  const queryKey = ["telemetry-sources", token, assetId];
  const sources = useQuery({ queryKey, queryFn: () => fetchTelemetrySources(token, assetId) });
  const [created, setCreated] = useState<TelemetrySourceCreated | null>(null);
  const form = useForm<SourceForm>({
    resolver: zodResolver(sourceForm),
    defaultValues: { name: "", network: "" },
  });
  const create = useMutation({
    mutationFn: (values: SourceForm) => registerTelemetrySource(token, assetId, values),
    onMutate: () => setCreated(null),
    onSuccess: (result) => {
      setCreated(result);
      form.reset();
      void queryClient.invalidateQueries({ queryKey });
    },
  });
  const revoke = useMutation({
    mutationFn: (sourceId: string) => revokeTelemetrySource(token, assetId, sourceId),
    onSuccess: (_result, sourceId) => {
      setCreated((current) => current?.id === sourceId ? null : current);
      void queryClient.invalidateQueries({ queryKey });
    },
  });

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
      {sources.data?.length === 0 && <p className="text-slate-500">Nenhuma fonte cadastrada para este ativo.</p>}
      {sources.data?.map((source) => (
        <div key={source.id} className="space-y-1 rounded border border-slate-200 p-2 dark:border-slate-800">
          <p className="font-semibold">{source.name} <span className="font-normal">· {source.network}</span></p>
          <p>Credencial {statusLabels[source.status].toLowerCase()} · {source.connection_count} conexões armazenadas</p>
          <p>Último envio {source.last_received_at ? formatDateTime(source.last_received_at) : "aguardando dados"}</p>
          {source.latest_observed_at && <p>Último evento {formatDateTime(source.latest_observed_at)}</p>}
          {canManage && source.status === "ACTIVE" && (
            <Button
              size="sm"
              variant="outline"
              disabled={revoke.isPending}
              onClick={() => revoke.mutate(source.id)}
              aria-label={`Revogar credencial de ${source.name}`}
            >
              Revogar credencial
            </Button>
          )}
        </div>
      ))}
      {revoke.isError && <p role="alert">{errorMessage(revoke.error)}</p>}
      {canManage && authorized && (
        <form
          className="flex flex-wrap items-start gap-2"
          aria-label="Cadastrar fonte de telemetria"
          onSubmit={form.handleSubmit((values) => create.mutate(values))}
        >
          <label>
            Nome da fonte
            <input className={inputClass} {...form.register("name")} />
            {form.formState.errors.name && <span role="alert" className="block">{form.formState.errors.name.message}</span>}
          </label>
          <label>
            Segmento autorizado
            <input className={inputClass} placeholder="192.168.50.0/24" {...form.register("network")} />
            {form.formState.errors.network && (
              <span role="alert" className="block">{form.formState.errors.network.message}</span>
            )}
          </label>
          <Button size="sm" type="submit" className="mt-4" disabled={create.isPending}>Cadastrar fonte</Button>
          {create.isError && <p role="alert">{errorMessage(create.error)}</p>}
        </form>
      )}
      {created && (
        <div className="space-y-1 rounded border border-slate-200 p-2 dark:border-slate-800">
          <p>Guarde a credencial da instalação. Ela aparece apenas após o cadastro.</p>
          <p>Identificador da fonte <code>{created.id}</code></p>
          <label>
            Credencial da fonte
            <input className={`${inputClass} font-mono`} readOnly value={created.collector_token}
              onFocus={(event) => event.target.select()} />
          </label>
          <Button size="sm" variant="outline" onClick={() => setCreated(null)}>Ocultar credencial</Button>
        </div>
      )}
    </section>
  );
}
