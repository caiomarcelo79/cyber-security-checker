"use client";

import React, { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { GitCompare } from "lucide-react";

import {
  type AssetResponse,
  fetchScanEvents,
  fetchScansPage,
  type ScanFilters,
  type ScanResponse,
} from "@/lib/api";
import {
  ACTIVE_SCAN_STATUSES,
  canManageScans,
  dayEndIso,
  dayStartIso,
  errorMessage,
  formatDateTime,
  formatDuration,
  SCAN_STATUS_LABEL,
  totalPages,
} from "@/lib/soc-utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export const SCANS_PAGE_SIZE = 10;

export interface ScanUiFilters {
  search: string;
  asset_id: string;
  status: string;
  date_from: string;
  date_to: string;
  sort_desc: boolean;
}

export const EMPTY_SCAN_FILTERS: ScanUiFilters = {
  search: "",
  asset_id: "",
  status: "",
  date_from: "",
  date_to: "",
  sort_desc: true,
};

export function toScanApiFilters(f: ScanUiFilters, page: number): ScanFilters {
  return {
    search: f.search.trim() || undefined,
    asset_id: f.asset_id || undefined,
    status: f.status || undefined,
    date_from: dayStartIso(f.date_from),
    date_to: dayEndIso(f.date_to),
    sort_by: "created_at",
    sort_desc: f.sort_desc,
    limit: SCANS_PAGE_SIZE,
    offset: (page - 1) * SCANS_PAGE_SIZE,
  };
}

/** Intervalo adaptativo: só consulta enquanto houver auditorias ativas na página visível. */
export function scansPollInterval(items: ScanResponse[] | undefined): number | false {
  const active = (items ?? []).some((s) => ACTIVE_SCAN_STATUSES.includes(s.status));
  return active ? 3000 : false;
}

export function countFindings(summary: Record<string, number>): number {
  return Object.values(summary ?? {}).reduce((a, b) => a + (Number(b) || 0), 0);
}

const inputClass =
  "h-8 rounded-md border border-slate-300 bg-transparent px-2 text-xs dark:border-slate-700";

interface ScansHistoryPanelProps {
  token: string;
  role?: string | null;
  assets: AssetResponse[];
  selectedScanId: string | null;
  onSelect: (scanId: string) => void;
  onCancel: (scanId: string) => void;
  onCompare?: (scanAId: string, scanBId: string) => void;
}

export function ScansHistoryPanel({
  token,
  role,
  assets,
  selectedScanId,
  onSelect,
  onCancel,
  onCompare,
}: ScansHistoryPanelProps) {
  const [filters, setFilters] = useState<ScanUiFilters>(EMPTY_SCAN_FILTERS);
  const [debouncedSearch, setDebouncedSearch] = useState("");
  const [page, setPage] = useState(1);
  const [selectedForComparison, setSelectedForComparison] = useState<string[]>([]);

  useEffect(() => {
    const t = setTimeout(() => setDebouncedSearch(filters.search), 350);
    return () => clearTimeout(t);
  }, [filters.search]);

  const effective = useMemo(
    () => ({ ...filters, search: debouncedSearch }),
    [filters, debouncedSearch]
  );

  const query = useQuery({
    queryKey: ["scans-page", token, effective, page],
    queryFn: () => fetchScansPage(token, toScanApiFilters(effective, page)),
    placeholderData: (prev) => prev,
    refetchInterval: (q) => scansPollInterval(q.state.data?.items),
  });

  function update<K extends keyof ScanUiFilters>(key: K, value: ScanUiFilters[K]) {
    setFilters((f) => ({ ...f, [key]: value }));
    setPage(1);
  }

  const data = query.data;
  const pages = data ? totalPages(data.total, data.limit) : 1;
  const allowCancel = canManageScans(role);

  return (
    <Card>
      <CardHeader>
        <CardTitle>Histórico de auditorias</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3 text-xs">
        <div className="grid grid-cols-2 gap-2 md:grid-cols-3" role="search" aria-label="Filtros de auditorias">
          <input aria-label="Buscar auditorias" placeholder="Buscar ID, ativo, perfil…" className={inputClass} value={filters.search} onChange={(e) => update("search", e.target.value)} maxLength={120} />
          <select aria-label="Filtrar auditorias por ativo" className={inputClass} value={filters.asset_id} onChange={(e) => update("asset_id", e.target.value)}>
            <option value="">Todos os ativos</option>
            {assets.map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}
          </select>
          <select aria-label="Filtrar auditorias por estado" className={inputClass} value={filters.status} onChange={(e) => update("status", e.target.value)}>
            <option value="">Todos os estados</option>
            {Object.entries(SCAN_STATUS_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          </select>
          <label className="flex items-center gap-1">De <input type="date" aria-label="Auditorias a partir de" className={inputClass} value={filters.date_from} onChange={(e) => update("date_from", e.target.value)} /></label>
          <label className="flex items-center gap-1">Até <input type="date" aria-label="Auditorias até" className={inputClass} value={filters.date_to} onChange={(e) => update("date_to", e.target.value)} /></label>
          <select aria-label="Ordenar auditorias por data" className={inputClass} value={filters.sort_desc ? "desc" : "asc"} onChange={(e) => update("sort_desc", e.target.value === "desc")}>
            <option value="desc">Mais recentes primeiro</option>
            <option value="asc">Mais antigas primeiro</option>
          </select>
        </div>

        {selectedForComparison.length > 0 && (
          <div className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-sky-500/30 bg-sky-500/10 p-2.5">
            <div className="flex items-center gap-2">
              <GitCompare className="h-4 w-4 text-sky-500" />
              <span className="font-medium">
                {selectedForComparison.length} auditoria(s) selecionada(s) para comparação
              </span>
              <span className="text-slate-500">
                (Selecione 2 auditorias do mesmo ativo)
              </span>
            </div>
            <div className="flex items-center gap-2">
              {selectedForComparison.length === 2 && onCompare && (
                <Button
                  size="sm"
                  onClick={() => onCompare(selectedForComparison[0], selectedForComparison[1])}
                >
                  Comparar Auditorias
                </Button>
              )}
              <Button
                size="sm"
                variant="outline"
                onClick={() => setSelectedForComparison([])}
              >
                Limpar Seleção
              </Button>
            </div>
          </div>
        )}

        {query.isLoading ? (
          <p role="status" className="text-slate-500">Carregando auditorias…</p>
        ) : query.isError ? (
          <p role="alert" className="text-red-500">{errorMessage(query.error)}</p>
        ) : !data || data.total === 0 ? (
          <p className="text-slate-500" data-testid="scans-empty">Nenhuma auditoria encontrada. Inicie uma auditoria em um ativo com autorização verificada.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead className="text-slate-500">
                <tr>
                  <th className="py-1 pr-2 w-8 text-center" title="Selecionar para comparação">Comp.</th>
                  <th className="py-1 pr-2">ID</th>
                  <th className="pr-2">Ativo</th>
                  <th className="pr-2">Perfil</th>
                  <th className="pr-2">Criada em</th>
                  <th className="pr-2">Estado</th>
                  <th className="pr-2">Progresso</th>
                  <th className="pr-2">Duração</th>
                  <th className="pr-2">Descobertas</th>
                  <th>Ações</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((s) => {
                  const active = ACTIVE_SCAN_STATUSES.includes(s.status);
                  return (
                    <tr key={s.id} className={`border-t border-slate-200 dark:border-slate-800 ${selectedScanId === s.id ? "bg-sky-500/5" : ""}`}>
                      <td className="py-2 pr-2 text-center">
                        <input
                          type="checkbox"
                          aria-label={`Comparar auditoria ${s.id.slice(0, 8)}`}
                          checked={selectedForComparison.includes(s.id)}
                          onChange={(e) => {
                            if (e.target.checked) {
                              if (selectedForComparison.length >= 2) {
                                setSelectedForComparison([selectedForComparison[1], s.id]);
                              } else {
                                setSelectedForComparison([...selectedForComparison, s.id]);
                              }
                            } else {
                              setSelectedForComparison(selectedForComparison.filter((id) => id !== s.id));
                            }
                          }}
                        />
                      </td>
                      <td className="py-2 pr-2 font-mono">{s.id.slice(0, 8)}</td>
                      <td className="pr-2">{s.asset_name ?? s.asset_id}</td>
                      <td className="pr-2">{s.profile_type}</td>
                      <td className="pr-2">{formatDateTime(s.created_at)}</td>
                      <td className="pr-2"><Badge variant={s.status === "FAILED" ? "critical" : s.status === "COMPLETED" ? "success" : "outline"}>{SCAN_STATUS_LABEL[s.status] ?? s.status}</Badge></td>
                      <td className="pr-2">
                        <progress aria-label={`Progresso da auditoria ${s.id.slice(0, 8)}`} className="h-2 w-20" value={s.progress_percent} max={100} /> {s.progress_percent}%
                      </td>
                      <td className="pr-2">{formatDuration(s.elapsed_seconds)}</td>
                      <td className="pr-2">{countFindings(s.findings_summary)}</td>
                      <td className="space-x-1 whitespace-nowrap">
                        <Button size="sm" variant="secondary" onClick={() => onSelect(s.id)}>Detalhes</Button>
                        {active && allowCancel && (
                          <Button size="sm" variant="outline" onClick={() => onCancel(s.id)}>Cancelar</Button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {data && data.total > 0 && (
          <nav aria-label="Paginação de auditorias" className="flex items-center justify-between">
            <span data-testid="scans-total">{data.total} auditoria(s) · página {page} de {pages}</span>
            <span className="space-x-2">
              <Button size="sm" variant="outline" disabled={page <= 1} onClick={() => setPage((p) => Math.max(1, p - 1))}>Anterior</Button>
              <Button size="sm" variant="outline" disabled={page >= pages} onClick={() => setPage((p) => p + 1)}>Próxima</Button>
            </span>
          </nav>
        )}
      </CardContent>
    </Card>
  );
}

const ACTION_LABEL: Record<string, string> = {
  SCAN_CREATED: "Auditoria criada e enfileirada",
  SCAN_CANCELLED: "Cancelamento solicitado",
  SCAN_BLOCKED_UNVERIFIED_ASSET: "Bloqueada: ativo sem autorização verificada",
};

export function ScanEventsCard({ token, scanId }: { token: string; scanId: string }) {
  const q = useQuery({
    queryKey: ["scan-events", token, scanId],
    queryFn: () => fetchScanEvents(token, scanId),
  });
  return (
    <Card>
      <CardHeader><CardTitle className="text-sm">Histórico de eventos</CardTitle></CardHeader>
      <CardContent className="space-y-1 text-xs">
        {q.isLoading ? (
          <p>Carregando eventos…</p>
        ) : q.isError ? (
          <p role="alert" className="text-red-500">{errorMessage(q.error)}</p>
        ) : (q.data ?? []).length === 0 ? (
          <p className="text-slate-500">Nenhum evento registrado para esta auditoria.</p>
        ) : (
          q.data!.map((e) => (
            <p key={e.id}>{formatDateTime(e.created_at)} · {ACTION_LABEL[e.action] ?? e.action}</p>
          ))
        )}
      </CardContent>
    </Card>
  );
}
