"use client";

import React, { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import {
  type AssetResponse,
  type FindingFilters,
  type FindingResponse,
  fetchFinding,
  fetchFindingHistory,
  fetchFindingsPage,
  revalidateFinding,
  type RevalidationResponse,
  updateFindingStatus,
} from "@/lib/api";
import {
  canTriage,
  CLASSIFICATION_LABEL,
  CONFIDENCE_LABEL,
  dayEndIso,
  dayStartIso,
  errorMessage,
  formatDateTime,
  PRIORITY_LABEL,
  SEVERITY_LABEL,
  SEVERITY_ORDER,
  severityVariant,
  totalPages,
  TREATMENT_LABEL,
  TREATMENT_OPTIONS,
} from "@/lib/soc-utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export const FINDINGS_PAGE_SIZE = 15;
const NOTE_REQUIRED_STATUSES = ["FALSE_POSITIVE", "ACCEPTED_RISK"];

export interface FindingUiFilters {
  search: string;
  severity: string;
  treatment_status: string;
  confidence: string;
  asset_id: string;
  category: string;
  module_id: string;
  date_from: string;
  date_to: string;
  sort_by: string;
  sort_desc: boolean;
}

export const EMPTY_FINDING_FILTERS: FindingUiFilters = {
  search: "",
  severity: "",
  treatment_status: "",
  confidence: "",
  asset_id: "",
  category: "",
  module_id: "",
  date_from: "",
  date_to: "",
  sort_by: "severity",
  sort_desc: true,
};

/** Converte filtros de UI + página em parâmetros da API (filtragem/ordenação no servidor). */
export function toApiFilters(f: FindingUiFilters, page: number): FindingFilters {
  return {
    search: f.search.trim() || undefined,
    severity: f.severity || undefined,
    treatment_status: f.treatment_status || undefined,
    confidence: f.confidence || undefined,
    asset_id: f.asset_id || undefined,
    category: f.category.trim() || undefined,
    module_id: f.module_id.trim() || undefined,
    date_from: dayStartIso(f.date_from),
    date_to: dayEndIso(f.date_to),
    sort_by: f.sort_by,
    sort_desc: f.sort_desc,
    limit: FINDINGS_PAGE_SIZE,
    offset: (page - 1) * FINDINGS_PAGE_SIZE,
  };
}

export function validateTriage(
  status: string,
  note: string,
  riskAcceptanceReason?: string
): string | null {
  if (!TREATMENT_OPTIONS.includes(status)) return "Selecione um estado válido.";
  if (status === "ACCEPTED_RISK") {
    const reason = (riskAcceptanceReason?.trim() || note.trim());
    if (reason.length < 5) {
      return "Informe uma justificativa formal (mínimo de 5 caracteres) para aceitação do risco.";
    }
  } else if (NOTE_REQUIRED_STATUSES.includes(status) && note.trim().length < 5) {
    return "Informe uma justificativa (mínimo de 5 caracteres) para este estado.";
  }
  if (note.length > 1000) return "A justificativa excede 1000 caracteres.";
  return null;
}

function useDebounced<T>(value: T, delayMs: number): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setDebounced(value), delayMs);
    return () => clearTimeout(t);
  }, [value, delayMs]);
  return debounced;
}

interface VulnerabilitiesPanelProps {
  token: string;
  role?: string | null;
  assets: AssetResponse[];
  initialAssetId?: string;
  initialSeverity?: string;
}

const inputClass =
  "h-8 rounded-md border border-slate-300 bg-transparent px-2 text-xs dark:border-slate-700";

export function VulnerabilitiesPanel({
  token,
  role,
  assets,
  initialAssetId,
  initialSeverity,
}: VulnerabilitiesPanelProps) {
  const [filters, setFilters] = useState<FindingUiFilters>({
    ...EMPTY_FINDING_FILTERS,
    asset_id: initialAssetId ?? "",
    severity: initialSeverity ?? "",
  });
  const [page, setPage] = useState(1);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  useEffect(() => {
    if (initialAssetId !== undefined) {
      setFilters((f) => ({ ...f, asset_id: initialAssetId }));
      setPage(1);
    }
  }, [initialAssetId]);

  const debouncedSearch = useDebounced(filters.search, 350);
  const effective = useMemo(
    () => ({ ...filters, search: debouncedSearch }),
    [filters, debouncedSearch]
  );

  const listQuery = useQuery({
    queryKey: ["findings-page", token, effective, page],
    queryFn: () => fetchFindingsPage(token, toApiFilters(effective, page)),
    placeholderData: (prev) => prev,
  });

  function update<K extends keyof FindingUiFilters>(key: K, value: FindingUiFilters[K]) {
    setFilters((f) => ({ ...f, [key]: value }));
    setPage(1);
  }

  const data = listQuery.data;
  const pages = data ? totalPages(data.total, data.limit) : 1;

  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,28rem)]">
      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Gestão de vulnerabilidades</CardTitle>
          <p className="text-xs text-slate-500">
            Exibe a detecção mais recente de cada vulnerabilidade por ativo (sem duplicar
            entre auditorias). O estado de triagem é administrativo e independe do resultado
            técnico do scanner.
          </p>
        </CardHeader>
        <CardContent className="space-y-3">
          <div
            className="grid grid-cols-2 gap-2 md:grid-cols-4"
            role="search"
            aria-label="Filtros de vulnerabilidades"
          >
            <input
              aria-label="Buscar vulnerabilidades"
              placeholder="Buscar título, endpoint, check…"
              className={`${inputClass} col-span-2`}
              value={filters.search}
              onChange={(e) => update("search", e.target.value)}
              maxLength={120}
            />
            <select aria-label="Filtrar por severidade" className={inputClass} value={filters.severity} onChange={(e) => update("severity", e.target.value)}>
              <option value="">Todas as severidades</option>
              {SEVERITY_ORDER.map((s) => (
                <option key={s} value={s}>{SEVERITY_LABEL[s]}</option>
              ))}
            </select>
            <select aria-label="Filtrar por estado" className={inputClass} value={filters.treatment_status} onChange={(e) => update("treatment_status", e.target.value)}>
              <option value="">Todos os estados</option>
              {TREATMENT_OPTIONS.map((s) => (
                <option key={s} value={s}>{TREATMENT_LABEL[s]}</option>
              ))}
            </select>
            <select aria-label="Filtrar por confiança" className={inputClass} value={filters.confidence} onChange={(e) => update("confidence", e.target.value)}>
              <option value="">Toda confiança</option>
              {Object.entries(CONFIDENCE_LABEL).map(([k, v]) => (
                <option key={k} value={k}>{v}</option>
              ))}
            </select>
            <select aria-label="Filtrar por ativo" className={inputClass} value={filters.asset_id} onChange={(e) => update("asset_id", e.target.value)}>
              <option value="">Todos os ativos</option>
              {assets.map((a) => (
                <option key={a.id} value={a.id}>{a.name}</option>
              ))}
            </select>
            <input aria-label="Filtrar por categoria" placeholder="Categoria" className={inputClass} value={filters.category} onChange={(e) => update("category", e.target.value)} />
            <input aria-label="Filtrar por módulo" placeholder="Módulo (ex.: http_headers)" className={inputClass} value={filters.module_id} onChange={(e) => update("module_id", e.target.value)} />
            <label className="flex items-center gap-1 text-xs">
              De
              <input type="date" aria-label="Período inicial" className={inputClass} value={filters.date_from} onChange={(e) => update("date_from", e.target.value)} />
            </label>
            <label className="flex items-center gap-1 text-xs">
              Até
              <input type="date" aria-label="Período final" className={inputClass} value={filters.date_to} onChange={(e) => update("date_to", e.target.value)} />
            </label>
            <select aria-label="Ordenar por" className={inputClass} value={`${filters.sort_by}:${filters.sort_desc ? "desc" : "asc"}`} onChange={(e) => {
              const [by, dir] = e.target.value.split(":");
              setFilters((f) => ({ ...f, sort_by: by, sort_desc: dir === "desc" }));
              setPage(1);
            }}>
              <option value="severity:desc">Severidade (maior primeiro)</option>
              <option value="last_confirmed_at:desc">Última detecção (recente)</option>
              <option value="last_confirmed_at:asc">Última detecção (antiga)</option>
              <option value="first_detected_at:desc">Primeira detecção (recente)</option>
              <option value="first_detected_at:asc">Primeira detecção (antiga)</option>
              <option value="title:asc">Título (A–Z)</option>
            </select>
            <Button size="sm" variant="outline" onClick={() => { setFilters(EMPTY_FINDING_FILTERS); setPage(1); }}>
              Limpar filtros
            </Button>
          </div>

          {listQuery.isLoading ? (
            <p role="status" className="text-xs text-slate-500">Carregando vulnerabilidades…</p>
          ) : listQuery.isError ? (
            <p role="alert" className="text-xs text-red-500">{errorMessage(listQuery.error)}</p>
          ) : !data || data.total === 0 ? (
            <p className="text-xs text-slate-500" data-testid="findings-empty">
              Nenhuma vulnerabilidade encontrada para os filtros atuais. Isso não comprova a
              inexistência de falhas: execute uma auditoria em um ativo autorizado.
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="text-slate-500">
                  <tr>
                    <th className="py-1 pr-2">Título</th>
                    <th className="pr-2">Severidade</th>
                    <th className="pr-2">Confiança</th>
                    <th className="pr-2">Ativo</th>
                    <th className="pr-2">Categoria</th>
                    <th className="pr-2">Triagem</th>
                    <th className="pr-2">1ª detecção</th>
                    <th className="pr-2">Última detecção</th>
                    <th><span className="sr-only">Ações</span></th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((f) => (
                    <tr key={f.id} className={`border-t border-slate-200 dark:border-slate-800 ${selectedId === f.id ? "bg-sky-500/5" : ""}`}>
                      <td className="py-2 pr-2 font-medium">{f.title}</td>
                      <td className="pr-2"><Badge variant={severityVariant(f.severity)}>{SEVERITY_LABEL[f.severity] ?? f.severity}</Badge></td>
                      <td className="pr-2">{CONFIDENCE_LABEL[f.confidence] ?? f.confidence}</td>
                      <td className="pr-2">{f.asset_name ?? f.asset_id}</td>
                      <td className="pr-2">{f.category}</td>
                      <td className="pr-2"><Badge variant="outline">{TREATMENT_LABEL[f.treatment_status] ?? f.treatment_status}</Badge></td>
                      <td className="pr-2">{formatDateTime(f.first_detected_at)}</td>
                      <td className="pr-2">{formatDateTime(f.last_confirmed_at)}</td>
                      <td>
                        <Button size="sm" variant="secondary" aria-label={`Ver detalhes de ${f.title}`} onClick={() => setSelectedId(f.id)}>
                          Detalhes
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {data && data.total > 0 && (
            <nav aria-label="Paginação" className="flex items-center justify-between text-xs">
              <span data-testid="findings-total">{data.total} resultado(s) · página {page} de {pages}</span>
              <span className="space-x-2">
                <Button size="sm" variant="outline" disabled={page <= 1} onClick={() => setPage((p) => Math.max(1, p - 1))}>Anterior</Button>
                <Button size="sm" variant="outline" disabled={page >= pages} onClick={() => setPage((p) => p + 1)}>Próxima</Button>
              </span>
            </nav>
          )}
        </CardContent>
      </Card>

      {selectedId ? (
        <FindingDetailPanel
          token={token}
          findingId={selectedId}
          role={role}
          onClose={() => setSelectedId(null)}
          onNavigate={setSelectedId}
        />
      ) : (
        <Card>
          <CardContent className="p-4 text-xs text-slate-500">
            Selecione uma vulnerabilidade para ver evidências, recomendações, validação da
            correção e histórico.
          </CardContent>
        </Card>
      )}
    </div>
  );
}

export function EvidenceView({ evidence }: { evidence: FindingResponse["evidence"] }) {
  // Todo conteúdo é renderizado como texto (escapado pelo React); nunca como HTML.
  const rows: [string, string | undefined][] = [
    ["Requisição", evidence.request_method && evidence.request_url ? `${evidence.request_method} ${evidence.request_url}` : undefined],
    ["Status HTTP", evidence.response_status_code != null ? String(evidence.response_status_code) : undefined],
    ["Valor observado", evidence.observed_value ?? undefined],
    ["Linha de base esperada", evidence.expected_baseline ?? undefined],
  ];
  const headers = evidence.response_headers ?? {};
  return (
    <div className="space-y-2" data-testid="evidence-view">
      {rows.filter(([, v]) => v).map(([k, v]) => (
        <div key={k}>
          <span className="font-semibold">{k}: </span>
          <span className="break-all font-mono">{v}</span>
        </div>
      ))}
      {Object.keys(headers).length > 0 && (
        <pre className="overflow-x-auto rounded-md bg-slate-100 p-2 font-mono dark:bg-slate-900">
          {Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join("\n")}
        </pre>
      )}
      {(evidence.technical_notes ?? []).length > 0 && (
        <ul className="list-disc pl-4">
          {evidence.technical_notes!.map((n, i) => <li key={i}>{n}</li>)}
        </ul>
      )}
      {(evidence.redacted_fields_count ?? 0) > 0 && (
        <p className="text-slate-500">
          {evidence.redacted_fields_count} campo(s) sensível(is) mascarado(s) antes da persistência.
        </p>
      )}
    </div>
  );
}

function FindingDetailPanel({
  token,
  findingId,
  role,
  onClose,
}: {
  token: string;
  findingId: string;
  role?: string | null;
  onClose: () => void;
  onNavigate: (id: string) => void;
}) {
  const queryClient = useQueryClient();
  const findingQuery = useQuery({
    queryKey: ["finding", token, findingId],
    queryFn: () => fetchFinding(token, findingId),
  });
  const historyQuery = useQuery({
    queryKey: ["finding-history", token, findingId],
    queryFn: () => fetchFindingHistory(token, findingId),
  });

  const [status, setStatus] = useState("");
  const [note, setNote] = useState("");
  const [priority, setPriority] = useState("");
  const [slaDeadline, setSlaDeadline] = useState("");
  const [riskReason, setRiskReason] = useState("");
  const [formError, setFormError] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<string | null>(null);
  const [revalidating, setRevalidating] = useState(false);
  const [revalFeedback, setRevalFeedback] = useState<string | null>(null);

  const f = findingQuery.data;
  useEffect(() => {
    if (f) {
      setStatus(f.treatment_status);
      setNote(f.triage_note ?? "");
      setPriority(f.priority ?? "");
      setSlaDeadline(f.sla_deadline ? f.sla_deadline.slice(0, 10) : "");
      setRiskReason(f.risk_acceptance_reason ?? "");
      setFeedback(null);
      setFormError(null);
      setRevalFeedback(null);
    }
  }, [f?.id, f?.treatment_status]); // eslint-disable-line react-hooks/exhaustive-deps

  const mutation = useMutation({
    mutationFn: () => {
      const payload: {
        treatment_status: string;
        triage_note?: string | null;
        priority?: string | null;
        sla_deadline?: string | null;
        risk_acceptance_reason?: string | null;
      } = {
        treatment_status: status,
        triage_note: note.trim() || null,
      };
      if (priority) {
        payload.priority = priority;
      }
      if (slaDeadline) {
        payload.sla_deadline = new Date(slaDeadline).toISOString();
      }
      if (status === "ACCEPTED_RISK" && (riskReason.trim() || note.trim())) {
        payload.risk_acceptance_reason = riskReason.trim() || note.trim();
      }
      return updateFindingStatus(token, findingId, payload);
    },
    onSuccess: () => {
      setFeedback("Triagem registrada com sucesso.");
      void queryClient.invalidateQueries({ queryKey: ["findings-page"] });
      void queryClient.invalidateQueries({ queryKey: ["finding", token, findingId] });
      void queryClient.invalidateQueries({ queryKey: ["finding-history", token, findingId] });
      void queryClient.invalidateQueries({ queryKey: ["dashboard-summary"] });
      void queryClient.invalidateQueries({ queryKey: ["dashboard-trends"] });
      void queryClient.invalidateQueries({ queryKey: ["dashboard-evolution"] });
      void queryClient.invalidateQueries({ queryKey: ["org-assets"] });
    },
    onError: (e) => setFeedback(errorMessage(e)),
  });

  const handleRevalidation = async () => {
    setRevalidating(true);
    setRevalFeedback(null);
    try {
      const res = await revalidateFinding(token, findingId, {
        triage_note: note.trim() || undefined,
      });
      setRevalFeedback(
        `Revalidação finalizada: ${TREATMENT_LABEL[res.new_status] ?? res.new_status} — ${res.message}`
      );
      void queryClient.invalidateQueries({ queryKey: ["findings-page"] });
      void queryClient.invalidateQueries({ queryKey: ["finding", token, findingId] });
      void queryClient.invalidateQueries({ queryKey: ["finding-history", token, findingId] });
      void queryClient.invalidateQueries({ queryKey: ["dashboard-summary"] });
    } catch (err) {
      setRevalFeedback(`Falha na revalidação: ${errorMessage(err)}`);
    } finally {
      setRevalidating(false);
    }
  };

  if (findingQuery.isLoading) return <p role="status" className="text-xs">Carregando detalhes…</p>;
  if (findingQuery.isError || !f) {
    return <p role="alert" className="text-xs text-red-500">{errorMessage(findingQuery.error)}</p>;
  }

  const rem = f.remediation_data;
  const triageAllowed = canTriage(role);

  return (
    <Card aria-label="Detalhes da vulnerabilidade">
      <CardHeader>
        <div className="flex items-start justify-between gap-2">
          <CardTitle className="text-sm">{f.title}</CardTitle>
          <Button size="sm" variant="outline" onClick={onClose}>Fechar</Button>
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          <Badge variant={severityVariant(f.severity)}>{SEVERITY_LABEL[f.severity] ?? f.severity}</Badge>
          <Badge variant="outline">{TREATMENT_LABEL[f.treatment_status] ?? f.treatment_status}</Badge>
          {f.priority && (
            <Badge variant="outline">
              {PRIORITY_LABEL[f.priority] ?? f.priority}
            </Badge>
          )}
          <Badge variant={f.result_classification === "VULNERABILITY" ? "critical" : "warning"}>
            {CLASSIFICATION_LABEL[f.result_classification] ?? f.result_classification}
          </Badge>
          {f.revalidation_scan_id && (
            <Badge variant="outline" className="font-mono text-emerald-500">
              Revalidado: {f.revalidation_scan_id.slice(0, 8)}
            </Badge>
          )}
        </div>
      </CardHeader>
      <CardContent className="space-y-4 text-xs">
        {f.result_classification === "POTENTIAL_VULNERABILITY" && (
          <p role="note" className="rounded-md border border-amber-500/30 bg-amber-500/10 p-2">
            Indício técnico que requer confirmação manual. Não é uma vulnerabilidade confirmada.
          </p>
        )}
        <section>
          <h4 className="font-bold">Ativo e endpoint</h4>
          <p>{f.asset_name ?? f.asset_id}</p>
          <p className="break-all font-mono">{f.affected_endpoint}</p>
        </section>
        <section><h4 className="font-bold">Descrição</h4><p>{f.description}</p></section>
        <section><h4 className="font-bold">Evidência técnica (sanitizada)</h4><EvidenceView evidence={f.evidence} /></section>
        <section><h4 className="font-bold">Impacto potencial</h4><p>{f.impact}</p></section>
        {f.sla_deadline && (
          <section>
            <h4 className="font-bold">Prazo de SLA de Remediação</h4>
            <p className="text-amber-500 font-semibold">{formatDateTime(f.sla_deadline)}</p>
          </section>
        )}
        {f.risk_acceptance_reason && (
          <section>
            <h4 className="font-bold">Justificativa de Risco Aceito</h4>
            <p className="italic text-slate-400">{f.risk_acceptance_reason}</p>
          </section>
        )}
        <section>
          <h4 className="font-bold">Confiança e origem</h4>
          <p>{CONFIDENCE_LABEL[f.confidence] ?? f.confidence} · módulo <code>{f.module_id}</code> · verificação <code>{f.check_id}</code></p>
          <p className="text-slate-500">{rem.how_it_was_detected}</p>
        </section>
        <section>
          <h4 className="font-bold">Referências</h4>
          <p>{[...f.cwe_ids, ...f.owasp_categories].join(" · ") || "Sem referências associadas."}</p>
          {f.cvss_v4_score != null && (
            <p>CVSS 4.0: {f.cvss_v4_score} ({f.cvss_v4_vector})</p>
          )}
          {(rem.references ?? []).length > 0 && (
            <ul className="list-disc pl-4">{rem.references.map((r, i) => <li key={i} className="break-all">{r}</li>)}</ul>
          )}
        </section>
        <section><h4 className="font-bold">Como corrigir</h4><p>{rem.how_to_fix}</p></section>
        <section>
          <h4 className="font-bold">Como validar a correção</h4>
          <p>{rem.how_to_validate}</p>
          {f.reproduction_steps.length > 0 && (
            <ol className="list-decimal pl-4">{f.reproduction_steps.map((s, i) => <li key={i}>{s}</li>)}</ol>
          )}
          <p className="text-slate-500">Após corrigir, execute uma nova auditoria para confirmar.</p>
        </section>

        <section aria-label="Triagem">
          <h4 className="font-bold">Triagem & Remediação</h4>
          {triageAllowed ? (
            <form
              className="space-y-3"
              onSubmit={(e) => {
                e.preventDefault();
                const err = validateTriage(status, note, riskReason);
                setFormError(err);
                if (!err) mutation.mutate();
              }}
            >
              <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
                <div>
                  <label className="block text-[11px] font-medium text-slate-500 mb-1">
                    Estado Administrativo
                  </label>
                  <select
                    aria-label="Estado de triagem"
                    className={`${inputClass} w-full`}
                    value={status}
                    onChange={(e) => setStatus(e.target.value)}
                  >
                    {TREATMENT_OPTIONS.map((s) => (
                      <option key={s} value={s}>
                        {TREATMENT_LABEL[s]}
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="block text-[11px] font-medium text-slate-500 mb-1">
                    Prioridade de Correção
                  </label>
                  <select
                    aria-label="Prioridade de correção"
                    className={`${inputClass} w-full`}
                    value={priority}
                    onChange={(e) => setPriority(e.target.value)}
                  >
                    <option value="">Não definida</option>
                    {Object.entries(PRIORITY_LABEL).map(([code, label]) => (
                      <option key={code} value={code}>
                        {label}
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="block text-[11px] font-medium text-slate-500 mb-1">
                    Prazo Limite de SLA
                  </label>
                  <input
                    type="date"
                    aria-label="Prazo de SLA"
                    className={`${inputClass} w-full`}
                    value={slaDeadline}
                    onChange={(e) => setSlaDeadline(e.target.value)}
                  />
                </div>
              </div>

              {status === "ACCEPTED_RISK" && (
                <div>
                  <label className="block text-[11px] font-medium text-amber-500 mb-1">
                    Justificativa Formal para Aceitação de Risco (Obrigatória)
                  </label>
                  <textarea
                    aria-label="Justificativa formal para aceitação de risco"
                    className="w-full rounded-md border border-amber-500/40 bg-amber-500/5 p-2 text-xs"
                    rows={2}
                    maxLength={2000}
                    value={riskReason}
                    onChange={(e) => setRiskReason(e.target.value)}
                    placeholder="Descreva o contexto do negócio, controles compensatórios e aprovação formal do risco."
                  />
                </div>
              )}

              <div>
                <label className="block text-[11px] font-medium text-slate-500 mb-1">
                  Notas Técnicas de Tratamento
                </label>
                <textarea
                  aria-label="Justificativa da triagem"
                  className="w-full rounded-md border border-slate-300 bg-transparent p-2 text-xs dark:border-slate-700"
                  rows={2}
                  maxLength={1000}
                  value={note}
                  onChange={(e) => setNote(e.target.value)}
                  placeholder="Justificativa técnica ou notas sobre o andamento da correção…"
                />
              </div>

              {formError && <p role="alert" className="text-red-500">{formError}</p>}

              <div className="flex flex-wrap items-center gap-2">
                <Button size="sm" type="submit" disabled={mutation.isPending}>
                  {mutation.isPending ? "Salvando…" : "Registrar triagem"}
                </Button>

                <Button
                  size="sm"
                  type="button"
                  variant="secondary"
                  disabled={revalidating || mutation.isPending}
                  onClick={handleRevalidation}
                >
                  {revalidating ? "Executando teste no alvo…" : "Solicitar Revalidação Técnica"}
                </Button>
              </div>
            </form>
          ) : (
            <p className="text-slate-500">Seu perfil (somente leitura) não permite alterar a triagem.</p>
          )}
          {feedback && <p role="status" className="mt-1 text-sky-500">{feedback}</p>}
          {revalFeedback && <p role="status" className="mt-1 font-semibold">{revalFeedback}</p>}
        </section>

        <section aria-label="Histórico">
          <h4 className="font-bold">Histórico</h4>
          {historyQuery.isLoading ? (
            <p>Carregando histórico…</p>
          ) : historyQuery.isError ? (
            <p role="alert" className="text-red-500">{errorMessage(historyQuery.error)}</p>
          ) : (
            <>
              <p className="font-semibold">Detecções ({historyQuery.data?.detections.length ?? 0})</p>
              <ul className="space-y-1">
                {(historyQuery.data?.detections ?? []).map((d) => (
                  <li key={d.finding_id}>{formatDateTime(d.detected_at)} · auditoria <code>{d.scan_id.slice(0, 8)}</code> · {SEVERITY_LABEL[d.severity] ?? d.severity}</li>
                ))}
              </ul>
              <p className="mt-2 font-semibold">Eventos de triagem ({historyQuery.data?.triage_events.length ?? 0})</p>
              {(historyQuery.data?.triage_events ?? []).length === 0 ? (
                <p className="text-slate-500">Nenhuma alteração de triagem registrada.</p>
              ) : (
                <ul className="space-y-1">
                  {historyQuery.data!.triage_events.map((e) => (
                    <li key={e.id}>
                      {formatDateTime(e.created_at)} · {TREATMENT_LABEL[e.previous_status ?? ""] ?? e.previous_status} → <strong>{TREATMENT_LABEL[e.new_status ?? ""] ?? e.new_status}</strong>
                      {e.triage_note ? ` — ${e.triage_note}` : ""}
                    </li>
                  ))}
                </ul>
              )}
            </>
          )}
        </section>
      </CardContent>
    </Card>
  );
}
