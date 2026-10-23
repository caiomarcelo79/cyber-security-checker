"use client";

import React, { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertCircle,
  CheckCircle2,
  Clock,
  Copy,
  Download,
  FileSpreadsheet,
  FileText,
  GitCompare,
  Plus,
  RefreshCw,
  Trash2,
} from "lucide-react";

import {
  type AssetResponse,
  createReport,
  deleteReport,
  listReports,
  type ReportCreateRequest,
  type ReportFormat,
  type ReportResponse,
  type ReportType,
  type ScanResponse,
} from "@/lib/api";
import { formatDateTime } from "@/lib/soc-utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export const REPORT_TYPE_LABEL: Record<ReportType, string> = {
  EXECUTIVE: "Executivo (Gestão/C-Level)",
  TECHNICAL: "Técnico Detalhado (SecOps)",
  COMPARISON: "Comparativo de Auditorias",
  REMEDIATION_TRACKING: "Acompanhamento de Correções (SLA)",
  ASSET: "Por Ativo",
  SCAN: "Por Auditoria Específica",
  FINDING: "Individual por Vulnerabilidade",
};

export const REPORT_FORMAT_LABEL: Record<ReportFormat, string> = {
  PDF: "PDF (Documento Profissional)",
  HTML: "HTML (Visualização Responsiva)",
  JSON: "JSON (Integração Estruturada)",
  CSV: "CSV (Planilha Sanitizada)",
};

interface ReportsPanelProps {
  token: string;
  role?: string | null;
  assets: AssetResponse[];
  scans: ScanResponse[];
  onOpenComparisonModal?: (scanAId: string, scanBId: string) => void;
}

export function ReportsPanel({
  token,
  role,
  assets,
  scans,
  onOpenComparisonModal,
}: ReportsPanelProps) {
  const queryClient = useQueryClient();

  const [page, setPage] = useState(1);
  const [filterType, setFilterType] = useState<string>("");
  const [filterFormat, setFilterFormat] = useState<string>("");
  const [filterAsset, setFilterAsset] = useState<string>("");

  const [isCreating, setIsCreating] = useState(false);
  const [newType, setNewType] = useState<ReportType>("EXECUTIVE");
  const [newFormat, setNewFormat] = useState<ReportFormat>("PDF");
  const [newTitle, setNewTitle] = useState("");
  const [selectedAssetId, setSelectedAssetId] = useState("");
  const [selectedScanId, setSelectedScanId] = useState("");
  const [scanAId, setScanAId] = useState("");
  const [scanBId, setScanBId] = useState("");

  const [feedbackMsg, setFeedbackMsg] = useState<{ type: "success" | "error"; text: string } | null>(
    null
  );

  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ["reports", token, page, filterType, filterFormat, filterAsset],
    queryFn: () =>
      listReports(token, {
        report_type: filterType || undefined,
        format: filterFormat || undefined,
        asset_id: filterAsset || undefined,
        limit: 10,
        offset: (page - 1) * 10,
      }),
    refetchInterval: (query) => {
      const items = query.state.data?.items ?? [];
      const hasActive = items.some((r) => r.status === "PENDING" || r.status === "GENERATING");
      return hasActive ? 3000 : false;
    },
  });

  const createMutation = useMutation({
    mutationFn: (payload: ReportCreateRequest) => createReport(token, payload),
    onSuccess: (created) => {
      queryClient.invalidateQueries({ queryKey: ["reports"] });
      setIsCreating(false);
      setNewTitle("");
      setFeedbackMsg({
        type: "success",
        text: `Relatório "${created.title}" gerado com sucesso (${created.format}).`,
      });
      setTimeout(() => setFeedbackMsg(null), 5000);
    },
    onError: (err: any) => {
      setFeedbackMsg({
        type: "error",
        text: err?.message || "Falha ao gerar relatório.",
      });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (reportId: string) => deleteReport(token, reportId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["reports"] });
      setFeedbackMsg({ type: "success", text: "Relatório excluído com sucesso." });
      setTimeout(() => setFeedbackMsg(null), 4000);
    },
    onError: (err: any) => {
      setFeedbackMsg({ type: "error", text: err?.message || "Falha ao excluir relatório." });
    },
  });

  const handleGenerate = (e: React.FormEvent) => {
    e.preventDefault();
    setFeedbackMsg(null);

    const payload: ReportCreateRequest = {
      report_type: newType,
      format: newFormat,
      title: newTitle.trim() || undefined,
      asset_id: selectedAssetId || undefined,
      scan_id: selectedScanId || undefined,
      comparison_scan_id_a: newType === "COMPARISON" ? scanAId || undefined : undefined,
      comparison_scan_id_b: newType === "COMPARISON" ? scanBId || undefined : undefined,
      execute_synchronously: true,
    };

    createMutation.mutate(payload);
  };

  const handleCopyTokenLink = (report: ReportResponse) => {
    if (!report.download_token) return;
    const url = `${window.location.origin}/api/v1/reports/download-by-token/${report.download_token}`;
    navigator.clipboard.writeText(url);
    setFeedbackMsg({ type: "success", text: "Link seguro de download copiado para a área de transferência!" });
    setTimeout(() => setFeedbackMsg(null), 4000);
  };

  const total = data?.total ?? 0;
  const totalPages = Math.ceil(total / 10) || 1;

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
            Central de Relatórios & Exportações
          </h2>
          <p className="text-sm text-slate-500 dark:text-slate-400">
            Geração de relatórios executivos, técnicos e comparativos em PDF, HTML, JSON e CSV com evidências sanitizadas.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            size="sm"
            variant="outline"
            onClick={() => refetch()}
            className="gap-1.5 text-xs"
          >
            <RefreshCw className="h-3.5 w-3.5" /> Atualizar
          </Button>
          <Button
            size="sm"
            onClick={() => setIsCreating(!isCreating)}
            className="gap-1.5 text-xs bg-sky-600 hover:bg-sky-500 text-white"
          >
            <Plus className="h-3.5 w-3.5" /> Novo Relatório
          </Button>
        </div>
      </div>

      {feedbackMsg && (
        <div
          className={`flex items-center gap-2 p-3 text-xs rounded-md border ${
            feedbackMsg.type === "success"
              ? "bg-emerald-500/10 text-emerald-600 border-emerald-500/20 dark:text-emerald-400"
              : "bg-rose-500/10 text-rose-600 border-rose-500/20 dark:text-rose-400"
          }`}
        >
          {feedbackMsg.type === "success" ? (
            <CheckCircle2 className="h-4 w-4 shrink-0" />
          ) : (
            <AlertCircle className="h-4 w-4 shrink-0" />
          )}
          <span>{feedbackMsg.text}</span>
        </div>
      )}

      {/* Formulário de Criação de Relatório */}
      {isCreating && (
        <Card className="border border-sky-500/30 bg-sky-500/5 dark:bg-sky-950/20">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <FileText className="h-4 w-4 text-sky-500" />
              Configurar Novo Relatório de Segurança
            </CardTitle>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleGenerate} className="space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4">
                <div>
                  <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                    Tipo de Relatório
                  </label>
                  <select
                    className="w-full text-xs h-9 rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-2"
                    value={newType}
                    onChange={(e) => setNewType(e.target.value as ReportType)}
                  >
                    <option value="EXECUTIVE">Executivo (C-Level)</option>
                    <option value="TECHNICAL">Técnico Detalhado</option>
                    <option value="COMPARISON">Comparativo entre Auditorias</option>
                    <option value="REMEDIATION_TRACKING">Acompanhamento de SLA</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                    Formato de Exportação
                  </label>
                  <select
                    className="w-full text-xs h-9 rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-2"
                    value={newFormat}
                    onChange={(e) => setNewFormat(e.target.value as ReportFormat)}
                  >
                    <option value="PDF">PDF (Documento)</option>
                    <option value="HTML">HTML (Web/SOC)</option>
                    <option value="JSON">JSON (Estruturado)</option>
                    <option value="CSV">CSV (Planilha Segura)</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                    Ativo Alvo (Opcional)
                  </label>
                  <select
                    className="w-full text-xs h-9 rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-2"
                    value={selectedAssetId}
                    onChange={(e) => setSelectedAssetId(e.target.value)}
                  >
                    <option value="">Todos os Ativos</option>
                    {assets.map((a) => (
                      <option key={a.id} value={a.id}>
                        {a.name} ({a.environment})
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                    Auditoria Específica (Opcional)
                  </label>
                  <select
                    className="w-full text-xs h-9 rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-2"
                    value={selectedScanId}
                    onChange={(e) => setSelectedScanId(e.target.value)}
                  >
                    <option value="">Auditoria mais recente</option>
                    {scans.map((s) => (
                      <option key={s.id} value={s.id}>
                        {s.asset_name ?? s.asset_id} — {s.profile_type} ({s.id.slice(0, 8)})
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              {newType === "COMPARISON" && (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 p-3 bg-slate-900/40 rounded-md border border-slate-800">
                  <div>
                    <label className="block text-xs font-medium text-sky-400 mb-1">
                      Auditoria Base (A)
                    </label>
                    <select
                      required
                      className="w-full text-xs h-9 rounded-md border border-slate-700 bg-slate-900 px-2"
                      value={scanAId}
                      onChange={(e) => setScanAId(e.target.value)}
                    >
                      <option value="">Selecione a auditoria base...</option>
                      {scans.map((s) => (
                        <option key={s.id} value={s.id}>
                          {s.asset_name ?? s.asset_id} [{formatDateTime(s.created_at)}] ({s.profile_type})
                        </option>
                      ))}
                    </select>
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-sky-400 mb-1">
                      Auditoria Recente para Comparar (B)
                    </label>
                    <select
                      required
                      className="w-full text-xs h-9 rounded-md border border-slate-700 bg-slate-900 px-2"
                      value={scanBId}
                      onChange={(e) => setScanBId(e.target.value)}
                    >
                      <option value="">Selecione a auditoria recente...</option>
                      {scans.map((s) => (
                        <option key={s.id} value={s.id}>
                          {s.asset_name ?? s.asset_id} [{formatDateTime(s.created_at)}] ({s.profile_type})
                        </option>
                      ))}
                    </select>
                  </div>
                </div>
              )}

              <div>
                <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                  Título Personalizado (Opcional)
                </label>
                <input
                  type="text"
                  placeholder="Ex: Auditoria Q4 2026 — Homologação Portal de Pagamentos"
                  className="w-full text-xs h-9 rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-3"
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                />
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  onClick={() => setIsCreating(false)}
                >
                  Cancelar
                </Button>
                <Button
                  type="submit"
                  size="sm"
                  disabled={createMutation.isPending}
                  className="bg-sky-600 hover:bg-sky-500 text-white"
                >
                  {createMutation.isPending ? "Processando..." : "Gerar Relatório Agora"}
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>
      )}

      {/* Filtros da Listagem */}
      <Card>
        <CardContent className="pt-4">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div>
              <label className="block text-xs font-medium text-slate-500 mb-1">Tipo</label>
              <select
                className="w-full text-xs h-8 rounded-md border border-slate-300 dark:border-slate-700 bg-transparent px-2"
                value={filterType}
                onChange={(e) => {
                  setFilterType(e.target.value);
                  setPage(1);
                }}
              >
                <option value="">Todos os Tipos</option>
                <option value="EXECUTIVE">Executivo</option>
                <option value="TECHNICAL">Técnico</option>
                <option value="COMPARISON">Comparativo</option>
                <option value="REMEDIATION_TRACKING">Acompanhamento</option>
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-500 mb-1">Formato</label>
              <select
                className="w-full text-xs h-8 rounded-md border border-slate-300 dark:border-slate-700 bg-transparent px-2"
                value={filterFormat}
                onChange={(e) => {
                  setFilterFormat(e.target.value);
                  setPage(1);
                }}
              >
                <option value="">Todos os Formatos</option>
                <option value="PDF">PDF</option>
                <option value="HTML">HTML</option>
                <option value="JSON">JSON</option>
                <option value="CSV">CSV</option>
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-500 mb-1">Ativo</label>
              <select
                className="w-full text-xs h-8 rounded-md border border-slate-300 dark:border-slate-700 bg-transparent px-2"
                value={filterAsset}
                onChange={(e) => {
                  setFilterAsset(e.target.value);
                  setPage(1);
                }}
              >
                <option value="">Todos os Ativos</option>
                {assets.map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.name}
                  </option>
                ))}
              </select>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Tabela de Relatórios */}
      <Card>
        <CardHeader className="py-3 px-4 border-b border-slate-200 dark:border-slate-800">
          <CardTitle className="text-sm font-semibold flex items-center justify-between">
            <span>Histórico de Relatórios Emitidos ({total})</span>
            <span className="text-xs font-normal text-slate-500">
              Página {page} de {totalPages}
            </span>
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="p-8 text-center text-xs text-slate-500 flex items-center justify-center gap-2">
              <RefreshCw className="h-4 w-4 animate-spin" /> Carregando relatórios...
            </div>
          ) : isError ? (
            <div className="p-8 text-center text-xs text-rose-500">
              Falha ao carregar relatórios. Verifique a conexão com a API.
            </div>
          ) : !data || data.items.length === 0 ? (
            <div className="p-8 text-center text-xs text-slate-500">
              Nenhum relatório emitido para os filtros aplicados. Clique em "Novo Relatório" para gerar.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-50 dark:bg-slate-900/50 text-slate-500 uppercase tracking-wider text-[10px]">
                  <tr>
                    <th className="py-2.5 px-4 font-semibold">Título / Identificador</th>
                    <th className="py-2.5 px-2 font-semibold">Tipo</th>
                    <th className="py-2.5 px-2 font-semibold">Formato</th>
                    <th className="py-2.5 px-2 font-semibold">Estado</th>
                    <th className="py-2.5 px-2 font-semibold">Tamanho</th>
                    <th className="py-2.5 px-2 font-semibold">Data de Emissão</th>
                    <th className="py-2.5 px-4 font-semibold text-right">Ações</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                  {data.items.map((r) => {
                    const isCompleted = r.status === "COMPLETED";
                    return (
                      <tr key={r.id} className="hover:bg-slate-50/50 dark:hover:bg-slate-800/40">
                        <td className="py-3 px-4 font-medium text-slate-900 dark:text-slate-100">
                          <div>{r.title}</div>
                          <div className="text-[10px] text-slate-400 font-mono mt-0.5">
                            ID: {r.id.slice(0, 8)}... | Ativo: {r.asset_name ?? "Geral da Organização"}
                          </div>
                        </td>
                        <td className="py-3 px-2">
                          <Badge variant="outline" className="text-[10px]">
                            {r.report_type}
                          </Badge>
                        </td>
                        <td className="py-3 px-2">
                          <span className="font-semibold text-sky-600 dark:text-sky-400 flex items-center gap-1">
                            {r.format === "PDF" ? (
                              <FileText className="h-3 w-3" />
                            ) : r.format === "CSV" ? (
                              <FileSpreadsheet className="h-3 w-3" />
                            ) : (
                              <FileText className="h-3 w-3" />
                            )}
                            {r.format}
                          </span>
                        </td>
                        <td className="py-3 px-2">
                          <Badge
                            variant={
                              r.status === "COMPLETED"
                                ? "success"
                                : r.status === "FAILED"
                                ? "critical"
                                : "outline"
                            }
                            className="text-[10px]"
                          >
                            {r.status}
                          </Badge>
                        </td>
                        <td className="py-3 px-2 text-slate-500">
                          {r.file_size_bytes > 0
                            ? `${(r.file_size_bytes / 1024).toFixed(1)} KB`
                            : "—"}
                        </td>
                        <td className="py-3 px-2 text-slate-500 whitespace-nowrap">
                          {formatDateTime(r.created_at)}
                        </td>
                        <td className="py-3 px-4 text-right space-x-1 whitespace-nowrap">
                          {isCompleted && (
                            <>
                              <a
                                href={`/api/v1/reports/${r.id}/download`}
                                target="_blank"
                                rel="noreferrer"
                                className="inline-flex items-center gap-1 px-2 py-1 text-[11px] rounded bg-sky-500/10 text-sky-600 dark:text-sky-400 hover:bg-sky-500/20 font-medium"
                              >
                                <Download className="h-3 w-3" /> Baixar
                              </a>
                              {r.download_token && (
                                <button
                                  type="button"
                                  onClick={() => handleCopyTokenLink(r)}
                                  title="Copiar Link Seguro de Download"
                                  className="p-1 text-slate-400 hover:text-slate-200"
                                >
                                  <Copy className="h-3.5 w-3.5 inline" />
                                </button>
                              )}
                            </>
                          )}
                          {role !== "VIEWER" && (
                            <button
                              type="button"
                              onClick={() => deleteMutation.mutate(r.id)}
                              title="Excluir Relatório"
                              className="p-1 text-rose-500/80 hover:text-rose-500"
                            >
                              <Trash2 className="h-3.5 w-3.5 inline" />
                            </button>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}

          {total > 10 && (
            <div className="p-3 border-t border-slate-100 dark:border-slate-800 flex items-center justify-between text-xs">
              <span className="text-slate-500">
                Exibindo {data?.items.length} de {total} relatório(s)
              </span>
              <div className="space-x-2">
                <Button
                  size="sm"
                  variant="outline"
                  disabled={page <= 1}
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  className="h-7 text-xs"
                >
                  Anterior
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  disabled={page >= totalPages}
                  onClick={() => setPage((p) => p + 1)}
                  className="h-7 text-xs"
                >
                  Próxima
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
