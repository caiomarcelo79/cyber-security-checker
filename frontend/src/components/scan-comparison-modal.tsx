"use client";

import React, { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  FileCheck2,
  GitCompare,
  Layers,
  RefreshCw,
  ShieldAlert,
  X,
} from "lucide-react";

import { compareScans, type ScanComparisonResponse } from "@/lib/api";
import { formatDateTime, SEVERITY_LABEL, severityVariant } from "@/lib/soc-utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

interface ScanComparisonModalProps {
  token: string;
  scanIdA: string;
  scanIdB: string;
  onClose: () => void;
  onGenerateReport?: (scanA: string, scanB: string) => void;
}

export function ScanComparisonModal({
  token,
  scanIdA,
  scanIdB,
  onClose,
  onGenerateReport,
}: ScanComparisonModalProps) {
  const [activeTab, setActiveTab] = useState<"new" | "resolved" | "persistent" | "coverage">(
    "new"
  );

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ["scan-comparison", token, scanIdA, scanIdB],
    queryFn: () => compareScans(token, scanIdA, scanIdB),
  });

  if (isLoading) {
    return (
      <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-6 max-w-md w-full text-center space-y-4">
          <RefreshCw className="h-8 w-8 animate-spin mx-auto text-sky-500" />
          <p className="text-sm text-slate-300">
            Correlacionando descobertas e calculando paridade de cobertura entre as auditorias...
          </p>
        </div>
      </div>
    );
  }

  if (isError || !data) {
    return (
      <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-6 max-w-md w-full space-y-4">
          <div className="flex items-center justify-between text-rose-400">
            <span className="font-semibold flex items-center gap-2">
              <AlertTriangle className="h-5 w-5" /> Erro na Comparação
            </span>
            <button onClick={onClose}>
              <X className="h-5 w-5" />
            </button>
          </div>
          <p className="text-xs text-slate-400">
            {(error as any)?.message || "Não foi possível comparar as auditorias selecionadas."}
          </p>
          <div className="flex justify-end">
            <Button size="sm" variant="outline" onClick={onClose}>
              Fechar
            </Button>
          </div>
        </div>
      </div>
    );
  }

  const sum = data.comparison_summary;
  const cov = data.coverage_diff;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 overflow-y-auto">
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl max-w-4xl w-full my-8 max-h-[90vh] flex flex-col shadow-2xl">
        {/* Cabeçalho */}
        <div className="p-4 sm:p-6 border-b border-slate-200 dark:border-slate-800 flex items-start justify-between">
          <div>
            <div className="flex items-center gap-2">
              <GitCompare className="h-5 w-5 text-sky-500" />
              <h2 className="text-lg font-bold text-slate-900 dark:text-slate-100">
                Comparativo de Auditorias — {data.asset_name ?? "Ativo"}
              </h2>
            </div>
            <div className="text-xs text-slate-500 dark:text-slate-400 mt-1 flex items-center gap-2 flex-wrap">
              <span>
                <strong>Base (A):</strong> {data.scan_a.profile_type} ({data.scan_a.id.slice(0, 8)}) [
                {formatDateTime(data.scan_a.created_at)}]
              </span>
              <ArrowRight className="h-3 w-3 text-slate-400" />
              <span>
                <strong>Recente (B):</strong> {data.scan_b.profile_type} ({data.scan_b.id.slice(0, 8)}) [
                {formatDateTime(data.scan_b.created_at)}]
              </span>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-200 p-1 rounded-md"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* KPIs Resumo */}
        <div className="p-4 sm:p-6 grid grid-cols-2 sm:grid-cols-5 gap-3 border-b border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-950/30">
          <div className="p-3 rounded-lg border border-rose-500/20 bg-rose-500/5 text-center">
            <span className="block text-xl font-bold text-rose-500">{sum.new_count as number}</span>
            <span className="text-[10px] text-slate-500 uppercase font-semibold">Novas Falhas</span>
          </div>
          <div className="p-3 rounded-lg border border-amber-500/20 bg-amber-500/5 text-center">
            <span className="block text-xl font-bold text-amber-500">
              {sum.persistent_count as number}
            </span>
            <span className="text-[10px] text-slate-500 uppercase font-semibold">Persistentes</span>
          </div>
          <div className="p-3 rounded-lg border border-emerald-500/20 bg-emerald-500/5 text-center">
            <span className="block text-xl font-bold text-emerald-500">
              {sum.confirmed_remediated_count as number}
            </span>
            <span className="text-[10px] text-slate-500 uppercase font-semibold">
              Correções Validadas
            </span>
          </div>
          <div className="p-3 rounded-lg border border-blue-500/20 bg-blue-500/5 text-center">
            <span className="block text-xl font-bold text-blue-500">
              {sum.not_verified_coverage_count as number}
            </span>
            <span className="text-[10px] text-slate-500 uppercase font-semibold">
              Diferença Cobertura
            </span>
          </div>
          <div className="p-3 rounded-lg border border-purple-500/20 bg-purple-500/5 text-center col-span-2 sm:col-span-1">
            <span className="block text-xl font-bold text-purple-500">
              {sum.coverage_parity_percent as number}%
            </span>
            <span className="text-[10px] text-slate-500 uppercase font-semibold">
              Paridade Módulos
            </span>
          </div>
        </div>

        {/* Abas Internas */}
        <div className="flex border-b border-slate-200 dark:border-slate-800 px-6 gap-4 text-xs font-medium">
          <button
            onClick={() => setActiveTab("new")}
            className={`py-3 border-b-2 flex items-center gap-1.5 ${
              activeTab === "new"
                ? "border-rose-500 text-rose-500 font-bold"
                : "border-transparent text-slate-500 hover:text-slate-300"
            }`}
          >
            <ShieldAlert className="h-3.5 w-3.5" />
            Novas Descobertas ({data.new_findings.length})
          </button>
          <button
            onClick={() => setActiveTab("resolved")}
            className={`py-3 border-b-2 flex items-center gap-1.5 ${
              activeTab === "resolved"
                ? "border-emerald-500 text-emerald-500 font-bold"
                : "border-transparent text-slate-500 hover:text-slate-300"
            }`}
          >
            <CheckCircle2 className="h-3.5 w-3.5" />
            Correções Validadas ({data.confirmed_remediated.length})
          </button>
          <button
            onClick={() => setActiveTab("persistent")}
            className={`py-3 border-b-2 flex items-center gap-1.5 ${
              activeTab === "persistent"
                ? "border-amber-500 text-amber-500 font-bold"
                : "border-transparent text-slate-500 hover:text-slate-300"
            }`}
          >
            <AlertTriangle className="h-3.5 w-3.5" />
            Persistentes ({data.persistent_findings.length})
          </button>
          <button
            onClick={() => setActiveTab("coverage")}
            className={`py-3 border-b-2 flex items-center gap-1.5 ${
              activeTab === "coverage"
                ? "border-sky-500 text-sky-500 font-bold"
                : "border-transparent text-slate-500 hover:text-slate-300"
            }`}
          >
            <Layers className="h-3.5 w-3.5" />
            Cobertura & Metodologia
          </button>
        </div>

        {/* Conteúdo da Aba */}
        <div className="p-6 overflow-y-auto flex-1 space-y-4 text-xs">
          {activeTab === "new" && (
            <div>
              {data.new_findings.length === 0 ? (
                <p className="text-slate-500 italic py-4 text-center">
                  Nenhuma nova vulnerabilidade introduzida na auditoria recente.
                </p>
              ) : (
                <div className="space-y-3">
                  {data.new_findings.map((f) => (
                    <div
                      key={f.id}
                      className="p-3 rounded-lg border border-rose-500/20 bg-rose-500/5 space-y-1"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-slate-900 dark:text-slate-100">
                          {f.title}
                        </span>
                        <Badge variant={severityVariant(f.severity)}>{SEVERITY_LABEL[f.severity]}</Badge>
                      </div>
                      <p className="text-slate-500 font-mono text-[11px]">{f.affected_endpoint}</p>
                      <p className="text-slate-400">{f.description}</p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {activeTab === "resolved" && (
            <div>
              {data.confirmed_remediated.length === 0 ? (
                <p className="text-slate-500 italic py-4 text-center">
                  Nenhuma correção com verificação técnica comprovada (PASSED) identificada.
                </p>
              ) : (
                <div className="space-y-3">
                  {data.confirmed_remediated.map((f) => (
                    <div
                      key={f.id}
                      className="p-3 rounded-lg border border-emerald-500/20 bg-emerald-500/5 space-y-1"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-slate-900 dark:text-slate-100 flex items-center gap-1.5">
                          <CheckCircle2 className="h-4 w-4 text-emerald-500" /> {f.title}
                        </span>
                        <Badge variant="success">RESOLVIDA</Badge>
                      </div>
                      <p className="text-slate-500 font-mono text-[11px]">{f.affected_endpoint}</p>
                      <p className="text-slate-400">
                        O teste do módulo <code>{f.module_id}</code> foi executado na auditoria recente e
                        retornou aprovado (PASSED), confirmando a mitigação técnica.
                      </p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {activeTab === "persistent" && (
            <div className="space-y-4">
              {data.severity_changes.length > 0 && (
                <div className="p-3 bg-amber-500/10 border border-amber-500/30 rounded-lg">
                  <span className="font-semibold text-amber-500 block mb-2">
                    Alterações de Severidade Identificadas ({data.severity_changes.length}):
                  </span>
                  <div className="space-y-1">
                    {data.severity_changes.map((sc) => (
                      <div key={sc.fingerprint} className="flex items-center justify-between">
                        <span>{sc.title}</span>
                        <span className="font-mono">
                          {sc.previous_severity} → <strong>{sc.current_severity}</strong>
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {data.persistent_findings.length === 0 ? (
                <p className="text-slate-500 italic py-4 text-center">
                  Nenhuma vulnerabilidade persistente encontrada em ambas as auditorias.
                </p>
              ) : (
                <div className="space-y-3">
                  {data.persistent_findings.map((f) => (
                    <div
                      key={f.id}
                      className="p-3 rounded-lg border border-slate-200 dark:border-slate-800 space-y-1"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-slate-900 dark:text-slate-100">
                          {f.title}
                        </span>
                        <Badge variant={severityVariant(f.severity)}>{SEVERITY_LABEL[f.severity]}</Badge>
                      </div>
                      <p className="text-slate-500 font-mono text-[11px]">{f.affected_endpoint}</p>
                      <p className="text-slate-400">
                        Detectada pela primeira vez em {formatDateTime(f.first_detected_at)}.
                      </p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {activeTab === "coverage" && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="p-3 bg-slate-50 dark:bg-slate-950 rounded-lg border border-slate-200 dark:border-slate-800">
                  <span className="font-semibold block mb-1">Módulos em Scan A (Base)</span>
                  <ul className="list-disc list-inside text-slate-400 space-y-0.5">
                    {cov.modules_a.map((m) => (
                      <li key={m}>{m}</li>
                    ))}
                  </ul>
                </div>
                <div className="p-3 bg-slate-50 dark:bg-slate-950 rounded-lg border border-slate-200 dark:border-slate-800">
                  <span className="font-semibold block mb-1">Módulos em Scan B (Recente)</span>
                  <ul className="list-disc list-inside text-slate-400 space-y-0.5">
                    {cov.modules_b.map((m) => (
                      <li key={m}>{m}</li>
                    ))}
                  </ul>
                </div>
              </div>

              {cov.modules_added_in_b.length > 0 && (
                <p className="text-emerald-500">
                  <strong>Módulos adicionados em B:</strong> {cov.modules_added_in_b.join(", ")}
                </p>
              )}
              {cov.modules_removed_in_b.length > 0 && (
                <p className="text-amber-500">
                  <strong>Módulos removidos em B (diferença de escopo):</strong>{" "}
                  {cov.modules_removed_in_b.join(", ")}
                </p>
              )}

              <p className="text-slate-400 text-[11px] leading-relaxed">
                Nota de integridade técnica: vulnerabilidades que constavam em Scan A mas cujos módulos
                não foram executados em Scan B são classificadas rigorosamente como "Diferença de
                Cobertura" e jamais como resolvidas.
              </p>
            </div>
          )}
        </div>

        {/* Rodapé do Modal */}
        <div className="p-4 border-t border-slate-200 dark:border-slate-800 flex items-center justify-between">
          <div className="text-[11px] text-slate-500">
            Comparação determinística baseada em fingerprints e evidências reais.
          </div>
          <div className="flex items-center gap-2">
            {onGenerateReport && (
              <Button
                size="sm"
                variant="outline"
                onClick={() => onGenerateReport(scanIdA, scanIdB)}
                className="gap-1.5 text-xs"
              >
                <FileCheck2 className="h-3.5 w-3.5" /> Gerar Relatório Comparativo
              </Button>
            )}
            <Button size="sm" onClick={onClose} className="text-xs">
              Concluir
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}
