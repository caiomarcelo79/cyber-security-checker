"use client";

import React from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import {
  fetchDashboardSummary,
  fetchDashboardTrends,
  getDashboardEvolution,
  type PlatformMetricsSummary,
  type TopRiskyAssetItem,
  type TrendPoint,
} from "@/lib/api";
import {
  errorMessage,
  formatDateTime,
  formatDuration,
  RISK_METHODOLOGY,
  riskLevel,
  SCAN_STATUS_LABEL,
  SEVERITY_COLOR,
  SEVERITY_LABEL,
  SEVERITY_ORDER,
} from "@/lib/soc-utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export interface KpiItem {
  key: string;
  label: string;
  value: number;
}

/** Deriva os 11 indicadores do painel apenas a partir de dados persistidos. */
export function buildKpis(m: PlatformMetricsSummary): KpiItem[] {
  const sc = m.scan_status_counts ?? {};
  return [
    { key: "assets", label: "Ativos cadastrados", value: m.total_assets },
    { key: "scans", label: "Auditorias", value: m.total_scans_executed },
    { key: "running", label: "Em andamento", value: m.scans_in_progress },
    { key: "completed", label: "Concluídas", value: sc.COMPLETED ?? 0 },
    {
      key: "failed",
      label: "Com falha",
      value: (sc.FAILED ?? 0) + (sc.ABORTED_TARGET_DEGRADED ?? 0),
    },
    { key: "critical", label: "Críticas", value: m.critical_vulnerabilities },
    { key: "high", label: "Altas", value: m.high_vulnerabilities },
    { key: "medium", label: "Médias", value: m.medium_vulnerabilities },
    { key: "low", label: "Baixas", value: m.low_vulnerabilities },
    { key: "open", label: "Vulnerabilidades abertas", value: m.open_vulnerabilities },
    {
      key: "resolved",
      label: "Corrigidas",
      value: m.resolved_vulnerabilities ?? 0,
    },
  ];
}

export function severityChartData(m: PlatformMetricsSummary) {
  const values: Record<string, number> = {
    CRITICAL: m.critical_vulnerabilities,
    HIGH: m.high_vulnerabilities,
    MEDIUM: m.medium_vulnerabilities,
    LOW: m.low_vulnerabilities,
    INFO: m.info_vulnerabilities,
  };
  return SEVERITY_ORDER.map((s) => ({
    key: s,
    name: SEVERITY_LABEL[s],
    total: values[s],
  }));
}

export function scanStatusChartData(m: PlatformMetricsSummary) {
  return Object.entries(m.scan_status_counts ?? {}).map(([status, total]) => ({
    name: SCAN_STATUS_LABEL[status] ?? status,
    total,
  }));
}

interface DashboardPanelProps {
  token: string;
  onViewAssetFindings: (assetId: string) => void;
  onViewAsset: (assetId: string) => void;
  onOpenScan: (scanId: string) => void;
}

export function DashboardPanel({
  token,
  onViewAssetFindings,
  onViewAsset,
  onOpenScan,
}: DashboardPanelProps) {
  const summaryQuery = useQuery({
    queryKey: ["dashboard-summary", token],
    queryFn: () => fetchDashboardSummary(token),
    refetchInterval: (q) =>
      (q.state.data?.scans_in_progress ?? 0) > 0 ? 5000 : false,
  });
  const trendsQuery = useQuery({
    queryKey: ["dashboard-trends", token, 30],
    queryFn: () => fetchDashboardTrends(token, 30),
  });
  const evolutionQuery = useQuery({
    queryKey: ["dashboard-evolution", token, 30],
    queryFn: () => getDashboardEvolution(token, 30),
  });

  if (summaryQuery.isLoading) {
    return (
      <p role="status" className="text-sm text-slate-500">
        Carregando indicadores reais da organização…
      </p>
    );
  }
  if (summaryQuery.isError || !summaryQuery.data) {
    return (
      <p role="alert" className="text-sm text-red-500">
        {errorMessage(summaryQuery.error)}
      </p>
    );
  }

  const m = summaryQuery.data;
  const kpis = buildKpis(m);
  const hasScans = m.total_scans_executed > 0;
  const trendPoints: TrendPoint[] = trendsQuery.data?.points ?? [];
  const trendHasData = trendPoints.some(
    (p) => p.detected > 0 || p.resolved > 0 || p.scans > 0
  );

  return (
    <section aria-label="Painel de indicadores da organização" className="space-y-4">
      <div
        className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-6"
        data-testid="kpi-grid"
      >
        {kpis.map((k) => (
          <Card key={k.key}>
            <CardHeader className="pb-1">
              <CardTitle className="text-xs font-medium uppercase text-slate-500 dark:text-slate-400">
                {k.label}
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-2xl font-bold" data-testid={`kpi-${k.key}`}>
                {k.value}
              </p>
            </CardContent>
          </Card>
        ))}
      </div>

      {!hasScans && (
        <div
          role="note"
          className="rounded-md border border-amber-500/30 bg-amber-500/10 p-3 text-xs"
        >
          Nenhuma auditoria foi executada nesta organização. Cadastre um ativo,
          comprove a autorização e inicie uma auditoria. A ausência de dados não
          comprova a inexistência de vulnerabilidades.
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">
              Vulnerabilidades abertas por severidade
            </CardTitle>
          </CardHeader>
          <CardContent className="h-56">
            {m.open_vulnerabilities === 0 ? (
              <p className="text-xs text-slate-500">
                Nenhuma vulnerabilidade aberta registrada.
              </p>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={severityChartData(m)}>
                  <CartesianGrid strokeDasharray="3 3" opacity={0.3} />
                  <XAxis dataKey="name" fontSize={11} />
                  <YAxis allowDecimals={false} fontSize={11} />
                  <Tooltip />
                  <Bar dataKey="total" name="Abertas">
                    {severityChartData(m).map((d) => (
                      <Cell key={d.key} fill={SEVERITY_COLOR[d.key]} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Distribuição de estados das auditorias</CardTitle>
          </CardHeader>
          <CardContent className="h-56">
            {!hasScans ? (
              <p className="text-xs text-slate-500">Sem auditorias registradas.</p>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={scanStatusChartData(m)}>
                  <CartesianGrid strokeDasharray="3 3" opacity={0.3} />
                  <XAxis dataKey="name" fontSize={11} />
                  <YAxis allowDecimals={false} fontSize={11} />
                  <Tooltip />
                  <Bar dataKey="total" name="Auditorias" fill="#0ea5e9" />
                </BarChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="text-sm">
              Histórico de descobertas e tendência de correções (30 dias)
            </CardTitle>
          </CardHeader>
          <CardContent className="h-64">
            {trendsQuery.isLoading ? (
              <p role="status" className="text-xs text-slate-500">
                Carregando série histórica…
              </p>
            ) : trendsQuery.isError ? (
              <p role="alert" className="text-xs text-red-500">
                {errorMessage(trendsQuery.error)}
              </p>
            ) : !trendHasData ? (
              <p className="text-xs text-slate-500">
                Ainda não há eventos persistidos no período.
              </p>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={trendPoints}>
                  <CartesianGrid strokeDasharray="3 3" opacity={0.3} />
                  <XAxis dataKey="date" fontSize={10} tickFormatter={(v: string) => v.slice(5)} />
                  <YAxis allowDecimals={false} fontSize={11} />
                  <Tooltip />
                  <Legend />
                  <Line type="monotone" dataKey="detected" name="Novas descobertas" stroke="#dc2626" dot={false} />
                  <Line type="monotone" dataKey="resolved" name="Correções registradas" stroke="#16a34a" dot={false} />
                  <Line type="monotone" dataKey="scans" name="Auditorias" stroke="#0ea5e9" dot={false} />
                </LineChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>
      </div>

      {evolutionQuery.data && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3" data-testid="evolution-summary">
          <Card>
            <CardHeader className="pb-1">
              <CardTitle className="text-xs font-medium uppercase text-slate-500">
                Tempo Médio de Remediação (MTTR 30 dias)
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-2xl font-bold text-sky-500" data-testid="mttr-value">
                {evolutionQuery.data.mttr_average_days != null
                  ? `${evolutionQuery.data.mttr_average_days.toFixed(1)} dias`
                  : "Sem resoluções recentes"}
              </p>
              <p className="text-xs text-slate-500 mt-1">
                Média calculada entre data de detecção e validação de correção.
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-1">
              <CardTitle className="text-xs font-medium uppercase text-slate-500">
                Vulnerabilidades Corrigidas (Últimos 30 dias)
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-2xl font-bold text-emerald-500" data-testid="resolved-30d-value">
                {evolutionQuery.data.total_resolved}
              </p>
              <p className="text-xs text-slate-500 mt-1">
                Total de falhas que transitaram para estado mitigado ou validado.
              </p>
            </CardContent>
          </Card>
        </div>
      )}

      <TopRiskyAssets
        assets={m.top_risky_assets ?? []}
        onViewAssetFindings={onViewAssetFindings}
        onViewAsset={onViewAsset}
      />

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">
            Auditorias recentes
            {m.average_scan_duration_seconds > 0 &&
              ` · duração média ${formatDuration(m.average_scan_duration_seconds)}`}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-xs">
          {(m.recent_scans ?? []).length === 0 ? (
            <p className="text-slate-500">Nenhuma auditoria recente.</p>
          ) : (
            m.recent_scans.map((s) => (
              <div
                key={s.id}
                className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-slate-200 p-2 dark:border-slate-800"
              >
                <span>
                  <strong>{s.asset_name}</strong> · {s.profile_type} ·{" "}
                  {formatDateTime(s.created_at)}
                </span>
                <span className="flex items-center gap-2">
                  <Badge variant="outline">{SCAN_STATUS_LABEL[s.status] ?? s.status}</Badge>
                  <span>{s.findings_count} descobertas</span>
                  <Button size="sm" variant="secondary" onClick={() => onOpenScan(s.id)}>
                    Detalhes
                  </Button>
                </span>
              </div>
            ))
          )}
        </CardContent>
      </Card>
    </section>
  );
}

export function TopRiskyAssets({
  assets,
  onViewAssetFindings,
  onViewAsset,
}: {
  assets: TopRiskyAssetItem[];
  onViewAssetFindings: (assetId: string) => void;
  onViewAsset: (assetId: string) => void;
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm">Ativos com maior risco</CardTitle>
        <p className="text-xs text-slate-500" data-testid="risk-methodology">
          {RISK_METHODOLOGY}
        </p>
      </CardHeader>
      <CardContent className="overflow-x-auto">
        {assets.length === 0 ? (
          <p className="text-xs text-slate-500">
            Nenhum ativo cadastrado. Cadastre um sistema para iniciar o monitoramento.
          </p>
        ) : (
          <table className="w-full text-left text-xs">
            <thead className="text-slate-500">
              <tr>
                <th className="py-1 pr-2">Ativo</th>
                <th className="pr-2">Ambiente</th>
                <th className="pr-2">Última auditoria</th>
                <th className="pr-2">Abertas</th>
                <th className="pr-2">Críticas</th>
                <th className="pr-2">Altas</th>
                <th className="pr-2">Indicador de risco</th>
                <th>Ações</th>
              </tr>
            </thead>
            <tbody>
              {assets.map((a) => {
                const lvl = riskLevel(a.risk_score);
                return (
                  <tr key={a.id} className="border-t border-slate-200 dark:border-slate-800">
                    <td className="py-2 pr-2">
                      <div className="font-bold">{a.name}</div>
                      <div className="font-mono text-slate-500">{a.target_url}</div>
                    </td>
                    <td className="pr-2">{a.environment}</td>
                    <td className="pr-2">{formatDateTime(a.last_scan_at)}</td>
                    <td className="pr-2">{a.open_findings_count}</td>
                    <td className="pr-2">{a.critical_count}</td>
                    <td className="pr-2">{a.high_count}</td>
                    <td className="pr-2">
                      <Badge variant={lvl.variant}>
                        {a.risk_score}/100 · {lvl.label}
                      </Badge>
                    </td>
                    <td className="space-x-1 whitespace-nowrap">
                      <Button size="sm" variant="secondary" onClick={() => onViewAssetFindings(a.id)}>
                        Vulnerabilidades
                      </Button>
                      <Button size="sm" variant="outline" onClick={() => onViewAsset(a.id)}>
                        Detalhes
                      </Button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </CardContent>
    </Card>
  );
}
