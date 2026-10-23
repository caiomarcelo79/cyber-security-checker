"use client";

import React, { useRef, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { useTheme } from "next-themes";
import {
  Activity,
  BookOpen,
  Building2,
  CheckCircle2,
  Database,
  FileSpreadsheet,
  FileText,
  GitCompare,
  Globe,
  KeyRound,
  Layers,
  Lock,
  LogOut,
  Moon,
  PlusCircle,
  RefreshCw,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sliders,
  Sun,
  Terminal,
  Users,
  Zap,
} from "lucide-react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import {
  addOrganizationMember,
  type AuthSessionResponse,
  cancelScan,
  createAsset,
  createScan,
  fetchAssetAuthorizations,
  fetchAssets,
  fetchAuditLogs,
  fetchOrganizationMembers,
  fetchRemediationCatalog,
  fetchScanDetailedResults,
  fetchScanProfiles,
  fetchScanProgress,
  fetchScansPage,
  fetchSecurityModules,
  fetchSystemStatus,
  initiateAssetAuthorization,
  loginUser,
  logoutUser,
  registerUser,
  revokeAssetAuthorization,
  type ScopeValidationResponse,
  type TargetAuthorizationResponse,
  validateScopePolicy,
  verifyAssetAuthorization,
} from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { AssetsDirectory } from "@/components/assets-directory";
import { AutomationsPanel } from "@/components/automations-panel";
import { DashboardPanel } from "@/components/dashboard-panel";
import { ReportsPanel } from "@/components/reports-panel";
import { ScanComparisonModal } from "@/components/scan-comparison-modal";
import { ScanEventsCard, ScansHistoryPanel } from "@/components/scans-history-panel";
import { VulnerabilitiesPanel } from "@/components/vulnerabilities-panel";
import { useScanLiveProgress } from "@/lib/use-scan-live-progress";

const scopeFormSchema = z.object({
  target_url: z.string().min(5, "Informe uma URL para validação de escopo"),
  authorized_hosts_csv: z
    .string()
    .min(2, "Informe ao menos um host autorizado no escopo"),
  allow_subdomains: z.boolean().default(false),
  excluded_paths_csv: z.string().default("/logout, /admin/delete"),
});

type ScopeFormValues = z.infer<typeof scopeFormSchema>;

const registerSchema = z.object({
  full_name: z.string().min(2, "Informe seu nome completo"),
  email: z.string().email("Informe um e-mail válido"),
  password: z.string().min(8, "A senha deve ter no mínimo 8 caracteres"),
  organization_name: z.string().min(2, "Informe o nome da organização"),
});

type RegisterFormValues = z.infer<typeof registerSchema>;

const loginSchema = z.object({
  email: z.string().email("Informe um e-mail válido"),
  password: z.string().min(8, "A senha deve ter no mínimo 8 caracteres"),
});

type LoginFormValues = z.infer<typeof loginSchema>;

const assetSchema = z.object({
  name: z.string().min(2, "Informe o nome do sistema/ativo"),
  target_url: z.string().url("Informe uma URL válida (http:// ou https://)"),
  asset_type: z.enum(["WEB_APP", "REST_API", "GRAPHQL_API", "DOMAIN"]),
  environment: z.enum(["PRODUCTION", "STAGING", "DEVELOPMENT", "LAB"]),
  owner_name: z.string().min(2, "Informe o nome do responsável técnico"),
  owner_email: z.string().email("Informe o e-mail do responsável"),
  tags_csv: z.string().default("web, homolog"),
  excluded_paths_csv: z.string().default("/logout, /delete"),
});

type AssetFormValues = z.infer<typeof assetSchema>;

const memberSchema = z.object({
  full_name: z.string().min(2, "Informe o nome do integrante"),
  email: z.string().email("Informe o e-mail"),
  password: z.string().min(8, "Senha inicial (mín. 8 caracteres)"),
  role: z.enum(["ADMIN", "SECURITY_ANALYST", "DEVELOPER", "VIEWER"]),
});

type MemberFormValues = z.infer<typeof memberSchema>;

type ActiveTab =
  | "dashboard"
  | "assets"
  | "scans"
  | "vulnerabilities"
  | "reports"
  | "automations"
  | "org_audit"
  | "auth"
  | "modules"
  | "profiles"
  | "remediation"
  | "scope_validator";

export function SocConsole() {
  const [activeTab, setActiveTab] = useState<ActiveTab>("dashboard");
  const [authSession, setAuthSession] = useState<AuthSessionResponse | null>(
    null
  );
  const [authMode, setAuthMode] = useState<"login" | "register">("register");
  const [authError, setAuthError] = useState<string | null>(null);
  const [assetFeedback, setAssetFeedback] = useState<string | null>(null);
  const [selectedAssetId, setSelectedAssetId] = useState<string | null>(null);
  const [selectedAuthMethod, setSelectedAuthMethod] = useState<
    "LAB_INTERNAL" | "DNS_TXT" | "HTTP_WELL_KNOWN"
  >("LAB_INTERNAL");
  const [scopeNotes, setScopeNotes] = useState(
    "Autorização formal registrada para auditoria de segurança."
  );
  const [scopeResult, setScopeResult] =
    useState<ScopeValidationResponse | null>(null);
  const [scopeLoading, setScopeLoading] = useState(false);

  // Estado Fase 3: Execução de Auditorias e Resultados
  const [selectedScanAssetId, setSelectedScanAssetId] = useState<string>("");
  const [selectedProfileType, setSelectedProfileType] =
    useState<string>("QUICK");
  const [scanMaxRps, setScanMaxRps] = useState<number>(5);
  const [scanMaxConcurrency, setScanMaxConcurrency] = useState<number>(3);
  const [scanTimeoutSeconds, setScanTimeoutSeconds] = useState<number>(10);
  const [executeSync, setExecuteSync] = useState<boolean>(true);
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const [scanFeedback, setScanFeedback] = useState<string | null>(null);
  const [scanSubmitting, setScanSubmitting] = useState<boolean>(false);

  const [findingsAssetId, setFindingsAssetId] = useState<string>("");
  const [findingsSeverity, setFindingsSeverity] = useState<string>("");

  // Estado Fase 6: Comparação e Relatórios
  const [comparisonModalOpen, setComparisonModalOpen] = useState(false);
  const [comparisonScanA, setComparisonScanA] = useState<string | null>(null);
  const [comparisonScanB, setComparisonScanB] = useState<string | null>(null);

  const { theme, setTheme } = useTheme();
  const queryClient = useQueryClient();
  const token = authSession?.access_token ?? null;

  const statusQuery = useQuery({
    queryKey: ["system-status"],
    queryFn: fetchSystemStatus,
  });

  const modulesQuery = useQuery({
    queryKey: ["security-modules"],
    queryFn: fetchSecurityModules,
  });

  const profilesQuery = useQuery({
    queryKey: ["scan-profiles"],
    queryFn: fetchScanProfiles,
  });

  const remediationQuery = useQuery({
    queryKey: ["remediation-catalog"],
    queryFn: fetchRemediationCatalog,
  });

  const assetsQuery = useQuery({
    queryKey: ["org-assets", token],
    queryFn: () => fetchAssets(token!),
    enabled: Boolean(token),
  });

  const recentScansQuery = useQuery({
    queryKey: ["soc-recent-scans", token],
    queryFn: () => fetchScansPage(token!, { limit: 50, sort_desc: true }),
    enabled: Boolean(token),
  });

  const selectedAssetAuthsQuery = useQuery({
    queryKey: ["asset-authorizations", token, selectedAssetId],
    queryFn: () => fetchAssetAuthorizations(token!, selectedAssetId!),
    enabled: Boolean(token && selectedAssetId),
  });

  const membersQuery = useQuery({
    queryKey: ["org-members", token],
    queryFn: () => fetchOrganizationMembers(token!),
    enabled: Boolean(token),
  });

  const auditLogsQuery = useQuery({
    queryKey: ["org-audit-logs", token],
    queryFn: () => fetchAuditLogs(token!),
    enabled: Boolean(
      token &&
        (authSession?.active_role === "ADMIN" ||
          authSession?.active_role === "SECURITY_ANALYST")
    ),
  });

  const liveStateRef = useRef<string>("idle");

  const selectedScanProgressQuery = useQuery({
    queryKey: ["scan-progress", token, selectedScanId],
    queryFn: () => fetchScanProgress(token!, selectedScanId!),
    enabled: Boolean(token && selectedScanId),
    refetchInterval: (query) => {
      const st = query.state.data?.status;
      if (liveStateRef.current === "live") return false;
      return st && ["PENDING", "QUEUED", "RUNNING"].includes(st) ? 2500 : false;
    },
  });

  const liveState = useScanLiveProgress(
    token,
    selectedScanId,
    Boolean(selectedScanId) &&
      ["PENDING", "QUEUED", "RUNNING"].includes(
        selectedScanProgressQuery.data?.status ?? ""
      )
  );
  liveStateRef.current = liveState;

  const selectedScanResultsQuery = useQuery({
    queryKey: [
      "scan-detailed-results",
      token,
      selectedScanId,
      selectedScanProgressQuery.data?.status,
      selectedScanProgressQuery.data?.total_checks_run,
    ],
    queryFn: () => fetchScanDetailedResults(token!, selectedScanId!),
    enabled: Boolean(token && selectedScanId),
  });

  const scopeForm = useForm<ScopeFormValues>({
    resolver: zodResolver(scopeFormSchema),
    defaultValues: {
      target_url: "https://portal.empresa.com.br/login",
      authorized_hosts_csv: "portal.empresa.com.br",
      allow_subdomains: false,
      excluded_paths_csv: "/logout, /admin/delete",
    },
  });

  const registerForm = useForm<RegisterFormValues>({
    resolver: zodResolver(registerSchema),
    defaultValues: {
      full_name: "",
      email: "",
      password: "",
      organization_name: "",
    },
  });

  const loginForm = useForm<LoginFormValues>({
    resolver: zodResolver(loginSchema),
    defaultValues: {
      email: "",
      password: "",
    },
  });

  const assetForm = useForm<AssetFormValues>({
    resolver: zodResolver(assetSchema),
    defaultValues: {
      name: "Portal Laboratório Homologação",
      target_url: "http://lab-target.internal:8080",
      asset_type: "WEB_APP",
      environment: "LAB",
      owner_name: "Equipe AppSec",
      owner_email: "appsec@empresa.local",
      tags_csv: "laboratorio, owasp",
      excluded_paths_csv: "/logout, /delete",
    },
  });

  const memberForm = useForm<MemberFormValues>({
    resolver: zodResolver(memberSchema),
    defaultValues: {
      full_name: "",
      email: "",
      password: "",
      role: "SECURITY_ANALYST",
    },
  });

  async function handleRegister(values: RegisterFormValues) {
    setAuthError(null);
    try {
      const session = await registerUser(values);
      setAuthSession(session);
      setActiveTab("assets");
      void statusQuery.refetch();
    } catch (err) {
      setAuthError(
        err instanceof Error ? err.message : "Erro ao registrar conta."
      );
    }
  }

  async function handleLogin(values: LoginFormValues) {
    setAuthError(null);
    try {
      const session = await loginUser(values);
      setAuthSession(session);
      setActiveTab("assets");
      void statusQuery.refetch();
    } catch (err) {
      setAuthError(err instanceof Error ? err.message : "Falha no login.");
    }
  }

  async function handleLogout() {
    if (token) {
      await logoutUser(token);
    }
    setAuthSession(null);
    setSelectedAssetId(null);
    queryClient.clear();
    void statusQuery.refetch();
  }

  async function handleCreateAsset(values: AssetFormValues) {
    if (!token) return;
    setAssetFeedback(null);
    try {
      const created = await createAsset(token, {
        name: values.name,
        target_url: values.target_url,
        asset_type: values.asset_type,
        environment: values.environment,
        owner_name: values.owner_name,
        owner_email: values.owner_email,
        tags: values.tags_csv
          .split(",")
          .map((t) => t.trim())
          .filter(Boolean),
        excluded_paths: values.excluded_paths_csv
          .split(",")
          .map((p) => p.trim())
          .filter(Boolean),
      });
      setSelectedAssetId(created.id);
      setAssetFeedback(
        `Ativo '${created.name}' (${created.hostname}) cadastrado com sucesso! Inicie abaixo a comprovação de autorização.`
      );
      void Promise.allSettled([
        assetsQuery.refetch(),
        statusQuery.refetch(),
        auditLogsQuery.refetch(),
      ]);
    } catch (err) {
      setAssetFeedback(
        err instanceof Error ? err.message : "Erro ao criar ativo."
      );
    }
  }

  async function handleInitiateAuth(assetId: string) {
    if (!token) return;
    setAssetFeedback(null);
    try {
      const challenge = await initiateAssetAuthorization(token, assetId, {
        method: selectedAuthMethod,
        scope_notes: scopeNotes,
        expires_in_days: 90,
      });
      setAssetFeedback(
        `Desafio ${challenge.method} gerado! Token: ${challenge.verification_token}`
      );
      void Promise.allSettled([
        selectedAssetAuthsQuery.refetch(),
        auditLogsQuery.refetch(),
      ]);
    } catch (err) {
      setAssetFeedback(
        err instanceof Error ? err.message : "Erro ao gerar desafio."
      );
    }
  }

  async function handleVerifyAuth(
    authRecord: TargetAuthorizationResponse
  ): Promise<void> {
    if (!token) return;
    setAssetFeedback(null);
    try {
      const verified = await verifyAssetAuthorization(
        token,
        authRecord.asset_id,
        authRecord.id
      );
      setAssetFeedback(
        `Comprovação ${verified.method} VALIDADA com sucesso! Status do ativo atualizado para VERIFIED.`
      );
      void Promise.allSettled([
        selectedAssetAuthsQuery.refetch(),
        assetsQuery.refetch(),
        statusQuery.refetch(),
        auditLogsQuery.refetch(),
      ]);
    } catch (err) {
      setAssetFeedback(
        err instanceof Error ? err.message : "Falha na comprovação técnica."
      );
      void auditLogsQuery.refetch();
    }
  }

  async function handleRevokeAuth(
    authRecord: TargetAuthorizationResponse
  ): Promise<void> {
    if (!token) return;
    try {
      await revokeAssetAuthorization(
        token,
        authRecord.asset_id,
        authRecord.id
      );
      setAssetFeedback("Autorização revogada formalmente.");
      void Promise.allSettled([
        selectedAssetAuthsQuery.refetch(),
        assetsQuery.refetch(),
        statusQuery.refetch(),
        auditLogsQuery.refetch(),
      ]);
    } catch (err) {
      setAssetFeedback(
        err instanceof Error ? err.message : "Erro ao revogar autorização."
      );
    }
  }

  async function handleAddMember(values: MemberFormValues) {
    if (!token) return;
    try {
      await addOrganizationMember(token, values);
      memberForm.reset();
      void Promise.allSettled([
        membersQuery.refetch(),
        auditLogsQuery.refetch(),
      ]);
    } catch (err) {
      setAssetFeedback(
        err instanceof Error ? err.message : "Erro ao adicionar membro."
      );
    }
  }

  async function invalidateScanCaches() {
    await Promise.all(
      ["scans-page", "dashboard-summary", "dashboard-trends", "findings-page", "asset-scans"].map(
        (k) => queryClient.invalidateQueries({ queryKey: [k] })
      )
    );
  }

  async function handleStartScan(e: React.FormEvent) {
    e.preventDefault();
    if (!token) return;
    const targetAssetId =
      selectedScanAssetId ||
      selectedAssetId ||
      (assetsQuery.data?.[0]?.id ?? "");
    if (!targetAssetId) {
      setScanFeedback("Selecione um ativo autorizado para iniciar a auditoria.");
      return;
    }
    setScanSubmitting(true);
    setScanFeedback(null);
    try {
      const created = await createScan(token, {
        asset_id: targetAssetId,
        profile_type: selectedProfileType,
        max_requests_per_second: scanMaxRps,
        max_concurrency: scanMaxConcurrency,
        request_timeout_seconds: scanTimeoutSeconds,
        execute_synchronously: executeSync,
      });
      setSelectedScanId(created.id);
      setScanFeedback(
        `Auditoria ${created.id.slice(0, 8)} iniciada com perfil ${created.profile_type} — Status: ${created.status}`
      );
      void Promise.allSettled([
        invalidateScanCaches(),
        selectedScanProgressQuery.refetch(),
        selectedScanResultsQuery.refetch(),
        assetsQuery.refetch(),
        statusQuery.refetch(),
        auditLogsQuery.refetch(),
      ]);
    } catch (err) {
      setScanFeedback(
        err instanceof Error ? err.message : "Erro ao iniciar auditoria."
      );
    } finally {
      setScanSubmitting(false);
    }
  }

  async function handleCancelScan(scanId: string) {
    if (!token) return;
    setScanFeedback(null);
    try {
      const cancelled = await cancelScan(token, scanId);
      setScanFeedback(
        `Auditoria ${cancelled.id.slice(0, 8)} cancelada cooperativamente (${cancelled.status}).`
      );
      void Promise.allSettled([
        invalidateScanCaches(),
        selectedScanProgressQuery.refetch(),
        selectedScanResultsQuery.refetch(),
        statusQuery.refetch(),
        auditLogsQuery.refetch(),
      ]);
    } catch (err) {
      setScanFeedback(
        err instanceof Error ? err.message : "Erro ao cancelar auditoria."
      );
    }
  }

  async function onSubmitScopeCheck(values: ScopeFormValues) {
    setScopeLoading(true);
    try {
      const authorized_hosts = values.authorized_hosts_csv
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
      const excluded_paths = values.excluded_paths_csv
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
      const res = await validateScopePolicy({
        target_url: values.target_url,
        authorized_hosts,
        allow_subdomains: values.allow_subdomains,
        excluded_paths,
      });
      setScopeResult(res);
    } catch (err) {
      setScopeResult({
        allowed: false,
        reason:
          err instanceof Error
            ? err.message
            : "Erro ao comunicar com a API de validação de escopo.",
      });
    } finally {
      setScopeLoading(false);
    }
  }

  const metrics = statusQuery.data?.metrics;
  const severityChartData = [
    { name: "Crítica", quantidade: metrics?.critical_vulnerabilities ?? 0 },
    { name: "Alta", quantidade: metrics?.high_vulnerabilities ?? 0 },
    { name: "Média", quantidade: metrics?.medium_vulnerabilities ?? 0 },
    { name: "Baixa", quantidade: metrics?.low_vulnerabilities ?? 0 },
    { name: "Info", quantidade: metrics?.info_vulnerabilities ?? 0 },
  ];

  return (
    <div className="min-h-screen flex bg-slate-50 dark:bg-[#090D16] text-slate-900 dark:text-slate-100">
      {/* Barra Lateral SOC */}
      <aside className="w-72 border-r border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0D1320] flex flex-col justify-between shrink-0">
        <div>
          <div className="p-5 border-b border-slate-200 dark:border-slate-800 flex items-center gap-3">
            <div className="h-10 w-10 rounded-lg bg-sky-500/15 border border-sky-500/40 flex items-center justify-center text-sky-500">
              <Shield className="h-6 w-6" />
            </div>
            <div>
              <h1 className="font-bold text-sm tracking-wide uppercase text-slate-900 dark:text-white">
                Cyber-Security-Checker
              </h1>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                SOC & Vulnerability Console
              </p>
            </div>
          </div>

          <nav className="p-3 space-y-1" aria-label="Navegação Principal">
            <button
              type="button"
              onClick={() => setActiveTab("dashboard")}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-md text-sm font-medium transition-colors ${
                activeTab === "dashboard"
                  ? "bg-sky-500/15 text-sky-600 dark:text-sky-400 border border-sky-500/30"
                  : "text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800/60"
              }`}
            >
              <Activity className="h-4 w-4" />
              Dashboard & Telemetria Real
            </button>

            <button
              type="button"
              onClick={() => setActiveTab("assets")}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-md text-sm font-medium transition-colors ${
                activeTab === "assets"
                  ? "bg-sky-500/15 text-sky-600 dark:text-sky-400 border border-sky-500/30"
                  : "text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800/60"
              }`}
            >
              <Globe className="h-4 w-4" />
              Sistemas / Ativos & Autorização
            </button>

            <button
              type="button"
              onClick={() => setActiveTab("scans")}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-md text-sm font-medium transition-colors ${
                activeTab === "scans"
                  ? "bg-sky-500/15 text-sky-600 dark:text-sky-400 border border-sky-500/30"
                  : "text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800/60"
              }`}
            >
              <FileText className="h-4 w-4" />
              Auditorias & Vulnerabilidades
            </button>

            <button
              type="button"
              onClick={() => setActiveTab("vulnerabilities")}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-md text-sm font-medium transition-colors ${
                activeTab === "vulnerabilities"
                  ? "bg-sky-500/15 text-sky-600 dark:text-sky-400 border border-sky-500/30"
                  : "text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800/60"
              }`}
            >
              <ShieldAlert className="h-4 w-4" />
              Gestão de Vulnerabilidades
            </button>

            <button
              type="button"
              onClick={() => setActiveTab("reports")}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-md text-sm font-medium transition-colors ${
                activeTab === "reports"
                  ? "bg-sky-500/15 text-sky-600 dark:text-sky-400 border border-sky-500/30"
                  : "text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800/60"
              }`}
            >
              <FileSpreadsheet className="h-4 w-4" />
              Relatórios & Comparação
            </button>

            <button
              type="button"
              onClick={() => setActiveTab("automations")}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-md text-sm font-medium transition-colors ${
                activeTab === "automations"
                  ? "bg-sky-500/15 text-sky-600 dark:text-sky-400 border border-sky-500/30"
                  : "text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800/60"
              }`}
            >
              <Zap className="h-4 w-4" />
              Automações & Integrações
            </button>

            <button
              type="button"
              onClick={() => setActiveTab("org_audit")}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-md text-sm font-medium transition-colors ${
                activeTab === "org_audit"
                  ? "bg-sky-500/15 text-sky-600 dark:text-sky-400 border border-sky-500/30"
                  : "text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800/60"
              }`}
            >
              <Users className="h-4 w-4" />
              Organizações, RBAC & Audit Log
            </button>

            <button
              type="button"
              onClick={() => setActiveTab("auth")}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-md text-sm font-medium transition-colors ${
                activeTab === "auth"
                  ? "bg-sky-500/15 text-sky-600 dark:text-sky-400 border border-sky-500/30"
                  : "text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800/60"
              }`}
            >
              <KeyRound className="h-4 w-4" />
              Autenticação & Sessão
            </button>

            <button
              type="button"
              onClick={() => setActiveTab("modules")}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-md text-sm font-medium transition-colors ${
                activeTab === "modules"
                  ? "bg-sky-500/15 text-sky-600 dark:text-sky-400 border border-sky-500/30"
                  : "text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800/60"
              }`}
            >
              <Layers className="h-4 w-4" />
              Módulos de Auditoria (A–H)
            </button>

            <button
              type="button"
              onClick={() => setActiveTab("profiles")}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-md text-sm font-medium transition-colors ${
                activeTab === "profiles"
                  ? "bg-sky-500/15 text-sky-600 dark:text-sky-400 border border-sky-500/30"
                  : "text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800/60"
              }`}
            >
              <Sliders className="h-4 w-4" />
              Perfis de Execução & Limites
            </button>

            <button
              type="button"
              onClick={() => setActiveTab("remediation")}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-md text-sm font-medium transition-colors ${
                activeTab === "remediation"
                  ? "bg-sky-500/15 text-sky-600 dark:text-sky-400 border border-sky-500/30"
                  : "text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800/60"
              }`}
            >
              <BookOpen className="h-4 w-4" />
              Base Técnica de Correções
            </button>

            <button
              type="button"
              onClick={() => setActiveTab("scope_validator")}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-md text-sm font-medium transition-colors ${
                activeTab === "scope_validator"
                  ? "bg-sky-500/15 text-sky-600 dark:text-sky-400 border border-sky-500/30"
                  : "text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800/60"
              }`}
            >
              <Lock className="h-4 w-4" />
              Validador Escopo & Anti-SSRF
            </button>
          </nav>
        </div>

        <div className="p-4 border-t border-slate-200 dark:border-slate-800 text-xs space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-slate-500 dark:text-slate-400">
              Status da API:
            </span>
            {statusQuery.data?.status === "UP" ? (
              <Badge variant="success">ONLINE (UP)</Badge>
            ) : statusQuery.isLoading ? (
              <Badge variant="outline">CONECTANDO...</Badge>
            ) : (
              <Badge variant="warning">VERIFICAR API</Badge>
            )}
          </div>
          <p className="text-[11px] text-slate-500 dark:text-slate-400">
            Política ativa: Somente alvos com autorização comprovada. Zero dados
            fictícios.
          </p>
        </div>
      </aside>

      {/* Conteúdo Principal */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Cabeçalho Superior */}
        <header className="h-16 border-b border-slate-200 dark:border-slate-800 bg-white/80 dark:bg-[#0D1320]/80 backdrop-blur px-6 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Badge variant="default">
              {statusQuery.data?.current_phase ??
                "FASE 2 — Autenticação, RBAC e Ativos Autorizados"}
            </Badge>
            {authSession && (
              <div className="flex items-center gap-2 text-xs">
                <Badge variant="success">
                  <Building2 className="h-3 w-3 mr-1" />
                  {authSession.active_organization.name}
                </Badge>
                <Badge variant="outline">{authSession.active_role}</Badge>
              </div>
            )}
          </div>

          <div className="flex items-center gap-2">
            {authSession ? (
              <Button variant="outline" size="sm" onClick={handleLogout}>
                <LogOut className="h-3.5 w-3.5 mr-1.5" />
                Sair ({authSession.user.email})
              </Button>
            ) : (
              <Button
                variant="default"
                size="sm"
                onClick={() => setActiveTab("auth")}
              >
                <KeyRound className="h-3.5 w-3.5 mr-1.5" />
                Entrar / Criar Organização
              </Button>
            )}

            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                void statusQuery.refetch();
                void modulesQuery.refetch();
                void profilesQuery.refetch();
                if (token) {
                  void assetsQuery.refetch();
                  void membersQuery.refetch();
                }
              }}
            >
              <RefreshCw className="h-3.5 w-3.5 mr-1.5" />
              Atualizar Estado
            </Button>

            <Button
              variant="secondary"
              size="sm"
              onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
              aria-label="Alternar tema claro ou escuro"
            >
              {theme === "dark" ? (
                <>
                  <Sun className="h-3.5 w-3.5 mr-1.5" />
                  Tema Claro
                </>
              ) : (
                <>
                  <Moon className="h-3.5 w-3.5 mr-1.5" />
                  Tema Escuro
                </>
              )}
            </Button>
          </div>
        </header>

        <main className="p-6 space-y-6 overflow-y-auto">
          {activeTab === "dashboard" && (
            <>
              {authSession && token && (
                <DashboardPanel
                  token={token}
                  onViewAssetFindings={(id) => {
                    setFindingsAssetId(id);
                    setFindingsSeverity("");
                    setActiveTab("vulnerabilities");
                  }}
                  onViewAsset={(id) => {
                    setSelectedAssetId(id);
                    setActiveTab("assets");
                  }}
                  onOpenScan={(id) => {
                    setSelectedScanId(id);
                    setActiveTab("scans");
                  }}
                />
              )}
              {!authSession && (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-xs font-medium uppercase text-slate-500 dark:text-slate-400">
                      Sistemas Cadastrados
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="text-2xl font-bold">
                      {metrics?.total_assets ?? 0}
                    </div>
                    <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                      {metrics?.verified_assets ?? 0} com autorização verificada
                    </p>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-xs font-medium uppercase text-slate-500 dark:text-slate-400">
                      Auditorias Executadas
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="text-2xl font-bold">
                      {metrics?.total_scans_executed ?? 0}
                    </div>
                    <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                      Histórico real no PostgreSQL
                    </p>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-xs font-medium uppercase text-slate-500 dark:text-slate-400">
                      Em Andamento
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="text-2xl font-bold text-sky-500">
                      {metrics?.scans_in_progress ?? 0}
                    </div>
                    <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                      Fila assíncrona Celery/Redis
                    </p>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-xs font-medium uppercase text-slate-500 dark:text-slate-400">
                      Vulnerabilidades Abertas
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="text-2xl font-bold text-amber-500">
                      {metrics?.open_vulnerabilities ?? 0}
                    </div>
                    <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                      Confirmadas ou sob triagem
                    </p>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-xs font-medium uppercase text-slate-500 dark:text-slate-400">
                      Severidade Crítica
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="text-2xl font-bold text-red-500">
                      {metrics?.critical_vulnerabilities ?? 0}
                    </div>
                    <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                      Prioridade máxima de mitigação
                    </p>
                  </CardContent>
                </Card>
              </div>
              )}

              <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                <Card>
                  <CardHeader className="pb-3 flex flex-row items-center justify-between">
                    <CardTitle className="flex items-center gap-2 text-sm">
                      <Database className="h-4 w-4 text-sky-500" />
                      PostgreSQL 16 (Persistência)
                    </CardTitle>
                    <Badge
                      variant={
                        statusQuery.data?.components?.database?.status === "UP"
                          ? "success"
                          : "critical"
                      }
                    >
                      {statusQuery.data?.components?.database?.status ??
                        "VERIFICANDO"}
                    </Badge>
                  </CardHeader>
                  <CardContent className="text-xs text-slate-500 dark:text-slate-400 space-y-1">
                    <p>
                      Latência:{" "}
                      <span className="font-mono text-slate-900 dark:text-slate-200">
                        {statusQuery.data?.components?.database?.latency_ms ??
                          0}{" "}
                        ms
                      </span>
                    </p>
                    <p>
                      Organizações ativas:{" "}
                      <strong>{metrics?.total_organizations ?? 0}</strong>
                    </p>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader className="pb-3 flex flex-row items-center justify-between">
                    <CardTitle className="flex items-center gap-2 text-sm">
                      <Server className="h-4 w-4 text-emerald-500" />
                      Redis 7 & Workers Assíncronos
                    </CardTitle>
                    <Badge
                      variant={
                        statusQuery.data?.components?.redis?.status === "UP"
                          ? "success"
                          : "warning"
                      }
                    >
                      {statusQuery.data?.components?.redis?.status ??
                        "VERIFICANDO"}
                    </Badge>
                  </CardHeader>
                  <CardContent className="text-xs text-slate-500 dark:text-slate-400 space-y-1">
                    <p>
                      Latência:{" "}
                      <span className="font-mono text-slate-900 dark:text-slate-200">
                        {statusQuery.data?.components?.redis?.latency_ms ?? 0}{" "}
                        ms
                      </span>
                    </p>
                    <p>
                      Broker de tarefas Celery pronto para processamento
                      isolado.
                    </p>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader className="pb-3 flex flex-row items-center justify-between">
                    <CardTitle className="flex items-center gap-2 text-sm">
                      <ShieldCheck className="h-4 w-4 text-sky-400" />
                      Security Engine & Plugin Registry
                    </CardTitle>
                    <Badge variant="success">
                      {statusQuery.data?.registered_modules_count ?? 8} MÓDULOS
                      ATIVOS
                    </Badge>
                  </CardHeader>
                  <CardContent className="text-xs text-slate-500 dark:text-slate-400 space-y-1">
                    <p>
                      Perfis configurados:{" "}
                      <span className="font-mono text-slate-900 dark:text-slate-200">
                        {statusQuery.data?.available_profiles_count ?? 6}
                      </span>
                    </p>
                    <p>
                      Guardrails ativos: Validador Anti-SSRF, Sanitizador de
                      Evidências e Rate Limiting Obrigatório.
                    </p>
                  </CardContent>
                </Card>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {!authSession && (
                <Card>
                  <CardHeader>
                    <CardTitle>
                      Distribuição Real de Vulnerabilidades por Severidade
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="h-64 w-full">
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={severityChartData}>
                          <CartesianGrid
                            strokeDasharray="3 3"
                            stroke="#334155"
                          />
                          <XAxis dataKey="name" stroke="#94a3b8" fontSize={12} />
                          <YAxis
                            allowDecimals={false}
                            stroke="#94a3b8"
                            fontSize={12}
                          />
                          <Tooltip />
                          <Bar
                            dataKey="quantidade"
                            fill="#0ea5e9"
                            radius={[4, 4, 0, 0]}
                          />
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                  </CardContent>
                </Card>
                )}

                <Card>
                  <CardHeader>
                    <CardTitle>
                      Integridade de Dados & Gestão de Ativos Autorizados
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4 text-sm">
                    <div className="p-4 rounded-md border border-slate-200 dark:border-slate-800 bg-slate-100/50 dark:bg-slate-900/50 space-y-2">
                      <div className="flex items-center gap-2 font-medium text-sky-600 dark:text-sky-400">
                        <CheckCircle2 className="h-4 w-4" />
                        Política Zero Dados Fictícios Ativa
                      </div>
                      <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
                        Todos os indicadores exibidos neste painel são lidos em
                        tempo real do PostgreSQL via FastAPI. Cadastre ativos e
                        valide desafios de autorização (DNS TXT, HTTP Well-Known
                        ou Laboratório) na aba Sistemas / Ativos.
                      </p>
                    </div>

                    <div className="flex flex-wrap gap-2">
                      <Button
                        size="sm"
                        variant="default"
                        onClick={() =>
                          setActiveTab(authSession ? "assets" : "auth")
                        }
                      >
                        {authSession
                          ? "Gerenciar Sistemas e Autorizações"
                          : "Autenticar e Cadastrar Ativo"}
                      </Button>
                      <Button
                        size="sm"
                        variant="secondary"
                        onClick={() => setActiveTab("scope_validator")}
                      >
                        Testar Validador Anti-SSRF
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              </div>
            </>
          )}

          {activeTab === "auth" && (
            <div className="max-w-xl space-y-4">
              <div>
                <h2 className="text-lg font-bold">
                  Autenticação Segura & Isolamento Multi-Organização
                </h2>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  Senhas protegidas com scrypt, sessão JWT assinada (HMAC-SHA256)
                  + Cookie HttpOnly e controle de acesso baseado em papéis
                  (RBAC).
                </p>
              </div>

              <div className="flex gap-2">
                <Button
                  size="sm"
                  variant={authMode === "register" ? "default" : "outline"}
                  onClick={() => setAuthMode("register")}
                >
                  Criar Conta & Organização (ADMIN)
                </Button>
                <Button
                  size="sm"
                  variant={authMode === "login" ? "default" : "outline"}
                  onClick={() => setAuthMode("login")}
                >
                  Entrar em Conta Existente
                </Button>
              </div>

              {authError && (
                <div className="p-3 rounded border border-red-500/40 bg-red-500/10 text-red-500 text-xs">
                  {authError}
                </div>
              )}

              {authMode === "register" ? (
                <Card>
                  <CardHeader>
                    <CardTitle>
                      Registrar Nova Organização e Administrador
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <form
                      onSubmit={registerForm.handleSubmit(handleRegister)}
                      className="space-y-3 text-xs"
                    >
                      <div>
                        <label
                          htmlFor="reg_org_name"
                          className="block font-semibold mb-1"
                        >
                          Nome da Organização
                        </label>
                        <input
                          id="reg_org_name"
                          type="text"
                          placeholder="Ex: SecOps Brasil Ltda"
                          {...registerForm.register("organization_name")}
                          className="w-full rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-2 text-sm"
                        />
                      </div>
                      <div>
                        <label
                          htmlFor="reg_full_name"
                          className="block font-semibold mb-1"
                        >
                          Seu Nome Completo
                        </label>
                        <input
                          id="reg_full_name"
                          type="text"
                          placeholder="Ex: Analista Principal"
                          {...registerForm.register("full_name")}
                          className="w-full rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-2 text-sm"
                        />
                      </div>
                      <div>
                        <label
                          htmlFor="reg_email"
                          className="block font-semibold mb-1"
                        >
                          E-mail Corporativo
                        </label>
                        <input
                          id="reg_email"
                          type="email"
                          placeholder="admin@empresa.com.br"
                          {...registerForm.register("email")}
                          className="w-full rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-2 text-sm"
                        />
                      </div>
                      <div>
                        <label
                          htmlFor="reg_password"
                          className="block font-semibold mb-1"
                        >
                          Senha (mínimo 8 caracteres)
                        </label>
                        <input
                          id="reg_password"
                          type="password"
                          {...registerForm.register("password")}
                          className="w-full rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-2 text-sm"
                        />
                      </div>
                      <Button type="submit">
                        Criar Organização e Iniciar Sessão
                      </Button>
                    </form>
                  </CardContent>
                </Card>
              ) : (
                <Card>
                  <CardHeader>
                    <CardTitle>Login na Plataforma</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <form
                      onSubmit={loginForm.handleSubmit(handleLogin)}
                      className="space-y-3 text-xs"
                    >
                      <div>
                        <label
                          htmlFor="login_email"
                          className="block font-semibold mb-1"
                        >
                          E-mail
                        </label>
                        <input
                          id="login_email"
                          type="email"
                          {...loginForm.register("email")}
                          className="w-full rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-2 text-sm"
                        />
                      </div>
                      <div>
                        <label
                          htmlFor="login_password"
                          className="block font-semibold mb-1"
                        >
                          Senha
                        </label>
                        <input
                          id="login_password"
                          type="password"
                          {...loginForm.register("password")}
                          className="w-full rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-2 text-sm"
                        />
                      </div>
                      <Button type="submit">Autenticar</Button>
                    </form>
                  </CardContent>
                </Card>
              )}
            </div>
          )}

          {activeTab === "assets" && (
            <div className="space-y-6">
              <div>
                <h2 className="text-lg font-bold">
                  Sistemas / Ativos e Comprovação de Autorização (Fase 2)
                </h2>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  Cadastre aplicações, APIs ou domínios da sua organização e
                  comprove formalmente o controle/autorização antes de qualquer
                  auditoria.
                </p>
              </div>

              {!authSession ? (
                <Card>
                  <CardContent className="p-6 text-xs space-y-3">
                    <p>
                      Autentique-se para gerenciar os ativos e comprovantes de
                      autorização da sua organização.
                    </p>
                    <Button size="sm" onClick={() => setActiveTab("auth")}>
                      Ir para Autenticação / Registro
                    </Button>
                  </CardContent>
                </Card>
              ) : (
                <>
                  {assetFeedback && (
                    <div className="p-3 rounded border border-sky-500/40 bg-sky-500/10 text-sky-400 text-xs">
                      {assetFeedback}
                    </div>
                  )}

                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    {/* Formulário de Cadastro de Ativo */}
                    <Card>
                      <CardHeader>
                        <CardTitle className="flex items-center gap-2">
                          <PlusCircle className="h-4 w-4 text-sky-500" />
                          Cadastrar Novo Sistema / Ativo
                        </CardTitle>
                      </CardHeader>
                      <CardContent>
                        <form
                          onSubmit={assetForm.handleSubmit(handleCreateAsset)}
                          className="space-y-3 text-xs"
                        >
                          <div>
                            <label
                              htmlFor="asset_name"
                              className="block font-semibold mb-1"
                            >
                              Nome Identificador do Sistema
                            </label>
                            <input
                              id="asset_name"
                              type="text"
                              {...assetForm.register("name")}
                              className="w-full rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-2 text-sm"
                            />
                          </div>

                          <div>
                            <label
                              htmlFor="asset_url"
                              className="block font-semibold mb-1"
                            >
                              URL Principal / Endpoint Alvo
                            </label>
                            <input
                              id="asset_url"
                              type="text"
                              {...assetForm.register("target_url")}
                              className="w-full rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-2 text-sm"
                            />
                          </div>

                          <div className="grid grid-cols-2 gap-3">
                            <div>
                              <label
                                htmlFor="asset_type"
                                className="block font-semibold mb-1"
                              >
                                Tipo de Ativo
                              </label>
                              <select
                                id="asset_type"
                                {...assetForm.register("asset_type")}
                                className="w-full rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-2 text-sm"
                              >
                                <option value="WEB_APP">Aplicação Web</option>
                                <option value="REST_API">API REST</option>
                                <option value="GRAPHQL_API">API GraphQL</option>
                                <option value="DOMAIN">Domínio</option>
                              </select>
                            </div>

                            <div>
                              <label
                                htmlFor="asset_env"
                                className="block font-semibold mb-1"
                              >
                                Ambiente
                              </label>
                              <select
                                id="asset_env"
                                {...assetForm.register("environment")}
                                className="w-full rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-2 text-sm"
                              >
                                <option value="LAB">
                                  Laboratório Isolado (LAB)
                                </option>
                                <option value="STAGING">
                                  Homologação (STAGING)
                                </option>
                                <option value="DEVELOPMENT">
                                  Desenvolvimento (DEV)
                                </option>
                                <option value="PRODUCTION">
                                  Produção (PRODUCTION)
                                </option>
                              </select>
                            </div>
                          </div>

                          <div className="grid grid-cols-2 gap-3">
                            <div>
                              <label
                                htmlFor="owner_name"
                                className="block font-semibold mb-1"
                              >
                                Responsável Técnico
                              </label>
                              <input
                                id="owner_name"
                                type="text"
                                {...assetForm.register("owner_name")}
                                className="w-full rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-2 text-sm"
                              />
                            </div>
                            <div>
                              <label
                                htmlFor="owner_email"
                                className="block font-semibold mb-1"
                              >
                                E-mail do Responsável
                              </label>
                              <input
                                id="owner_email"
                                type="email"
                                {...assetForm.register("owner_email")}
                                className="w-full rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-2 text-sm"
                              />
                            </div>
                          </div>

                          <div className="grid grid-cols-2 gap-3">
                            <div>
                              <label
                                htmlFor="asset_tags"
                                className="block font-semibold mb-1"
                              >
                                Tags (separadas por vírgula)
                              </label>
                              <input
                                id="asset_tags"
                                type="text"
                                {...assetForm.register("tags_csv")}
                                className="w-full rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-2 text-sm"
                              />
                            </div>
                            <div>
                              <label
                                htmlFor="asset_exclusions"
                                className="block font-semibold mb-1"
                              >
                                Endpoints Excluídos
                              </label>
                              <input
                                id="asset_exclusions"
                                type="text"
                                {...assetForm.register("excluded_paths_csv")}
                                className="w-full rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-2 text-sm"
                              />
                            </div>
                          </div>

                          <Button type="submit">Cadastrar Ativo</Button>
                        </form>
                      </CardContent>
                    </Card>

                    <AssetsDirectory
                      token={token!}
                      role={authSession.active_role}
                      orgName={authSession.active_organization.name}
                      assets={assetsQuery.data ?? []}
                      selectedAssetId={selectedAssetId}
                      onManageAuthorization={setSelectedAssetId}
                      onAudit={(id) => {
                        setSelectedScanAssetId(id);
                        setActiveTab("scans");
                      }}
                      onViewFindings={(id) => {
                        setFindingsAssetId(id);
                        setFindingsSeverity("");
                        setActiveTab("vulnerabilities");
                      }}
                      onOpenScan={(id) => {
                        setSelectedScanId(id);
                        setActiveTab("scans");
                      }}
                    />
                  </div>

                  {/* Painel de Comprovação de Autorização do Ativo Selecionado */}
                  {selectedAssetId && (
                    <Card>
                      <CardHeader>
                        <CardTitle>
                          Comprovação de Autorização do Alvo (DNS TXT / HTTP
                          Well-Known / Laboratório)
                        </CardTitle>
                      </CardHeader>
                      <CardContent className="space-y-4 text-xs">
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 items-end">
                          <div>
                            <label
                              htmlFor="auth_method_select"
                              className="block font-semibold mb-1"
                            >
                              Método de Comprovação
                            </label>
                            <select
                              id="auth_method_select"
                              value={selectedAuthMethod}
                              onChange={(e) =>
                                setSelectedAuthMethod(
                                  e.target.value as
                                    | "LAB_INTERNAL"
                                    | "DNS_TXT"
                                    | "HTTP_WELL_KNOWN"
                                )
                              }
                              className="w-full rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-2 text-sm"
                            >
                              <option value="LAB_INTERNAL">
                                LAB_INTERNAL (Laboratório Isolado)
                              </option>
                              <option value="DNS_TXT">
                                DNS_TXT (Registro TXT no Domínio)
                              </option>
                              <option value="HTTP_WELL_KNOWN">
                                HTTP_WELL_KNOWN (/.well-known/...)
                              </option>
                            </select>
                          </div>

                          <div>
                            <label
                              htmlFor="scope_notes_input"
                              className="block font-semibold mb-1"
                            >
                              Observações de Escopo e Responsabilidade
                            </label>
                            <input
                              id="scope_notes_input"
                              type="text"
                              value={scopeNotes}
                              onChange={(e) => setScopeNotes(e.target.value)}
                              className="w-full rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-2 text-sm"
                            />
                          </div>

                          <div>
                            <Button
                              onClick={() =>
                                handleInitiateAuth(selectedAssetId)
                              }
                            >
                              Gerar Desafio Criptográfico
                            </Button>
                          </div>
                        </div>

                        <div className="space-y-3 pt-2">
                          {(selectedAssetAuthsQuery.data ?? []).map((auth) => (
                            <div
                              key={auth.id}
                              className="p-3 rounded border border-slate-200 dark:border-slate-800 bg-slate-100/40 dark:bg-slate-900/50 space-y-2"
                            >
                              <div className="flex items-center justify-between">
                                <div className="flex items-center gap-2">
                                  <Badge variant="default">{auth.method}</Badge>
                                  <span className="font-mono text-[11px]">
                                    {auth.verification_token}
                                  </span>
                                </div>
                                <Badge
                                  variant={
                                    auth.status === "VERIFIED"
                                      ? "success"
                                      : auth.status === "REVOKED"
                                      ? "critical"
                                      : "warning"
                                  }
                                >
                                  {auth.status}
                                </Badge>
                              </div>
                              <p className="text-slate-600 dark:text-slate-300">
                                {auth.instructions?.summary}
                              </p>
                              <div className="flex gap-2">
                                {auth.status !== "VERIFIED" &&
                                  auth.status !== "REVOKED" && (
                                    <Button
                                      size="sm"
                                      onClick={() => handleVerifyAuth(auth)}
                                    >
                                      Validar Comprovação Agora
                                    </Button>
                                  )}
                                {auth.status !== "REVOKED" && (
                                  <Button
                                    size="sm"
                                    variant="outline"
                                    onClick={() => handleRevokeAuth(auth)}
                                  >
                                    Revogar Autorização
                                  </Button>
                                )}
                              </div>
                            </div>
                          ))}
                        </div>
                      </CardContent>
                    </Card>
                  )}
                </>
              )}
            </div>
          )}

          {activeTab === "scans" && (
            <div className="space-y-6">
              <div>
                <h2 className="text-lg font-bold">
                  Execução de Auditorias em Tempo Real & Resultados Técnicos
                  (Fase 3)
                </h2>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  Inicie auditorias reais sobre ativos com autorização
                  comprovada (VERIFIED), acompanhe o progresso por módulo,
                  cancele execuções ativas e inspecione verificações e
                  vulnerabilidades com evidências sanitizadas.
                </p>
              </div>

              {!authSession ? (
                <Card>
                  <CardContent className="p-6 text-xs space-y-3">
                    <p>
                      Autentique-se para iniciar e acompanhar auditorias da sua
                      organização.
                    </p>
                    <Button size="sm" onClick={() => setActiveTab("auth")}>
                      Ir para Autenticação / Registro
                    </Button>
                  </CardContent>
                </Card>
              ) : (
                <>
                  {scanFeedback && (
                    <div className="p-3 rounded border border-sky-500/40 bg-sky-500/10 text-sky-400 text-xs">
                      {scanFeedback}
                    </div>
                  )}

                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    {/* Formulário de Disparo de Auditoria */}
                    <Card>
                      <CardHeader>
                        <CardTitle className="flex items-center gap-2">
                          <ShieldCheck className="h-4 w-4 text-sky-500" />
                          Iniciar Nova Auditoria Autorizada
                        </CardTitle>
                      </CardHeader>
                      <CardContent>
                        <form
                          onSubmit={handleStartScan}
                          className="space-y-3 text-xs"
                        >
                          <div>
                            <label
                              htmlFor="scan_asset_select"
                              className="block font-semibold mb-1"
                            >
                              Ativo Alvo (Requer Status VERIFIED)
                            </label>
                            <select
                              id="scan_asset_select"
                              value={
                                selectedScanAssetId ||
                                selectedAssetId ||
                                (assetsQuery.data?.[0]?.id ?? "")
                              }
                              onChange={(e) =>
                                setSelectedScanAssetId(e.target.value)
                              }
                              className="w-full rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-2 text-sm"
                            >
                              <option value="">
                                -- Selecione um sistema cadastrado --
                              </option>
                              {(assetsQuery.data ?? []).map((a) => (
                                <option key={a.id} value={a.id}>
                                  {a.name} ({a.target_url}) — [
                                  {a.authorization_status}]
                                </option>
                              ))}
                            </select>
                          </div>

                          <div className="grid grid-cols-2 gap-3">
                            <div>
                              <label
                                htmlFor="scan_profile_select"
                                className="block font-semibold mb-1"
                              >
                                Perfil de Auditoria
                              </label>
                              <select
                                id="scan_profile_select"
                                value={selectedProfileType}
                                onChange={(e) =>
                                  setSelectedProfileType(e.target.value)
                                }
                                className="w-full rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-2 text-sm"
                              >
                                <option value="QUICK">
                                  QUICK (Passivo Rápido: HTTPS, TLS, Headers,
                                  Cookies)
                                </option>
                                <option value="STANDARD">
                                  STANDARD (Padrão Web)
                                </option>
                                <option value="API">
                                  API (REST & GraphQL)
                                </option>
                                <option value="AUTHENTICATED">
                                  AUTHENTICATED (Sessão Autenticada)
                                </option>
                                <option value="DEEP_ASSESSMENT">
                                  DEEP_ASSESSMENT (Restrito a Lab/Homologação)
                                </option>
                              </select>
                            </div>

                            <div>
                              <label
                                htmlFor="scan_rps_input"
                                className="block font-semibold mb-1"
                              >
                                Limite de Taxa (Máx Req/s)
                              </label>
                              <input
                                id="scan_rps_input"
                                type="number"
                                min={1}
                                max={20}
                                value={scanMaxRps}
                                onChange={(e) =>
                                  setScanMaxRps(Number(e.target.value) || 5)
                                }
                                className="w-full rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-2 text-sm"
                              />
                            </div>
                          </div>

                          <div className="grid grid-cols-2 gap-3">
                            <div>
                              <label
                                htmlFor="scan_conc_input"
                                className="block font-semibold mb-1"
                              >
                                Concorrência Máxima
                              </label>
                              <input
                                id="scan_conc_input"
                                type="number"
                                min={1}
                                max={10}
                                value={scanMaxConcurrency}
                                onChange={(e) =>
                                  setScanMaxConcurrency(
                                    Number(e.target.value) || 3
                                  )
                                }
                                className="w-full rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-2 text-sm"
                              />
                            </div>

                            <div>
                              <label
                                htmlFor="scan_timeout_input"
                                className="block font-semibold mb-1"
                              >
                                Timeout por Requisição (s)
                              </label>
                              <input
                                id="scan_timeout_input"
                                type="number"
                                min={2}
                                max={30}
                                value={scanTimeoutSeconds}
                                onChange={(e) =>
                                  setScanTimeoutSeconds(
                                    Number(e.target.value) || 10
                                  )
                                }
                                className="w-full rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-2 text-sm"
                              />
                            </div>
                          </div>

                          <div className="flex items-center gap-2 pt-1">
                            <input
                              id="scan_sync_checkbox"
                              type="checkbox"
                              checked={executeSync}
                              onChange={(e) => setExecuteSync(e.target.checked)}
                              className="rounded border-slate-700"
                            />
                            <label htmlFor="scan_sync_checkbox">
                              Aguardar conclusão imediata do worker (execução
                              síncrona determinística)
                            </label>
                          </div>

                          <Button type="submit" disabled={scanSubmitting}>
                            {scanSubmitting
                              ? "Executando Auditoria..."
                              : "Iniciar Auditoria de Segurança"}
                          </Button>
                        </form>
                      </CardContent>
                    </Card>

                    <ScansHistoryPanel
                      token={token!}
                      role={authSession.active_role}
                      assets={assetsQuery.data ?? []}
                      selectedScanId={selectedScanId}
                      onSelect={setSelectedScanId}
                      onCancel={handleCancelScan}
                      onCompare={(scanA, scanB) => {
                        setComparisonScanA(scanA);
                        setComparisonScanB(scanB);
                        setComparisonModalOpen(true);
                      }}
                    />
                  </div>

                  {/* Painel de Progresso em Tempo Real e Resultados Detalhados */}
                  {selectedScanId && selectedScanResultsQuery.data && (
                    <div className="space-y-6">
                      <ScanEventsCard token={token!} scanId={selectedScanId} />
                      <Card>
                        <CardHeader className="pb-2">
                          <div className="flex items-center justify-between">
                            <CardTitle>
                              Monitor de Execução — Auditoria{" "}
                              {selectedScanResultsQuery.data.scan.id.slice(
                                0,
                                8
                              )}
                            </CardTitle>
                            <div className="flex items-center gap-2">
                              <Badge variant="default">
                                {selectedScanProgressQuery.data?.status ??
                                  selectedScanResultsQuery.data.scan.status}
                              </Badge>
                              {liveState !== "idle" && (
                                <span className="text-xs text-slate-500" data-testid="live-state">
                                  {liveState === "live" ? "● Tempo real (SSE)" : liveState === "connecting" ? "Conectando…" : "Atualização por consulta periódica"}
                                </span>
                              )}
                              {["PENDING", "QUEUED", "RUNNING"].includes(
                                selectedScanProgressQuery.data?.status ??
                                  selectedScanResultsQuery.data.scan.status
                              ) && (
                                <Button
                                  size="sm"
                                  variant="outline"
                                  onClick={() =>
                                    handleCancelScan(selectedScanId)
                                  }
                                >
                                  Cancelar Agora
                                </Button>
                              )}
                            </div>
                          </div>
                        </CardHeader>
                        <CardContent className="space-y-3 text-xs">
                          <div className="w-full bg-slate-200 dark:bg-slate-800 h-2.5 rounded-full overflow-hidden">
                            <div
                              className="bg-sky-500 h-full transition-all duration-300"
                              style={{
                                width: `${
                                  selectedScanProgressQuery.data
                                    ?.progress_percent ??
                                  selectedScanResultsQuery.data.scan
                                    .progress_percent
                                }%`,
                              }}
                            />
                          </div>

                          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 pt-1">
                            <div className="p-2.5 rounded bg-slate-100 dark:bg-slate-900">
                              <span className="text-slate-500 block">
                                Módulo Atual / Status
                              </span>
                              <span className="font-mono font-semibold">
                                {selectedScanProgressQuery.data
                                  ?.current_module ?? "Concluído / Ocioso"}
                              </span>
                            </div>
                            <div className="p-2.5 rounded bg-slate-100 dark:bg-slate-900">
                              <span className="text-slate-500 block">
                                Módulos Concluídos
                              </span>
                              <span className="font-mono font-semibold">
                                {
                                  (
                                    selectedScanProgressQuery.data
                                      ?.completed_modules ??
                                    selectedScanResultsQuery.data.scan
                                      .completed_modules
                                  ).length
                                }{" "}
                                /{" "}
                                {
                                  selectedScanResultsQuery.data.scan
                                    .enabled_modules.length
                                }
                              </span>
                            </div>
                            <div className="p-2.5 rounded bg-slate-100 dark:bg-slate-900">
                              <span className="text-slate-500 block">
                                Verificações Executadas
                              </span>
                              <span className="font-mono font-semibold">
                                {selectedScanProgressQuery.data
                                  ?.total_checks_run ??
                                  selectedScanResultsQuery.data.scan
                                    .total_checks_run}
                              </span>
                            </div>
                            <div className="p-2.5 rounded bg-slate-100 dark:bg-slate-900">
                              <span className="text-slate-500 block">
                                Tempo Decorrido
                              </span>
                              <span className="font-mono font-semibold">
                                {selectedScanProgressQuery.data
                                  ?.elapsed_seconds ??
                                  selectedScanResultsQuery.data.scan
                                    .elapsed_seconds}
                                s
                              </span>
                            </div>
                          </div>

                          {selectedScanResultsQuery.data.scan.error_message && (
                            <div className="p-3 rounded border border-red-500/40 bg-red-500/10 text-red-400">
                              <strong>Mensagem Operacional / Erro:</strong>{" "}
                              {selectedScanResultsQuery.data.scan.error_message}
                            </div>
                          )}
                        </CardContent>
                      </Card>

                      {/* Lista de Verificações Individuais (Checks) */}
                      <Card>
                        <CardHeader>
                          <CardTitle>
                            Verificações Individuais Executadas (
                            {selectedScanResultsQuery.data.checks.length})
                          </CardTitle>
                        </CardHeader>
                        <CardContent className="space-y-2 text-xs">
                          {selectedScanResultsQuery.data.checks.map((chk) => (
                            <div
                              key={chk.id}
                              className="p-2.5 rounded border border-slate-200 dark:border-slate-800 flex items-center justify-between gap-3"
                            >
                              <div>
                                <div className="flex items-center gap-2 font-semibold">
                                  <span className="font-mono text-sky-400">
                                    {chk.check_id}
                                  </span>
                                  <span>{chk.title}</span>
                                </div>
                                <p className="text-slate-500 mt-0.5">
                                  {chk.summary}
                                </p>
                              </div>
                              <Badge
                                variant={
                                  chk.status === "PASSED"
                                    ? "success"
                                    : chk.status === "VULNERABILITY" ||
                                      chk.status === "EXECUTION_ERROR"
                                    ? "critical"
                                    : chk.status === "POTENTIAL_VULNERABILITY"
                                    ? "warning"
                                    : "outline"
                                }
                              >
                                {chk.status}
                              </Badge>
                            </div>
                          ))}
                        </CardContent>
                      </Card>

                      {/* Lista de Vulnerabilidades e Indícios Técnicos (Findings) */}
                      <Card>
                        <CardHeader>
                          <CardTitle>
                            Vulnerabilidades e Indícios Técnicos Identificados (
                            {selectedScanResultsQuery.data.findings.length})
                          </CardTitle>
                        </CardHeader>
                        <CardContent className="space-y-4 text-xs">
                          {selectedScanResultsQuery.data.findings.length ===
                          0 ? (
                            <p className="text-emerald-500 font-medium">
                              Nenhuma vulnerabilidade ou indício técnico
                              identificado nesta execução.
                            </p>
                          ) : (
                            selectedScanResultsQuery.data.findings.map(
                              (fnd) => (
                                <div
                                  key={fnd.id}
                                  className="p-4 rounded-md border border-slate-200 dark:border-slate-800 space-y-2.5"
                                >
                                  <div className="flex items-center justify-between gap-2">
                                    <div className="flex items-center gap-2">
                                      <Badge
                                        variant={
                                          fnd.severity === "CRITICAL" ||
                                          fnd.severity === "HIGH"
                                            ? "critical"
                                            : fnd.severity === "MEDIUM"
                                            ? "warning"
                                            : "default"
                                        }
                                      >
                                        {fnd.severity}
                                      </Badge>
                                      <Badge variant="outline">
                                        {fnd.result_classification}
                                      </Badge>
                                      <Badge variant="outline">
                                        Confiança: {fnd.confidence}
                                      </Badge>
                                    </div>
                                    <span className="font-mono text-[11px] text-slate-500">
                                      {fnd.check_id} | {fnd.cwe_ids.join(", ")}
                                    </span>
                                  </div>

                                  <h3 className="font-bold text-sm">
                                    {fnd.title}
                                  </h3>
                                  <p className="text-slate-600 dark:text-slate-300">
                                    {fnd.description}
                                  </p>

                                  <div className="p-2.5 rounded bg-slate-900 text-slate-200 font-mono text-[11px] space-y-1">
                                    <div>
                                      <span className="text-sky-400">
                                        Endpoint:
                                      </span>{" "}
                                      {fnd.affected_endpoint}
                                    </div>
                                    <div>
                                      <span className="text-amber-400">
                                        Observado (Sanitizado):
                                      </span>{" "}
                                      {fnd.evidence.observed_value}
                                    </div>
                                    <div>
                                      <span className="text-emerald-400">
                                        Baseline Esperado:
                                      </span>{" "}
                                      {fnd.evidence.expected_baseline}
                                    </div>
                                  </div>

                                  {fnd.remediation_data?.how_to_fix && (
                                    <div className="p-2.5 rounded bg-emerald-500/5 border border-emerald-500/20">
                                      <strong className="text-emerald-500 block mb-0.5">
                                        Recomendação Técnica de Correção:
                                      </strong>
                                      <p>{fnd.remediation_data.how_to_fix}</p>
                                    </div>
                                  )}
                                </div>
                              )
                            )
                          )}
                        </CardContent>
                      </Card>
                    </div>
                  )}
                </>
              )}
            </div>
          )}

          {activeTab === "vulnerabilities" && (
            <div className="space-y-4">
              <h2 className="text-lg font-bold">Gestão de Vulnerabilidades</h2>
              {authSession && token ? (
                <VulnerabilitiesPanel
                  token={token}
                  role={authSession.active_role}
                  assets={assetsQuery.data ?? []}
                  initialAssetId={findingsAssetId}
                  initialSeverity={findingsSeverity}
                />
              ) : (
                <Card>
                  <CardContent className="space-y-3 p-4 text-sm">
                    <p>Autentique-se para consultar as vulnerabilidades da sua organização.</p>
                    <Button size="sm" onClick={() => setActiveTab("auth")}>
                      Acessar
                    </Button>
                  </CardContent>
                </Card>
              )}
            </div>
          )}

          {activeTab === "reports" && (
            <div className="space-y-4">
              <h2 className="text-lg font-bold">Relatórios & Comparação de Auditorias</h2>
              {authSession && token ? (
                <ReportsPanel
                  token={token}
                  role={authSession.active_role}
                  assets={assetsQuery.data ?? []}
                  scans={recentScansQuery.data?.items ?? []}
                  onOpenComparisonModal={(scanA, scanB) => {
                    setComparisonScanA(scanA);
                    setComparisonScanB(scanB);
                    setComparisonModalOpen(true);
                  }}
                />
              ) : (
                <Card>
                  <CardContent className="space-y-3 p-4 text-sm">
                    <p>Autentique-se para gerar relatórios e comparar auditorias da sua organização.</p>
                    <Button size="sm" onClick={() => setActiveTab("auth")}>
                      Acessar
                    </Button>
                  </CardContent>
                </Card>
              )}
            </div>
          )}

          {activeTab === "automations" && (
            <div className="space-y-4">
              {authSession && token ? (
                <AutomationsPanel
                  token={token}
                  role={authSession.active_role}
                  assets={assetsQuery.data ?? []}
                />
              ) : (
                <Card>
                  <CardContent className="space-y-3 p-4 text-sm">
                    <p>Autentique-se para configurar agendamentos, webhooks, notificações e chaves de API.</p>
                    <Button size="sm" onClick={() => setActiveTab("auth")}>
                      Acessar
                    </Button>
                  </CardContent>
                </Card>
              )}
            </div>
          )}

          {activeTab === "org_audit" && (
            <div className="space-y-6">
              <div>
                <h2 className="text-lg font-bold">
                  Gestão Multi-Usuário (RBAC) e Trilha de Auditoria Interna
                </h2>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  Controle de papéis (ADMIN, SECURITY_ANALYST, DEVELOPER,
                  VIEWER) e histórico imutável de ações executadas na
                  organização.
                </p>
              </div>

              {!authSession ? (
                <Card>
                  <CardContent className="p-6 text-xs">
                    Autentique-se para visualizar membros e logs de auditoria da
                    organização.
                  </CardContent>
                </Card>
              ) : (
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  <Card>
                    <CardHeader>
                      <CardTitle>
                        Membros da Organização (
                        {authSession.active_organization.name})
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-4 text-xs">
                      <div className="space-y-2">
                        {(membersQuery.data ?? []).map((mem) => (
                          <div
                            key={mem.membership_id}
                            className="p-2.5 rounded border border-slate-200 dark:border-slate-800 flex items-center justify-between"
                          >
                            <div>
                              <span className="font-semibold block">
                                {mem.full_name}
                              </span>
                              <span className="text-slate-500">
                                {mem.email}
                              </span>
                            </div>
                            <Badge variant="default">{mem.role}</Badge>
                          </div>
                        ))}
                      </div>

                      {authSession.active_role === "ADMIN" && (
                        <form
                          onSubmit={memberForm.handleSubmit(handleAddMember)}
                          className="space-y-2.5 pt-3 border-t border-slate-200 dark:border-slate-800"
                        >
                          <p className="font-semibold">
                            Adicionar / Atualizar Papel de Integrante (ADMIN):
                          </p>
                          <input
                            type="text"
                            placeholder="Nome completo"
                            {...memberForm.register("full_name")}
                            className="w-full rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-1.5"
                          />
                          <input
                            type="email"
                            placeholder="E-mail"
                            {...memberForm.register("email")}
                            className="w-full rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-1.5"
                          />
                          <input
                            type="password"
                            placeholder="Senha inicial (mínimo 8 caracteres)"
                            {...memberForm.register("password")}
                            className="w-full rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-1.5"
                          />
                          <select
                            {...memberForm.register("role")}
                            className="w-full rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-1.5"
                          >
                            <option value="SECURITY_ANALYST">
                              Analista de Segurança (SECURITY_ANALYST)
                            </option>
                            <option value="DEVELOPER">
                              Desenvolvedor (DEVELOPER)
                            </option>
                            <option value="VIEWER">
                              Visualizador (VIEWER)
                            </option>
                            <option value="ADMIN">Administrador (ADMIN)</option>
                          </select>
                          <Button size="sm" type="submit">
                            Salvar Integrante
                          </Button>
                        </form>
                      )}
                    </CardContent>
                  </Card>

                  <Card>
                    <CardHeader>
                      <CardTitle>
                        Trilha de Auditoria Interna (Audit Logs)
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-2 text-xs max-h-96 overflow-y-auto">
                      {(auditLogsQuery.data ?? []).map((log) => (
                        <div
                          key={log.id}
                          className="p-2.5 rounded border border-slate-200 dark:border-slate-800 font-mono text-[11px]"
                        >
                          <div className="flex justify-between text-sky-400">
                            <span>{log.action}</span>
                            <span className="text-slate-500">
                              {new Date(log.created_at).toLocaleTimeString(
                                "pt-BR"
                              )}
                            </span>
                          </div>
                          <div className="text-slate-500 mt-0.5">
                            Recurso: {log.resource_type} ({log.resource_id})
                          </div>
                        </div>
                      ))}
                    </CardContent>
                  </Card>
                </div>
              )}
            </div>
          )}

          {activeTab === "modules" && (
            <div className="space-y-4">
              <div>
                <h2 className="text-lg font-bold">
                  Catálogo de Módulos do Security Engine (Módulos A a H)
                </h2>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  Módulos registrados dinamicamente no PluginRegistry com
                  mapeamento OWASP Top 10, WSTG, ASVS 5.0 e CWE.
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {(modulesQuery.data ?? []).map((mod) => (
                  <Card key={mod.module_id}>
                    <CardHeader className="pb-2">
                      <div className="flex items-center justify-between gap-2">
                        <Badge variant="default">{mod.code}</Badge>
                        <div className="flex items-center gap-1.5">
                          <Badge
                            variant={
                              mod.allow_in_production ? "success" : "warning"
                            }
                          >
                            {mod.allow_in_production
                              ? "Permitido em Produção"
                              : "Restrito a Homologação/Lab"}
                          </Badge>
                          <Badge variant="outline">{mod.impact_level}</Badge>
                        </div>
                      </div>
                      <CardTitle className="pt-2">{mod.name}</CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-3 text-xs">
                      <p className="text-slate-600 dark:text-slate-400">
                        {mod.description}
                      </p>
                      <div>
                        <span className="font-semibold text-slate-800 dark:text-slate-200">
                          Verificações catalogadas:
                        </span>
                        <ul className="list-disc list-inside mt-1 space-y-0.5 text-slate-500 dark:text-slate-400">
                          {mod.checks_catalog.map((chk) => (
                            <li key={chk}>{chk}</li>
                          ))}
                        </ul>
                      </div>
                      <div className="flex flex-wrap gap-1.5 pt-1">
                        {mod.owasp_references.map((ref) => (
                          <Badge key={ref} variant="outline">
                            {ref}
                          </Badge>
                        ))}
                        {mod.cwe_references.map((cwe) => (
                          <Badge key={cwe} variant="outline">
                            {cwe}
                          </Badge>
                        ))}
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            </div>
          )}

          {activeTab === "profiles" && (
            <div className="space-y-4">
              <div>
                <h2 className="text-lg font-bold">
                  Perfis de Auditoria e Limites Operacionais
                </h2>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  Cada perfil explicita escopo, impacto potencial, limites de
                  requisição, pré-requisitos e riscos conhecidos.
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {(profilesQuery.data ?? []).map((prof) => (
                  <Card key={prof.profile_type}>
                    <CardHeader className="pb-2">
                      <div className="flex items-center justify-between">
                        <Badge variant="default">{prof.profile_type}</Badge>
                        <Badge
                          variant={
                            prof.allowed_in_production ? "success" : "critical"
                          }
                        >
                          {prof.allowed_in_production
                            ? "Produção Liberada"
                            : "Bloqueado em Produção"}
                        </Badge>
                      </div>
                      <CardTitle className="pt-2">{prof.name}</CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-3 text-xs">
                      <p className="text-slate-600 dark:text-slate-400">
                        {prof.description}
                      </p>
                      <div className="grid grid-cols-3 gap-2 p-2.5 rounded bg-slate-100 dark:bg-slate-900">
                        <div>
                          <span className="text-slate-500 block">Máx RPS</span>
                          <span className="font-mono font-semibold">
                            {prof.default_max_rps} req/s
                          </span>
                        </div>
                        <div>
                          <span className="text-slate-500 block">
                            Concorrência
                          </span>
                          <span className="font-mono font-semibold">
                            {prof.default_max_concurrency} conexões
                          </span>
                        </div>
                        <div>
                          <span className="text-slate-500 block">
                            Timeout Global
                          </span>
                          <span className="font-mono font-semibold">
                            {prof.default_timeout_seconds}s
                          </span>
                        </div>
                      </div>
                      <div>
                        <strong className="text-slate-800 dark:text-slate-200">
                          O que é analisado:
                        </strong>
                        <ul className="list-disc list-inside text-slate-500 dark:text-slate-400 mt-1">
                          {prof.what_is_analyzed.map((item) => (
                            <li key={item}>{item}</li>
                          ))}
                        </ul>
                      </div>
                      <div>
                        <strong className="text-slate-800 dark:text-slate-200">
                          O que NÃO é analisado:
                        </strong>
                        <ul className="list-disc list-inside text-slate-500 dark:text-slate-400 mt-1">
                          {prof.what_is_not_analyzed.map((item) => (
                            <li key={item}>{item}</li>
                          ))}
                        </ul>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            </div>
          )}

          {activeTab === "remediation" && (
            <div className="space-y-4">
              <div>
                <h2 className="text-lg font-bold">
                  Base Versionada de Recomendações de Correção (Remediation
                  Engine)
                </h2>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  Orientações técnicas determinísticas com exemplos seguros em
                  múltiplas stacks (Nginx, Apache, Node.js, Python/FastAPI).
                </p>
              </div>

              <div className="space-y-4">
                {(remediationQuery.data ?? []).map((rem) => (
                  <Card key={rem.remediation_id}>
                    <CardHeader className="pb-2">
                      <div className="flex items-center justify-between">
                        <Badge variant="default">{rem.remediation_id}</Badge>
                        <Badge variant="outline">Versão {rem.version}</Badge>
                      </div>
                      <CardTitle className="pt-2">
                        {rem.what_was_identified}
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-3 text-xs">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <div className="p-3 rounded bg-red-500/5 border border-red-500/20">
                          <strong className="text-red-500 block mb-1">
                            Por que é perigoso:
                          </strong>
                          <p className="text-slate-600 dark:text-slate-300">
                            {rem.why_it_is_dangerous}
                          </p>
                        </div>
                        <div className="p-3 rounded bg-emerald-500/5 border border-emerald-500/20">
                          <strong className="text-emerald-500 block mb-1">
                            Como corrigir e validar:
                          </strong>
                          <p className="text-slate-600 dark:text-slate-300">
                            {rem.how_to_fix}
                          </p>
                          <p className="mt-1.5 text-slate-500">
                            <strong>Validação:</strong> {rem.how_to_validate}
                          </p>
                        </div>
                      </div>

                      {rem.secure_examples.length > 0 && (
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
                          {rem.secure_examples.map((ex) => (
                            <div
                              key={`${rem.remediation_id}-${ex.technology}`}
                              className="rounded border border-slate-200 dark:border-slate-800 bg-slate-900 text-slate-100 p-3 font-mono text-[11px]"
                            >
                              <div className="flex items-center justify-between text-sky-400 pb-1.5 mb-1.5 border-b border-slate-800">
                                <span>{ex.technology}</span>
                                <span className="text-slate-500">
                                  {ex.language}
                                </span>
                              </div>
                              <pre className="whitespace-pre-wrap overflow-x-auto">
                                {ex.code}
                              </pre>
                            </div>
                          ))}
                        </div>
                      )}
                    </CardContent>
                  </Card>
                ))}
              </div>
            </div>
          )}

          {activeTab === "scope_validator" && (
            <div className="max-w-3xl space-y-4">
              <div>
                <h2 className="text-lg font-bold">
                  Simulador do Guardrail de Escopo & Proteção Anti-SSRF
                </h2>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  Valide ao vivo como o ScopePolicyValidator bloqueia redes
                  privadas RFC 1918, loopback, metadados de nuvem
                  (169.254.169.254), subdomínios não herdados e caminhos
                  excluídos.
                </p>
              </div>

              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Terminal className="h-4 w-4 text-sky-500" />
                    Testar Política de Escopo na API (/api/v1/scope/validate)
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <form
                    onSubmit={scopeForm.handleSubmit(onSubmitScopeCheck)}
                    className="space-y-4 text-sm"
                  >
                    <div>
                      <label
                        htmlFor="target_url"
                        className="block text-xs font-semibold mb-1"
                      >
                        URL Alvo para Verificação
                      </label>
                      <input
                        id="target_url"
                        type="text"
                        {...scopeForm.register("target_url")}
                        className="w-full rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-2 text-sm"
                      />
                    </div>

                    <div>
                      <label
                        htmlFor="authorized_hosts_csv"
                        className="block text-xs font-semibold mb-1"
                      >
                        Hosts Comprovadamente Autorizados (separados por
                        vírgula)
                      </label>
                      <input
                        id="authorized_hosts_csv"
                        type="text"
                        {...scopeForm.register("authorized_hosts_csv")}
                        className="w-full rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-2 text-sm"
                      />
                    </div>

                    <div>
                      <label
                        htmlFor="excluded_paths_csv"
                        className="block text-xs font-semibold mb-1"
                      >
                        Caminhos Excluídos (Excluded Endpoints)
                      </label>
                      <input
                        id="excluded_paths_csv"
                        type="text"
                        {...scopeForm.register("excluded_paths_csv")}
                        className="w-full rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-3 py-2 text-sm"
                      />
                    </div>

                    <div className="flex items-center gap-2">
                      <input
                        id="allow_subdomains"
                        type="checkbox"
                        {...scopeForm.register("allow_subdomains")}
                        className="rounded border-slate-700"
                      />
                      <label htmlFor="allow_subdomains" className="text-xs">
                        Permitir subdomínios explicitamente comprovados via
                        wildcard DNS
                      </label>
                    </div>

                    <div className="flex flex-wrap gap-2">
                      <Button type="submit" disabled={scopeLoading}>
                        {scopeLoading
                          ? "Validando..."
                          : "Validar Escopo & Anti-SSRF"}
                      </Button>
                      <Button
                        type="button"
                        variant="outline"
                        onClick={() => {
                          scopeForm.setValue(
                            "target_url",
                            "http://169.254.169.254/latest/meta-data/"
                          );
                          scopeForm.setValue(
                            "authorized_hosts_csv",
                            "169.254.169.254"
                          );
                        }}
                      >
                        Testar Bloqueio Cloud Metadata (SSRF)
                      </Button>
                    </div>
                  </form>

                  {scopeResult && (
                    <div
                      className={`mt-4 p-4 rounded-md border text-xs ${
                        scopeResult.allowed
                          ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-300"
                          : "border-red-500/40 bg-red-500/10 text-red-600 dark:text-red-300"
                      }`}
                    >
                      <div className="flex items-center gap-2 font-bold mb-1">
                        {scopeResult.allowed ? (
                          <>
                            <CheckCircle2 className="h-4 w-4" />
                            ESCOPO PERMITIDO
                          </>
                        ) : (
                          <>
                            <ShieldAlert className="h-4 w-4" />
                            ESCOPO BLOQUEADO PELO GUARDRAIL
                          </>
                        )}
                      </div>
                      <p>{scopeResult.reason}</p>
                      {scopeResult.normalized_url && (
                        <p className="mt-1 font-mono">
                          URL Canônica: {scopeResult.normalized_url}
                        </p>
                      )}
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
          )}
        </main>
      </div>

      {comparisonModalOpen && comparisonScanA && comparisonScanB && token && (
        <ScanComparisonModal
          token={token}
          scanIdA={comparisonScanA}
          scanIdB={comparisonScanB}
          onClose={() => {
            setComparisonModalOpen(false);
            setComparisonScanA(null);
            setComparisonScanB(null);
          }}
          onGenerateReport={() => {
            setComparisonModalOpen(false);
            setActiveTab("reports");
          }}
        />
      )}
    </div>
  );
}
