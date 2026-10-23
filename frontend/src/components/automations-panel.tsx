"use client";

import React, { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertCircle,
  Bell,
  Calendar,
  CheckCircle2,
  Clock,
  Copy,
  ExternalLink,
  Key,
  Layers,
  Pause,
  Play,
  Plus,
  RefreshCw,
  Send,
  Shield,
  Trash2,
  Webhook,
  Zap,
} from "lucide-react";

import {
  type ApiToken,
  type ApiTokenCreated,
  type AssetResponse,
  createApiToken,
  createSchedule,
  createTemplate,
  createWebhook,
  deleteSchedule,
  deleteTemplate,
  deleteWebhook,
  getNotificationPreferences,
  listApiTokens,
  listNotifications,
  listSchedules,
  listTemplates,
  listWebhookDeliveries,
  listWebhooks,
  markAllNotificationsRead,
  markNotificationRead,
  type NotificationItem,
  pauseSchedule,
  resumeSchedule,
  revokeApiToken,
  rotateWebhookSecret,
  type ScanSchedule,
  type ScanTemplate,
  seedTemplates,
  testWebhook,
  triggerDueSchedules,
  updateNotificationPreferences,
  type WebhookDelivery,
  type WebhookEndpoint,
} from "@/lib/api";
import { formatDateTime } from "@/lib/soc-utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

interface AutomationsPanelProps {
  token: string;
  role?: string | null;
  assets: AssetResponse[];
}

type TabType = "schedules" | "notifications" | "webhooks" | "tokens" | "templates";

export function AutomationsPanel({ token, role, assets }: AutomationsPanelProps) {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<TabType>("schedules");

  // State: Agendamentos
  const [isCreatingSchedule, setIsCreatingSchedule] = useState(false);
  const [schedAssetId, setSchedAssetId] = useState("");
  const [schedProfile, setSchedProfile] = useState("QUICK");
  const [schedFrequency, setSchedFrequency] = useState("DAILY");
  const [schedCron, setSchedCron] = useState("0 2 * * *");
  const [schedTimezone, setSchedTimezone] = useState("America/Sao_Paulo");
  const [schedFeedback, setSchedFeedback] = useState<string | null>(null);

  // State: Notificações
  const [isEditingPreferences, setIsEditingPreferences] = useState(false);
  const [prefEmailEnabled, setPrefEmailEnabled] = useState(false);
  const [prefEmailDest, setPrefEmailDest] = useState("");
  const [prefMinSeverity, setPrefMinSeverity] = useState("HIGH");
  const [notifFeedback, setNotifFeedback] = useState<string | null>(null);

  // State: Webhooks
  const [isCreatingWebhook, setIsCreatingWebhook] = useState(false);
  const [webhookUrl, setWebhookUrl] = useState("");
  const [webhookDesc, setWebhookDesc] = useState("");
  const [webhookFeedback, setWebhookFeedback] = useState<string | null>(null);
  const [selectedWebhookForDeliveries, setSelectedWebhookForDeliveries] = useState<string | null>(null);
  const [rotatedSecretModal, setRotatedSecretModal] = useState<{ id: string; secret: string } | null>(null);

  // State: Tokens de API
  const [isCreatingToken, setIsCreatingToken] = useState(false);
  const [tokenName, setTokenName] = useState("");
  const [tokenExpiresDays, setTokenExpiresDays] = useState(90);
  const [tokenScopes, setTokenScopes] = useState<string[]>(["scans:read", "findings:read"]);
  const [createdTokenModal, setCreatedTokenModal] = useState<ApiTokenCreated | null>(null);
  const [tokenFeedback, setTokenFeedback] = useState<string | null>(null);

  // State: Templates
  const [isCreatingTemplate, setIsCreatingTemplate] = useState(false);
  const [tplName, setTplName] = useState("");
  const [tplDesc, setTplDesc] = useState("");
  const [tplProfile, setTplProfile] = useState("QUICK");
  const [tplEnv, setTplEnv] = useState("PRODUCTION");
  const [templateFeedback, setTemplateFeedback] = useState<string | null>(null);

  // Queries
  const { data: schedulesData, isLoading: loadingSchedules, refetch: refetchSchedules } = useQuery({
    queryKey: ["automations", "schedules", token],
    queryFn: () => listSchedules(token),
    enabled: activeTab === "schedules",
  });

  const { data: notificationsData, isLoading: loadingNotifications, refetch: refetchNotifications } = useQuery({
    queryKey: ["automations", "notifications", token],
    queryFn: () => listNotifications(token),
    enabled: activeTab === "notifications",
  });

  const { data: preferencesData, refetch: refetchPreferences } = useQuery({
    queryKey: ["automations", "preferences", token],
    queryFn: () => getNotificationPreferences(token),
    enabled: activeTab === "notifications" && isEditingPreferences,
  });

  const { data: webhooksData, isLoading: loadingWebhooks, refetch: refetchWebhooks } = useQuery({
    queryKey: ["automations", "webhooks", token],
    queryFn: () => listWebhooks(token),
    enabled: activeTab === "webhooks",
  });

  const { data: deliveriesData, isLoading: loadingDeliveries } = useQuery({
    queryKey: ["automations", "deliveries", token, selectedWebhookForDeliveries],
    queryFn: () => listWebhookDeliveries(token, { webhook_id: selectedWebhookForDeliveries || undefined }),
    enabled: !!selectedWebhookForDeliveries,
  });

  const { data: tokensData, isLoading: loadingTokens, refetch: refetchTokens } = useQuery({
    queryKey: ["automations", "tokens", token],
    queryFn: () => listApiTokens(token),
    enabled: activeTab === "tokens",
  });

  const { data: templatesData, isLoading: loadingTemplates, refetch: refetchTemplates } = useQuery({
    queryKey: ["automations", "templates", token],
    queryFn: () => listTemplates(token),
    enabled: activeTab === "templates",
  });

  // Mutações: Agendamentos
  const createScheduleMutation = useMutation({
    mutationFn: () =>
      createSchedule(token, {
        asset_id: schedAssetId,
        profile_type: schedProfile,
        frequency: schedFrequency,
        cron_expression: schedCron,
        timezone: schedTimezone,
      }),
    onSuccess: () => {
      setIsCreatingSchedule(false);
      setSchedFeedback("Agendamento criado com sucesso!");
      refetchSchedules();
      setTimeout(() => setSchedFeedback(null), 4000);
    },
    onError: (err: any) => setSchedFeedback(err.message || "Erro ao criar agendamento."),
  });

  const pauseScheduleMutation = useMutation({
    mutationFn: (id: string) => pauseSchedule(token, id),
    onSuccess: () => refetchSchedules(),
  });

  const resumeScheduleMutation = useMutation({
    mutationFn: (id: string) => resumeSchedule(token, id),
    onSuccess: () => refetchSchedules(),
  });

  const deleteScheduleMutation = useMutation({
    mutationFn: (id: string) => deleteSchedule(token, id),
    onSuccess: () => refetchSchedules(),
  });

  const triggerDueMutation = useMutation({
    mutationFn: () => triggerDueSchedules(token),
    onSuccess: (data) => {
      setSchedFeedback(`Verificação executada: ${data.triggered_scan_ids.length} auditorias disparadas.`);
      refetchSchedules();
      setTimeout(() => setSchedFeedback(null), 4000);
    },
  });

  // Mutações: Notificações
  const markReadMutation = useMutation({
    mutationFn: (id: string) => markNotificationRead(token, id),
    onSuccess: () => refetchNotifications(),
  });

  const markAllReadMutation = useMutation({
    mutationFn: () => markAllNotificationsRead(token),
    onSuccess: () => refetchNotifications(),
  });

  const updatePreferencesMutation = useMutation({
    mutationFn: () =>
      updateNotificationPreferences(token, {
        email_enabled: prefEmailEnabled,
        email_destination: prefEmailDest || null,
        min_severity: prefMinSeverity,
      }),
    onSuccess: () => {
      setIsEditingPreferences(false);
      setNotifFeedback("Preferências salvas com sucesso!");
      setTimeout(() => setNotifFeedback(null), 4000);
    },
  });

  // Mutações: Webhooks
  const createWebhookMutation = useMutation({
    mutationFn: () =>
      createWebhook(token, {
        url: webhookUrl,
        description: webhookDesc || undefined,
      }),
    onSuccess: () => {
      setIsCreatingWebhook(false);
      setWebhookUrl("");
      setWebhookDesc("");
      setWebhookFeedback("Webhook cadastrado com sucesso!");
      refetchWebhooks();
      setTimeout(() => setWebhookFeedback(null), 4000);
    },
    onError: (err: any) => setWebhookFeedback(err.message || "Erro ao cadastrar webhook."),
  });

  const deleteWebhookMutation = useMutation({
    mutationFn: (id: string) => deleteWebhook(token, id),
    onSuccess: () => refetchWebhooks(),
  });

  const rotateSecretMutation = useMutation({
    mutationFn: (id: string) => rotateWebhookSecret(token, id),
    onSuccess: (data) => {
      setRotatedSecretModal({ id: data.id, secret: data.new_secret_token });
      refetchWebhooks();
    },
  });

  const testWebhookMutation = useMutation({
    mutationFn: (id: string) => testWebhook(token, id),
    onSuccess: (data) => {
      setWebhookFeedback(`Teste ${data.status}: ${data.message} (${data.duration_ms || 0}ms)`);
      setTimeout(() => setWebhookFeedback(null), 5000);
    },
    onError: (err: any) => setWebhookFeedback(`Erro no teste: ${err.message}`),
  });

  // Mutações: Chaves de API
  const createTokenMutation = useMutation({
    mutationFn: () =>
      createApiToken(token, {
        name: tokenName,
        scopes: tokenScopes,
        expires_in_days: tokenExpiresDays || null,
      }),
    onSuccess: (data) => {
      setIsCreatingToken(false);
      setCreatedTokenModal(data);
      setTokenName("");
      refetchTokens();
    },
    onError: (err: any) => setTokenFeedback(err.message || "Erro ao criar chave de API."),
  });

  const revokeTokenMutation = useMutation({
    mutationFn: (id: string) => revokeApiToken(token, id),
    onSuccess: () => refetchTokens(),
  });

  // Mutações: Templates
  const seedTemplatesMutation = useMutation({
    mutationFn: () => seedTemplates(token),
    onSuccess: () => {
      setTemplateFeedback("Templates padrão carregados com sucesso!");
      refetchTemplates();
      setTimeout(() => setTemplateFeedback(null), 4000);
    },
  });

  const createTemplateMutation = useMutation({
    mutationFn: () =>
      createTemplate(token, {
        name: tplName,
        description: tplDesc || undefined,
        profile_type: tplProfile,
        environment_type: tplEnv,
      }),
    onSuccess: () => {
      setIsCreatingTemplate(false);
      setTplName("");
      setTplDesc("");
      setTemplateFeedback("Template de auditoria criado com sucesso!");
      refetchTemplates();
      setTimeout(() => setTemplateFeedback(null), 4000);
    },
    onError: (err: any) => setTemplateFeedback(err.message || "Erro ao criar template."),
  });

  const deleteTemplateMutation = useMutation({
    mutationFn: (id: string) => deleteTemplate(token, id),
    onSuccess: () => refetchTemplates(),
  });

  const verifiedAssets = assets.filter((a) => a.authorization_status === "VERIFIED");

  const getSeverityBadge = (severity: string) => {
    switch (severity.toUpperCase()) {
      case "CRITICAL":
        return <Badge className="bg-red-950 text-red-400 border-red-800">CRÍTICO</Badge>;
      case "HIGH":
        return <Badge className="bg-orange-950 text-orange-400 border-orange-800">ALTO</Badge>;
      case "MEDIUM":
        return <Badge className="bg-amber-950 text-amber-400 border-amber-800">MÉDIO</Badge>;
      case "LOW":
        return <Badge className="bg-blue-950 text-blue-400 border-blue-800">BAIXO</Badge>;
      default:
        return <Badge className="bg-emerald-950 text-emerald-400 border-emerald-800">INFO</Badge>;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header com Navegação de Sub-abas */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 bg-slate-900/80 p-4 rounded-xl border border-slate-800">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Zap className="w-5 h-5 text-indigo-400" />
            Automações, Agendamentos e Integrações (Fase 7)
          </h2>
          <p className="text-sm text-slate-400">
            Orquestração contínua, canal de notificações in-app e SMTP, webhooks com HMAC e chaves de API para CI/CD.
          </p>
        </div>

        {/* Sub-tabs pills */}
        <div className="flex flex-wrap gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800">
          <Button
            size="sm"
            variant={activeTab === "schedules" ? "default" : "ghost"}
            className={activeTab === "schedules" ? "bg-indigo-600 hover:bg-indigo-700 text-white" : "text-slate-400"}
            onClick={() => setActiveTab("schedules")}
          >
            <Calendar className="w-4 h-4 mr-1.5" />
            Agendamentos
          </Button>
          <Button
            size="sm"
            variant={activeTab === "notifications" ? "default" : "ghost"}
            className={activeTab === "notifications" ? "bg-indigo-600 hover:bg-indigo-700 text-white" : "text-slate-400"}
            onClick={() => setActiveTab("notifications")}
          >
            <Bell className="w-4 h-4 mr-1.5" />
            Notificações
            {notificationsData?.unread_count ? (
              <span className="ml-1 px-1.5 py-0.5 text-xs bg-red-600 text-white rounded-full">
                {notificationsData.unread_count}
              </span>
            ) : null}
          </Button>
          <Button
            size="sm"
            variant={activeTab === "webhooks" ? "default" : "ghost"}
            className={activeTab === "webhooks" ? "bg-indigo-600 hover:bg-indigo-700 text-white" : "text-slate-400"}
            onClick={() => setActiveTab("webhooks")}
          >
            <Webhook className="w-4 h-4 mr-1.5" />
            Webhooks
          </Button>
          <Button
            size="sm"
            variant={activeTab === "tokens" ? "default" : "ghost"}
            className={activeTab === "tokens" ? "bg-indigo-600 hover:bg-indigo-700 text-white" : "text-slate-400"}
            onClick={() => setActiveTab("tokens")}
          >
            <Key className="w-4 h-4 mr-1.5" />
            Chaves de API
          </Button>
          <Button
            size="sm"
            variant={activeTab === "templates" ? "default" : "ghost"}
            className={activeTab === "templates" ? "bg-indigo-600 hover:bg-indigo-700 text-white" : "text-slate-400"}
            onClick={() => setActiveTab("templates")}
          >
            <Layers className="w-4 h-4 mr-1.5" />
            Templates
          </Button>
        </div>
      </div>

      {/* =================================================================== */}
      {/* ABA 1: AGENDAMENTOS                                                 */}
      {/* =================================================================== */}
      {activeTab === "schedules" && (
        <div className="space-y-4">
          <div className="flex justify-between items-center">
            <div className="flex items-center gap-3">
              <Button
                variant="outline"
                size="sm"
                onClick={() => refetchSchedules()}
                className="border-slate-700 text-slate-300 hover:bg-slate-800"
              >
                <RefreshCw className="w-4 h-4 mr-1.5" />
                Atualizar
              </Button>
              <Button
                variant="secondary"
                size="sm"
                onClick={() => triggerDueMutation.mutate()}
                disabled={triggerDueMutation.isPending}
                className="bg-slate-800 text-slate-200 hover:bg-slate-700"
              >
                <Play className="w-4 h-4 mr-1.5 text-emerald-400" />
                Disparar Verificação Manual
              </Button>
            </div>

            <Button
              size="sm"
              onClick={() => setIsCreatingSchedule(true)}
              className="bg-indigo-600 hover:bg-indigo-700 text-white"
            >
              <Plus className="w-4 h-4 mr-1.5" />
              Novo Agendamento
            </Button>
          </div>

          {schedFeedback && (
            <div className="p-3 bg-indigo-950/60 border border-indigo-800 text-indigo-300 text-sm rounded-lg flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-indigo-400" />
              {schedFeedback}
            </div>
          )}

          {/* Modal / Formulário de Criação de Agendamento */}
          {isCreatingSchedule && (
            <Card className="bg-slate-900 border-indigo-800">
              <CardHeader>
                <CardTitle className="text-base text-slate-100 flex items-center gap-2">
                  <Calendar className="w-4 h-4 text-indigo-400" />
                  Configurar Novo Agendamento de Auditoria
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="text-xs text-slate-400 font-medium">Ativo Autorizado</label>
                    <select
                      value={schedAssetId}
                      onChange={(e) => setSchedAssetId(e.target.value)}
                      className="w-full mt-1 bg-slate-950 border border-slate-700 text-slate-200 text-sm rounded-md p-2"
                    >
                      <option value="">Selecione um ativo verificado...</option>
                      {verifiedAssets.map((asset) => (
                        <option key={asset.id} value={asset.id}>
                          {asset.name} ({asset.hostname})
                        </option>
                      ))}
                    </select>
                  </div>

                  <div>
                    <label className="text-xs text-slate-400 font-medium">Perfil de Auditoria</label>
                    <select
                      value={schedProfile}
                      onChange={(e) => setSchedProfile(e.target.value)}
                      className="w-full mt-1 bg-slate-950 border border-slate-700 text-slate-200 text-sm rounded-md p-2"
                    >
                      <option value="QUICK">QUICK — Verificação Rápida e Perímetro</option>
                      <option value="FULL">FULL — Auditoria Completa OWASP</option>
                      <option value="API">API — Focada em Endpoints e Autenticação</option>
                      <option value="PASSIVE">PASSIVE — Não Invasiva</option>
                    </select>
                  </div>

                  <div>
                    <label className="text-xs text-slate-400 font-medium">Frequência</label>
                    <select
                      value={schedFrequency}
                      onChange={(e) => {
                        setSchedFrequency(e.target.value);
                        if (e.target.value === "DAILY") setSchedCron("0 2 * * *");
                        if (e.target.value === "WEEKLY") setSchedCron("0 2 * * 1");
                        if (e.target.value === "MONTHLY") setSchedCron("0 2 1 * *");
                      }}
                      className="w-full mt-1 bg-slate-950 border border-slate-700 text-slate-200 text-sm rounded-md p-2"
                    >
                      <option value="DAILY">Diária (02:00)</option>
                      <option value="WEEKLY">Semanal (Segunda-feira 02:00)</option>
                      <option value="MONTHLY">Mensal (Dia 1º 02:00)</option>
                      <option value="CRON">Personalizada (Expressão Cron)</option>
                    </select>
                  </div>

                  <div>
                    <label className="text-xs text-slate-400 font-medium">Expressão Cron (5 campos)</label>
                    <input
                      type="text"
                      value={schedCron}
                      onChange={(e) => setSchedCron(e.target.value)}
                      disabled={schedFrequency !== "CRON"}
                      placeholder="0 2 * * *"
                      className="w-full mt-1 bg-slate-950 border border-slate-700 text-slate-200 text-sm rounded-md p-2 disabled:opacity-50"
                    />
                  </div>

                  <div>
                    <label className="text-xs text-slate-400 font-medium">Fuso Horário (IANA)</label>
                    <input
                      type="text"
                      value={schedTimezone}
                      onChange={(e) => setSchedTimezone(e.target.value)}
                      placeholder="America/Sao_Paulo"
                      className="w-full mt-1 bg-slate-950 border border-slate-700 text-slate-200 text-sm rounded-md p-2"
                    />
                  </div>
                </div>

                <div className="flex justify-end gap-2 pt-2">
                  <Button variant="ghost" size="sm" onClick={() => setIsCreatingSchedule(false)}>
                    Cancelar
                  </Button>
                  <Button
                    size="sm"
                    onClick={() => createScheduleMutation.mutate()}
                    disabled={!schedAssetId || createScheduleMutation.isPending}
                    className="bg-indigo-600 hover:bg-indigo-700 text-white"
                  >
                    Salvar Agendamento
                  </Button>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Tabela de Agendamentos */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-sm">
                <thead>
                  <tr className="border-b border-slate-800 bg-slate-950/60 text-slate-400 text-xs font-semibold uppercase tracking-wider">
                    <th className="py-3 px-4">Ativo</th>
                    <th className="py-3 px-4">Perfil</th>
                    <th className="py-3 px-4">Frequência</th>
                    <th className="py-3 px-4">Próxima Execução</th>
                    <th className="py-3 px-4">Status</th>
                    <th className="py-3 px-4 text-right">Ações</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800 text-slate-300">
                  {loadingSchedules ? (
                    <tr>
                      <td colSpan={6} className="py-8 text-center text-slate-500">
                        Carregando agendamentos...
                      </td>
                    </tr>
                  ) : !schedulesData?.items.length ? (
                    <tr>
                      <td colSpan={6} className="py-8 text-center text-slate-500">
                        Nenhum agendamento configurado. Crie um agendamento para auditorias periódicas contínuas.
                      </td>
                    </tr>
                  ) : (
                    schedulesData.items.map((sched) => (
                      <tr key={sched.id} className="hover:bg-slate-800/40 transition">
                        <td className="py-3 px-4 font-medium text-slate-200">
                          {sched.asset_name || sched.asset_id}
                        </td>
                        <td className="py-3 px-4">
                          <Badge variant="outline" className="border-slate-700 text-slate-300">
                            {sched.profile_type}
                          </Badge>
                        </td>
                        <td className="py-3 px-4 text-xs font-mono text-slate-400">
                          {sched.frequency} ({sched.cron_expression})
                        </td>
                        <td className="py-3 px-4 text-xs text-slate-300">
                          {sched.next_run_at ? formatDateTime(sched.next_run_at) : "—"}
                        </td>
                        <td className="py-3 px-4">
                          {sched.status === "ACTIVE" ? (
                            <Badge className="bg-emerald-950 text-emerald-400 border-emerald-800">ATIVO</Badge>
                          ) : sched.status === "PAUSED" ? (
                            <Badge className="bg-amber-950 text-amber-400 border-amber-800">PAUSADO</Badge>
                          ) : (
                            <Badge className="bg-red-950 text-red-400 border-red-800">{sched.status}</Badge>
                          )}
                        </td>
                        <td className="py-3 px-4 text-right space-x-2">
                          {sched.status === "ACTIVE" ? (
                            <Button
                              variant="ghost"
                              size="sm"
                              className="text-amber-400 hover:bg-slate-800"
                              onClick={() => pauseScheduleMutation.mutate(sched.id)}
                            >
                              <Pause className="w-3.5 h-3.5 mr-1" />
                              Pausar
                            </Button>
                          ) : (
                            <Button
                              variant="ghost"
                              size="sm"
                              className="text-emerald-400 hover:bg-slate-800"
                              onClick={() => resumeScheduleMutation.mutate(sched.id)}
                            >
                              <Play className="w-3.5 h-3.5 mr-1" />
                              Retomar
                            </Button>
                          )}
                          <Button
                            variant="ghost"
                            size="sm"
                            className="text-red-400 hover:bg-slate-800"
                            onClick={() => deleteScheduleMutation.mutate(sched.id)}
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </Button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* =================================================================== */}
      {/* ABA 2: NOTIFICAÇÕES & ALERTAS                                       */}
      {/* =================================================================== */}
      {activeTab === "notifications" && (
        <div className="space-y-4">
          <div className="flex justify-between items-center">
            <div className="flex items-center gap-3">
              <Button
                variant="outline"
                size="sm"
                onClick={() => refetchNotifications()}
                className="border-slate-700 text-slate-300 hover:bg-slate-800"
              >
                <RefreshCw className="w-4 h-4 mr-1.5" />
                Atualizar
              </Button>
              <Button
                variant="secondary"
                size="sm"
                onClick={() => markAllReadMutation.mutate()}
                className="bg-slate-800 text-slate-200 hover:bg-slate-700"
              >
                <CheckCircle2 className="w-4 h-4 mr-1.5 text-indigo-400" />
                Marcar Todas como Lidas
              </Button>
            </div>

            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                if (preferencesData) {
                  setPrefEmailEnabled(preferencesData.email_enabled);
                  setPrefEmailDest(preferencesData.email_destination || "");
                  setPrefMinSeverity(preferencesData.min_severity);
                }
                setIsEditingPreferences(!isEditingPreferences);
              }}
              className="border-slate-700 text-slate-300 hover:bg-slate-800"
            >
              Configurar Alertas e Email
            </Button>
          </div>

          {notifFeedback && (
            <div className="p-3 bg-indigo-950/60 border border-indigo-800 text-indigo-300 text-sm rounded-lg flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-indigo-400" />
              {notifFeedback}
            </div>
          )}

          {/* Configuração de Preferências */}
          {isEditingPreferences && (
            <Card className="bg-slate-900 border-indigo-800">
              <CardHeader>
                <CardTitle className="text-base text-slate-100 flex items-center gap-2">
                  <Bell className="w-4 h-4 text-indigo-400" />
                  Preferências de Alertas e Notificações por Email
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="flex items-center gap-3 pt-6">
                    <input
                      type="checkbox"
                      id="emailToggle"
                      checked={prefEmailEnabled}
                      onChange={(e) => setPrefEmailEnabled(e.target.checked)}
                      className="w-4 h-4 rounded bg-slate-950 border-slate-700 text-indigo-600"
                    />
                    <label htmlFor="emailToggle" className="text-sm text-slate-200">
                      Habilitar Envio por Email (SMTP)
                    </label>
                  </div>

                  <div>
                    <label className="text-xs text-slate-400 font-medium">Destino de Email Alternativo</label>
                    <input
                      type="email"
                      value={prefEmailDest}
                      onChange={(e) => setPrefEmailDest(e.target.value)}
                      placeholder="alerts-soc@empresa.com"
                      className="w-full mt-1 bg-slate-950 border border-slate-700 text-slate-200 text-sm rounded-md p-2"
                    />
                  </div>

                  <div>
                    <label className="text-xs text-slate-400 font-medium">Severidade Mínima para Alerta</label>
                    <select
                      value={prefMinSeverity}
                      onChange={(e) => setPrefMinSeverity(e.target.value)}
                      className="w-full mt-1 bg-slate-950 border border-slate-700 text-slate-200 text-sm rounded-md p-2"
                    >
                      <option value="INFO">INFO (Todos os eventos)</option>
                      <option value="LOW">LOW (Baixo ou superior)</option>
                      <option value="MEDIUM">MEDIUM (Médio ou superior)</option>
                      <option value="HIGH">HIGH (Alto e Crítico)</option>
                      <option value="CRITICAL">CRITICAL (Somente Crítico)</option>
                    </select>
                  </div>
                </div>

                <div className="flex justify-end gap-2 pt-2">
                  <Button variant="ghost" size="sm" onClick={() => setIsEditingPreferences(false)}>
                    Cancelar
                  </Button>
                  <Button
                    size="sm"
                    onClick={() => updatePreferencesMutation.mutate()}
                    className="bg-indigo-600 hover:bg-indigo-700 text-white"
                  >
                    Salvar Preferências
                  </Button>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Lista de Notificações */}
          <div className="space-y-2">
            {loadingNotifications ? (
              <div className="py-8 text-center text-slate-500">Carregando notificações...</div>
            ) : !notificationsData?.items.length ? (
              <div className="py-8 text-center text-slate-500">Nenhuma notificação registrada no momento.</div>
            ) : (
              notificationsData.items.map((item) => (
                <div
                  key={item.id}
                  className={`p-4 rounded-xl border transition flex items-start justify-between gap-4 ${
                    item.read_at
                      ? "bg-slate-900/40 border-slate-800/60 opacity-75"
                      : "bg-slate-900 border-slate-700/80 shadow-md"
                  }`}
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      {getSeverityBadge(item.severity)}
                      <Badge variant="outline" className="text-xs text-slate-400 border-slate-700 font-mono">
                        {item.event_type}
                      </Badge>
                      <span className="text-xs text-slate-500">{formatDateTime(item.created_at)}</span>
                    </div>
                    <h4 className="text-sm font-semibold text-slate-200">{item.title}</h4>
                    <p className="text-xs text-slate-400 whitespace-pre-wrap">{item.message}</p>
                    {item.link_url && (
                      <a
                        href={item.link_url}
                        target="_blank"
                        rel="noreferrer"
                        className="text-xs text-indigo-400 hover:underline inline-flex items-center gap-1 pt-1"
                      >
                        Abrir Recurso <ExternalLink className="w-3 h-3" />
                      </a>
                    )}
                  </div>

                  {!item.read_at && (
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => markReadMutation.mutate(item.id)}
                      className="text-xs text-slate-400 hover:text-slate-200"
                    >
                      Marcar lida
                    </Button>
                  )}
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* =================================================================== */}
      {/* ABA 3: WEBHOOKS                                                     */}
      {/* =================================================================== */}
      {activeTab === "webhooks" && (
        <div className="space-y-4">
          <div className="flex justify-between items-center">
            <Button
              variant="outline"
              size="sm"
              onClick={() => refetchWebhooks()}
              className="border-slate-700 text-slate-300 hover:bg-slate-800"
            >
              <RefreshCw className="w-4 h-4 mr-1.5" />
              Atualizar
            </Button>

            <Button
              size="sm"
              onClick={() => setIsCreatingWebhook(true)}
              className="bg-indigo-600 hover:bg-indigo-700 text-white"
            >
              <Plus className="w-4 h-4 mr-1.5" />
              Cadastrar Webhook
            </Button>
          </div>

          {webhookFeedback && (
            <div className="p-3 bg-indigo-950/60 border border-indigo-800 text-indigo-300 text-sm rounded-lg flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-indigo-400" />
              {webhookFeedback}
            </div>
          )}

          {/* Modal de Segredo Rotacionado */}
          {rotatedSecretModal && (
            <div className="p-4 bg-amber-950/60 border border-amber-700 rounded-xl space-y-2">
              <h4 className="text-sm font-semibold text-amber-300 flex items-center gap-2">
                <AlertCircle className="w-4 h-4 text-amber-400" />
                Novo Segredo HMAC Gerado
              </h4>
              <p className="text-xs text-amber-200">
                Guarde este segredo agora para validar assinaturas HMAC-SHA256 no cabeçalho X-CSC-Signature:
              </p>
              <div className="flex items-center gap-2 bg-slate-950 p-2 rounded border border-slate-800 font-mono text-xs text-emerald-400">
                <span className="flex-1 select-all">{rotatedSecretModal.secret}</span>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => navigator.clipboard.writeText(rotatedSecretModal.secret)}
                >
                  <Copy className="w-3.5 h-3.5" />
                </Button>
              </div>
              <Button size="sm" variant="outline" onClick={() => setRotatedSecretModal(null)} className="mt-2">
                Fechar
              </Button>
            </div>
          )}

          {/* Cadastro de Novo Webhook */}
          {isCreatingWebhook && (
            <Card className="bg-slate-900 border-indigo-800">
              <CardHeader>
                <CardTitle className="text-base text-slate-100 flex items-center gap-2">
                  <Webhook className="w-4 h-4 text-indigo-400" />
                  Cadastrar Endpoint de Webhook (Anti-SSRF e HMAC-SHA256)
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <label className="text-xs text-slate-400 font-medium">URL de Destino (HTTPS Obrigatório)</label>
                  <input
                    type="url"
                    value={webhookUrl}
                    onChange={(e) => setWebhookUrl(e.target.value)}
                    placeholder="https://siem.empresa.com/api/v1/events"
                    className="w-full mt-1 bg-slate-950 border border-slate-700 text-slate-200 text-sm rounded-md p-2"
                  />
                  <p className="text-xs text-slate-500 mt-1">
                    Redes privadas RFC 1918 e metadados de nuvem são bloqueados por segurança por padrão.
                  </p>
                </div>

                <div>
                  <label className="text-xs text-slate-400 font-medium">Descrição / Identificador</label>
                  <input
                    type="text"
                    value={webhookDesc}
                    onChange={(e) => setWebhookDesc(e.target.value)}
                    placeholder="Integração Splunk SOC ou Discord Channel"
                    className="w-full mt-1 bg-slate-950 border border-slate-700 text-slate-200 text-sm rounded-md p-2"
                  />
                </div>

                <div className="flex justify-end gap-2 pt-2">
                  <Button variant="ghost" size="sm" onClick={() => setIsCreatingWebhook(false)}>
                    Cancelar
                  </Button>
                  <Button
                    size="sm"
                    onClick={() => createWebhookMutation.mutate()}
                    disabled={!webhookUrl || createWebhookMutation.isPending}
                    className="bg-indigo-600 hover:bg-indigo-700 text-white"
                  >
                    Salvar Webhook
                  </Button>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Tabela de Webhooks */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-sm">
                <thead>
                  <tr className="border-b border-slate-800 bg-slate-950/60 text-slate-400 text-xs font-semibold uppercase tracking-wider">
                    <th className="py-3 px-4">URL</th>
                    <th className="py-3 px-4">Descrição</th>
                    <th className="py-3 px-4">Segredo HMAC</th>
                    <th className="py-3 px-4">Status</th>
                    <th className="py-3 px-4 text-right">Ações</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800 text-slate-300">
                  {loadingWebhooks ? (
                    <tr>
                      <td colSpan={5} className="py-8 text-center text-slate-500">
                        Carregando webhooks...
                      </td>
                    </tr>
                  ) : !webhooksData?.length ? (
                    <tr>
                      <td colSpan={5} className="py-8 text-center text-slate-500">
                        Nenhum endpoint de webhook cadastrado.
                      </td>
                    </tr>
                  ) : (
                    webhooksData.map((ep) => (
                      <tr key={ep.id} className="hover:bg-slate-800/40 transition">
                        <td className="py-3 px-4 font-mono text-xs text-indigo-300 max-w-xs truncate">
                          {ep.url}
                        </td>
                        <td className="py-3 px-4 text-xs text-slate-300">{ep.description || "—"}</td>
                        <td className="py-3 px-4 font-mono text-xs text-slate-400">
                          {ep.secret_token_prefix}
                        </td>
                        <td className="py-3 px-4">
                          {ep.is_active ? (
                            <Badge className="bg-emerald-950 text-emerald-400 border-emerald-800">ATIVO</Badge>
                          ) : (
                            <Badge className="bg-red-950 text-red-400 border-red-800">
                              INATIVO ({ep.consecutive_failures} falhas)
                            </Badge>
                          )}
                        </td>
                        <td className="py-3 px-4 text-right space-x-2">
                          <Button
                            variant="ghost"
                            size="sm"
                            className="text-indigo-400 hover:bg-slate-800"
                            onClick={() => testWebhookMutation.mutate(ep.id)}
                            title="Disparar ping de teste"
                          >
                            <Send className="w-3.5 h-3.5 mr-1" />
                            Testar
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            className="text-amber-400 hover:bg-slate-800"
                            onClick={() => rotateSecretMutation.mutate(ep.id)}
                            title="Rotacionar segredo HMAC"
                          >
                            <RefreshCw className="w-3.5 h-3.5" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            className="text-slate-400 hover:bg-slate-800"
                            onClick={() => setSelectedWebhookForDeliveries(ep.id)}
                            title="Ver histórico de entregas"
                          >
                            <Clock className="w-3.5 h-3.5" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            className="text-red-400 hover:bg-slate-800"
                            onClick={() => deleteWebhookMutation.mutate(ep.id)}
                            title="Remover webhook"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </Button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Histórico de Entregas do Webhook Selecionado */}
          {selectedWebhookForDeliveries && (
            <Card className="bg-slate-900 border-slate-800 mt-4">
              <CardHeader className="flex flex-row justify-between items-center">
                <CardTitle className="text-sm text-slate-100 flex items-center gap-2">
                  <Clock className="w-4 h-4 text-indigo-400" />
                  Histórico de Entregas do Webhook
                </CardTitle>
                <Button size="sm" variant="ghost" onClick={() => setSelectedWebhookForDeliveries(null)}>
                  Fechar
                </Button>
              </CardHeader>
              <CardContent>
                {loadingDeliveries ? (
                  <div className="py-4 text-center text-slate-500">Carregando histórico...</div>
                ) : !deliveriesData?.items.length ? (
                  <div className="py-4 text-center text-slate-500">Nenhuma entrega registrada ainda.</div>
                ) : (
                  <div className="space-y-2">
                    {deliveriesData.items.map((del) => (
                      <div
                        key={del.id}
                        className="p-3 bg-slate-950 rounded border border-slate-800 flex justify-between items-center text-xs"
                      >
                        <div>
                          <span className="font-mono text-indigo-300 font-semibold">{del.event_type}</span>
                          <span className="ml-2 text-slate-500">{formatDateTime(del.created_at)}</span>
                          {del.error_message && (
                            <p className="text-red-400 mt-1 font-mono">{del.error_message}</p>
                          )}
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="text-slate-400">{del.duration_ms || 0}ms</span>
                          {del.status === "DELIVERED" ? (
                            <Badge className="bg-emerald-950 text-emerald-400 border-emerald-800">
                              {del.status_code || 200} OK
                            </Badge>
                          ) : (
                            <Badge className="bg-red-950 text-red-400 border-red-800">
                              {del.status_code || "FALHA"}
                            </Badge>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          )}
        </div>
      )}

      {/* =================================================================== */}
      {/* ABA 4: CHAVES DE API (TOKENS)                                       */}
      {/* =================================================================== */}
      {activeTab === "tokens" && (
        <div className="space-y-4">
          <div className="flex justify-between items-center">
            <Button
              variant="outline"
              size="sm"
              onClick={() => refetchTokens()}
              className="border-slate-700 text-slate-300 hover:bg-slate-800"
            >
              <RefreshCw className="w-4 h-4 mr-1.5" />
              Atualizar
            </Button>

            <Button
              size="sm"
              onClick={() => setIsCreatingToken(true)}
              className="bg-indigo-600 hover:bg-indigo-700 text-white"
            >
              <Plus className="w-4 h-4 mr-1.5" />
              Gerar Nova Chave de API
            </Button>
          </div>

          {tokenFeedback && (
            <div className="p-3 bg-indigo-950/60 border border-indigo-800 text-indigo-300 text-sm rounded-lg flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-indigo-400" />
              {tokenFeedback}
            </div>
          )}

          {/* Modal de Revelação Única da Chave de API */}
          {createdTokenModal && (
            <div className="p-4 bg-emerald-950/60 border border-emerald-700 rounded-xl space-y-3">
              <h4 className="text-sm font-semibold text-emerald-300 flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                Chave de API Gerada com Sucesso
              </h4>
              <p className="text-xs text-emerald-200">
                Esta chave completa é exibida <strong>UMA ÚNICA VEZ</strong>. Armazene em seus segredos de CI/CD ou gerenciador de senhas:
              </p>
              <div className="flex items-center gap-2 bg-slate-950 p-2.5 rounded border border-slate-800 font-mono text-xs text-emerald-400">
                <span className="flex-1 select-all break-all">{createdTokenModal.raw_api_token}</span>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => navigator.clipboard.writeText(createdTokenModal.raw_api_token)}
                >
                  <Copy className="w-3.5 h-3.5" />
                </Button>
              </div>
              <Button size="sm" variant="outline" onClick={() => setCreatedTokenModal(null)} className="mt-2">
                Entendido e Copiado
              </Button>
            </div>
          )}

          {/* Modal de Criação de Chave */}
          {isCreatingToken && (
            <Card className="bg-slate-900 border-indigo-800">
              <CardHeader>
                <CardTitle className="text-base text-slate-100 flex items-center gap-2">
                  <Key className="w-4 h-4 text-indigo-400" />
                  Gerar Chave de Integração de API
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="text-xs text-slate-400 font-medium">Nome Identificador</label>
                    <input
                      type="text"
                      value={tokenName}
                      onChange={(e) => setTokenName(e.target.value)}
                      placeholder="Ex: GitHub Actions CI/CD Pipeline"
                      className="w-full mt-1 bg-slate-950 border border-slate-700 text-slate-200 text-sm rounded-md p-2"
                    />
                  </div>

                  <div>
                    <label className="text-xs text-slate-400 font-medium">Expiração</label>
                    <select
                      value={tokenExpiresDays}
                      onChange={(e) => setTokenExpiresDays(Number(e.target.value))}
                      className="w-full mt-1 bg-slate-950 border border-slate-700 text-slate-200 text-sm rounded-md p-2"
                    >
                      <option value={30}>30 Dias</option>
                      <option value={60}>60 Dias</option>
                      <option value={90}>90 Dias (Recomendado)</option>
                      <option value={365}>1 Ano</option>
                    </select>
                  </div>
                </div>

                <div>
                  <label className="text-xs text-slate-400 font-medium block mb-2">Escopos de Acesso Autorizados</label>
                  <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
                    {[
                      "scans:read",
                      "scans:write",
                      "findings:read",
                      "findings:write",
                      "assets:read",
                      "reports:read",
                      "schedules:read",
                    ].map((scope) => (
                      <label key={scope} className="flex items-center gap-2 text-xs text-slate-300">
                        <input
                          type="checkbox"
                          checked={tokenScopes.includes(scope)}
                          onChange={(e) => {
                            if (e.target.checked) setTokenScopes([...tokenScopes, scope]);
                            else setTokenScopes(tokenScopes.filter((s) => s !== scope));
                          }}
                          className="rounded bg-slate-950 border-slate-700 text-indigo-600"
                        />
                        <span className="font-mono">{scope}</span>
                      </label>
                    ))}
                  </div>
                </div>

                <div className="flex justify-end gap-2 pt-2">
                  <Button variant="ghost" size="sm" onClick={() => setIsCreatingToken(false)}>
                    Cancelar
                  </Button>
                  <Button
                    size="sm"
                    onClick={() => createTokenMutation.mutate()}
                    disabled={!tokenName.trim() || createTokenMutation.isPending}
                    className="bg-indigo-600 hover:bg-indigo-700 text-white"
                  >
                    Gerar Chave
                  </Button>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Tabela de Chaves de API */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-sm">
                <thead>
                  <tr className="border-b border-slate-800 bg-slate-950/60 text-slate-400 text-xs font-semibold uppercase tracking-wider">
                    <th className="py-3 px-4">Nome</th>
                    <th className="py-3 px-4">Prefixo</th>
                    <th className="py-3 px-4">Escopos</th>
                    <th className="py-3 px-4">Último Uso</th>
                    <th className="py-3 px-4">Expiração</th>
                    <th className="py-3 px-4 text-right">Ação</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800 text-slate-300">
                  {loadingTokens ? (
                    <tr>
                      <td colSpan={6} className="py-8 text-center text-slate-500">
                        Carregando chaves de API...
                      </td>
                    </tr>
                  ) : !tokensData?.items.length ? (
                    <tr>
                      <td colSpan={6} className="py-8 text-center text-slate-500">
                        Nenhuma chave de API gerada.
                      </td>
                    </tr>
                  ) : (
                    tokensData.items.map((t) => (
                      <tr key={t.id} className="hover:bg-slate-800/40 transition">
                        <td className="py-3 px-4 font-medium text-slate-200">{t.name}</td>
                        <td className="py-3 px-4 font-mono text-xs text-indigo-400">{t.token_prefix}...</td>
                        <td className="py-3 px-4">
                          <div className="flex flex-wrap gap-1">
                            {t.scopes.map((s) => (
                              <Badge key={s} variant="outline" className="text-xs font-mono border-slate-700">
                                {s}
                              </Badge>
                            ))}
                          </div>
                        </td>
                        <td className="py-3 px-4 text-xs text-slate-400">
                          {t.last_used_at ? formatDateTime(t.last_used_at) : "Nunca"}
                        </td>
                        <td className="py-3 px-4 text-xs text-slate-400">
                          {t.expires_at ? formatDateTime(t.expires_at) : "Sem expiração"}
                        </td>
                        <td className="py-3 px-4 text-right">
                          {t.is_revoked ? (
                            <Badge className="bg-red-950 text-red-400 border-red-800">REVOGADA</Badge>
                          ) : (
                            <Button
                              variant="ghost"
                              size="sm"
                              className="text-red-400 hover:bg-slate-800"
                              onClick={() => revokeTokenMutation.mutate(t.id)}
                            >
                              Revogar
                            </Button>
                          )}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* =================================================================== */}
      {/* ABA 5: TEMPLATES DE AUDITORIA                                       */}
      {/* =================================================================== */}
      {activeTab === "templates" && (
        <div className="space-y-4">
          <div className="flex justify-between items-center">
            <div className="flex items-center gap-3">
              <Button
                variant="outline"
                size="sm"
                onClick={() => refetchTemplates()}
                className="border-slate-700 text-slate-300 hover:bg-slate-800"
              >
                <RefreshCw className="w-4 h-4 mr-1.5" />
                Atualizar
              </Button>
              <Button
                variant="secondary"
                size="sm"
                onClick={() => seedTemplatesMutation.mutate()}
                className="bg-slate-800 text-slate-200 hover:bg-slate-700"
              >
                <Layers className="w-4 h-4 mr-1.5 text-indigo-400" />
                Carregar Padrões da Indústria
              </Button>
            </div>

            <Button
              size="sm"
              onClick={() => setIsCreatingTemplate(true)}
              className="bg-indigo-600 hover:bg-indigo-700 text-white"
            >
              <Plus className="w-4 h-4 mr-1.5" />
              Novo Template
            </Button>
          </div>

          {templateFeedback && (
            <div className="p-3 bg-indigo-950/60 border border-indigo-800 text-indigo-300 text-sm rounded-lg flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-indigo-400" />
              {templateFeedback}
            </div>
          )}

          {/* Criação de Template */}
          {isCreatingTemplate && (
            <Card className="bg-slate-900 border-indigo-800">
              <CardHeader>
                <CardTitle className="text-base text-slate-100 flex items-center gap-2">
                  <Layers className="w-4 h-4 text-indigo-400" />
                  Cadastrar Novo Template de Auditoria
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="text-xs text-slate-400 font-medium">Nome do Template</label>
                    <input
                      type="text"
                      value={tplName}
                      onChange={(e) => setTplName(e.target.value)}
                      placeholder="Ex: Auditoria Periódica de Staging"
                      className="w-full mt-1 bg-slate-950 border border-slate-700 text-slate-200 text-sm rounded-md p-2"
                    />
                  </div>

                  <div>
                    <label className="text-xs text-slate-400 font-medium">Perfil Base</label>
                    <select
                      value={tplProfile}
                      onChange={(e) => setTplProfile(e.target.value)}
                      className="w-full mt-1 bg-slate-950 border border-slate-700 text-slate-200 text-sm rounded-md p-2"
                    >
                      <option value="QUICK">QUICK</option>
                      <option value="FULL">FULL</option>
                      <option value="API">API</option>
                      <option value="PASSIVE">PASSIVE</option>
                    </select>
                  </div>

                  <div>
                    <label className="text-xs text-slate-400 font-medium">Ambiente Recomendado</label>
                    <select
                      value={tplEnv}
                      onChange={(e) => setTplEnv(e.target.value)}
                      className="w-full mt-1 bg-slate-950 border border-slate-700 text-slate-200 text-sm rounded-md p-2"
                    >
                      <option value="PRODUCTION">Produção</option>
                      <option value="STAGING">Homologação / Staging</option>
                      <option value="LAB">Laboratório</option>
                    </select>
                  </div>

                  <div>
                    <label className="text-xs text-slate-400 font-medium">Descrição</label>
                    <input
                      type="text"
                      value={tplDesc}
                      onChange={(e) => setTplDesc(e.target.value)}
                      placeholder="Objetivo e escopo coberto por este template"
                      className="w-full mt-1 bg-slate-950 border border-slate-700 text-slate-200 text-sm rounded-md p-2"
                    />
                  </div>
                </div>

                <div className="flex justify-end gap-2 pt-2">
                  <Button variant="ghost" size="sm" onClick={() => setIsCreatingTemplate(false)}>
                    Cancelar
                  </Button>
                  <Button
                    size="sm"
                    onClick={() => createTemplateMutation.mutate()}
                    disabled={!tplName.trim() || createTemplateMutation.isPending}
                    className="bg-indigo-600 hover:bg-indigo-700 text-white"
                  >
                    Salvar Template
                  </Button>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Cards de Templates */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {loadingTemplates ? (
              <div className="col-span-3 py-8 text-center text-slate-500">Carregando templates...</div>
            ) : !templatesData?.items.length ? (
              <div className="col-span-3 py-8 text-center text-slate-500">
                Nenhum template cadastrado. Clique em &ldquo;Carregar Padrões da Indústria&rdquo; para inicializar.
              </div>
            ) : (
              templatesData.items.map((tpl) => (
                <Card key={tpl.id} className="bg-slate-900 border-slate-800 flex flex-col justify-between">
                  <CardHeader className="pb-2">
                    <div className="flex justify-between items-start">
                      <CardTitle className="text-sm font-semibold text-slate-100">{tpl.name}</CardTitle>
                      <Badge variant="outline" className="text-xs border-indigo-700 text-indigo-300">
                        {tpl.profile_type}
                      </Badge>
                    </div>
                  </CardHeader>
                  <CardContent className="space-y-3 flex-1 flex flex-col justify-between text-xs">
                    <p className="text-slate-400">{tpl.description || "Sem descrição."}</p>
                    <div className="space-y-2 pt-2 border-t border-slate-800">
                      <div className="flex items-center justify-between">
                        <span className="text-slate-500">Ambiente:</span>
                        <span className="text-slate-300 font-medium">{tpl.environment_type || "Geral"}</span>
                      </div>
                      <div className="flex flex-wrap gap-1">
                        {tpl.enabled_modules.map((m) => (
                          <Badge key={m} variant="secondary" className="bg-slate-950 text-slate-300 text-[10px]">
                            {m}
                          </Badge>
                        ))}
                      </div>
                      <div className="flex justify-end pt-2">
                        <Button
                          variant="ghost"
                          size="sm"
                          className="text-red-400 hover:bg-slate-800 h-7 px-2"
                          onClick={() => deleteTemplateMutation.mutate(tpl.id)}
                        >
                          <Trash2 className="w-3.5 h-3.5 mr-1" />
                          Excluir
                        </Button>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
}
