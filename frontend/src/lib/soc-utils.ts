/** Utilitários puros de apresentação (pt-BR) compartilhados pelos painéis da Fase 4. */

import { ApiError } from "@/lib/api";

export const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const;

export const SEVERITY_LABEL: Record<string, string> = {
  CRITICAL: "Crítica",
  HIGH: "Alta",
  MEDIUM: "Média",
  LOW: "Baixa",
  INFO: "Informativa",
};

export const SEVERITY_COLOR: Record<string, string> = {
  CRITICAL: "#dc2626",
  HIGH: "#ea580c",
  MEDIUM: "#d97706",
  LOW: "#0284c7",
  INFO: "#64748b",
};

export const CONFIDENCE_LABEL: Record<string, string> = {
  CERTAIN: "Confirmada",
  FIRM: "Firme",
  TENTATIVE: "Indício (requer confirmação)",
};

/** Estado administrativo (triagem), separado do resultado técnico do scanner. */
export const TREATMENT_LABEL: Record<string, string> = {
  OPEN: "Aberta",
  IN_ANALYSIS: "Em análise",
  IN_PROGRESS: "Em correção",
  WAITING_VALIDATION: "Aguardando validação",
  RESOLVED_VERIFIED: "Corrigida e validada",
  FALSE_POSITIVE: "Falso positivo",
  ACCEPTED_RISK: "Risco aceito",
  REOPENED: "Reaberta",
  MITIGATED: "Corrigida (aguardando revalidação)",
};

export const TREATMENT_OPTIONS = Object.keys(TREATMENT_LABEL);

export const PRIORITY_LABEL: Record<string, string> = {
  P1: "P1 — Crítica",
  P2: "P2 — Alta",
  P3: "P3 — Média",
  P4: "P4 — Baixa",
};

export const SCAN_STATUS_LABEL: Record<string, string> = {
  PENDING: "Pendente",
  QUEUED: "Na fila",
  RUNNING: "Em execução",
  COMPLETED: "Concluída",
  PARTIALLY_COMPLETED: "Parcialmente concluída",
  FAILED: "Falhou",
  CANCELLED: "Cancelada",
  ABORTED_TARGET_DEGRADED: "Interrompida (alvo degradado)",
};

export const ACTIVE_SCAN_STATUSES = ["PENDING", "QUEUED", "RUNNING"];

export const CLASSIFICATION_LABEL: Record<string, string> = {
  VULNERABILITY: "Vulnerabilidade",
  POTENTIAL_VULNERABILITY: "Potencial (não confirmada)",
};

/** Metodologia do indicador próprio de risco do ativo (NÃO é CVSS). */
export const RISK_METHODOLOGY =
  "Indicador próprio 0–100: soma, por vulnerabilidade aberta (sem duplicar entre auditorias), de peso da severidade " +
  "(Crítica 25, Alta 14, Média 6, Baixa 2, Info 0,25) × confiança (Confirmada 1,0; Firme 0,8; Indício 0,45) × " +
  "classificação (vulnerabilidade 1,0; potencial 0,65), limitado a 100. Existindo falha crítica aberta, o mínimo é 75. " +
  "Estados resolvidos, falso positivo e risco aceito não pontuam. Não equivale a CVSS.";

export function riskLevel(score: number): {
  label: string;
  variant: "critical" | "warning" | "default" | "success";
} {
  if (score >= 75) return { label: "Crítico", variant: "critical" };
  if (score >= 40) return { label: "Alto", variant: "warning" };
  if (score > 0) return { label: "Moderado", variant: "default" };
  return { label: "Sem pendências abertas", variant: "success" };
}

export function severityVariant(
  sev: string
): "critical" | "warning" | "default" | "outline" {
  if (sev === "CRITICAL" || sev === "HIGH") return "critical";
  if (sev === "MEDIUM") return "warning";
  if (sev === "LOW") return "default";
  return "outline";
}

export function formatDateTime(value?: string | null): string {
  if (!value) return "—";
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? "—" : d.toLocaleString("pt-BR");
}

export function formatDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return "—";
  if (seconds < 60) return `${seconds.toFixed(1)} s`;
  const m = Math.floor(seconds / 60);
  return `${m} min ${Math.round(seconds - m * 60)} s`;
}

export function totalPages(total: number, limit: number): number {
  return Math.max(1, Math.ceil(total / limit));
}

export function isForbidden(error: unknown): boolean {
  return error instanceof ApiError && error.status === 403;
}

export function errorMessage(error: unknown): string {
  if (isForbidden(error)) {
    return "Seu perfil não possui permissão para acessar este recurso.";
  }
  return error instanceof Error ? error.message : "Erro inesperado.";
}

/** Papéis que podem alterar a triagem (o backend também impõe a regra). */
export function canTriage(role?: string | null): boolean {
  return role === "ADMIN" || role === "SECURITY_ANALYST" || role === "DEVELOPER";
}

export function canManageScans(role?: string | null): boolean {
  return role === "ADMIN" || role === "SECURITY_ANALYST";
}

/** Converte data local (yyyy-mm-dd) em limites ISO do dia para filtros de período. */
export function dayStartIso(date: string): string | undefined {
  return date ? new Date(`${date}T00:00:00`).toISOString() : undefined;
}

export function dayEndIso(date: string): string | undefined {
  return date ? new Date(`${date}T23:59:59.999`).toISOString() : undefined;
}
