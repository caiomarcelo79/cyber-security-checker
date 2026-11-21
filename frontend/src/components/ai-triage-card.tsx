"use client";

import React, { useState } from "react";

import { Button } from "@/components/ui/button";
import { reviewTriageSuggestion, type AiTriageSuggestion } from "@/lib/api";
import { errorMessage, formatDateTime } from "@/lib/soc-utils";

const modeLabels: Record<AiTriageSuggestion["generation_mode"], string> = {
  AI_PROVIDER: "IA fundamentada",
  DETERMINISTIC_FALLBACK: "Síntese determinística (fallback)",
};

const aiStatusLabels: Record<AiTriageSuggestion["ai_status"], string> = {
  AVAILABLE: "IA disponível",
  UNAVAILABLE: "IA indisponível — fallback ativo",
  UNCONFIGURED: "IA desativada — modo determinístico",
  INVALID_OUTPUT_FALLBACK: "Saída da IA sem fundamentação — fallback ativo",
};

const reviewStatusLabels: Record<AiTriageSuggestion["review_status"], string> = {
  PENDING_REVIEW: "Pendente de revisão do analista",
  APPROVED: "Aprovada pelo analista",
  REJECTED: "Rejeitada pelo analista",
};

const actionLabels: Record<AiTriageSuggestion["recommended_action"], string> = {
  INVESTIGATE: "Investigar",
  CONTAIN: "Conter",
  REMEDIATE: "Remediar",
  VERIFY_CHANGE: "Validar alteração",
};

export interface AiTriageCardProps {
  token: string;
  targetLabel: string;
  canReview?: boolean;
  initialSuggestion?: AiTriageSuggestion | null;
  onGenerate: () => Promise<AiTriageSuggestion>;
}

export function AiTriageCard({
  token,
  targetLabel,
  canReview = true,
  initialSuggestion = null,
  onGenerate,
}: AiTriageCardProps) {
  const [suggestion, setSuggestion] = useState<AiTriageSuggestion | null>(initialSuggestion);
  const [reviewNotes, setReviewNotes] = useState("");
  const [loading, setLoading] = useState(false);
  const [reviewing, setReviewing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleGenerate = async () => {
    setLoading(true);
    setError(null);
    try {
      const created = await onGenerate();
      setSuggestion(created);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setLoading(false);
    }
  };

  const handleReview = async (decision: "APPROVED" | "REJECTED") => {
    if (!suggestion) return;
    setReviewing(true);
    setError(null);
    try {
      const updated = await reviewTriageSuggestion(token, suggestion.id, {
        decision,
        reviewer_notes: reviewNotes.trim() || null,
      });
      setSuggestion(updated);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setReviewing(false);
    }
  };

  return (
    <div
      aria-label={`Triagem assistida por IA: ${targetLabel}`}
      className="mt-2 space-y-2 rounded border border-slate-200 bg-white/70 p-2 text-xs dark:border-slate-800 dark:bg-slate-950/60"
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="font-semibold">Triagem assistida (revisável)</span>
        {canReview ? (
          <Button
            size="sm"
            type="button"
            variant="outline"
            disabled={loading || reviewing}
            onClick={() => void handleGenerate()}
          >
            {loading
              ? "Gerando sugestão…"
              : suggestion
                ? "Atualizar triagem assistida"
                : "Gerar triagem assistida"}
          </Button>
        ) : (
          <span className="text-slate-500">Disponível para perfis Analista ou Admin.</span>
        )}
      </div>

      {error && (
        <p role="alert" className="text-red-500">
          {error}
        </p>
      )}

      {suggestion && (
        <div className="space-y-1.5">
          <p className="text-slate-600 dark:text-slate-300">
            <strong>{modeLabels[suggestion.generation_mode]}</strong> ·{" "}
            {aiStatusLabels[suggestion.ai_status]} ·{" "}
            <strong>{reviewStatusLabels[suggestion.review_status]}</strong> · Ação:{" "}
            {actionLabels[suggestion.recommended_action]}
          </p>
          <p>
            <strong>Resumo:</strong> {suggestion.summary}
          </p>
          <p>{suggestion.explanation}</p>

          {suggestion.evidence_citations.length > 0 && (
            <div>
              <p className="font-semibold">Citações da evidência:</p>
              <ul className="list-disc pl-4">
                {suggestion.evidence_citations.map((cit, idx) => (
                  <li key={`${cit.field}-${idx}`}>
                    <code>{cit.field}</code>: <code>{cit.value_excerpt}</code>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {suggestion.remediation_steps.length > 0 && (
            <div>
              <p className="font-semibold">Passos sugeridos de correção:</p>
              <ol className="list-decimal pl-4">
                {suggestion.remediation_steps.map((step, idx) => (
                  <li key={idx}>{step}</li>
                ))}
              </ol>
            </div>
          )}

          {suggestion.reviewed_at && (
            <p className="text-slate-500">
              Revisado em {formatDateTime(suggestion.reviewed_at)}
              {suggestion.reviewer_notes ? ` — Nota: ${suggestion.reviewer_notes}` : ""}
            </p>
          )}

          {canReview && (
            <div className="space-y-1.5 pt-1">
              <textarea
                aria-label="Nota de revisão da triagem assistida"
                className="w-full rounded border border-slate-300 bg-transparent p-1.5 text-xs dark:border-slate-700"
                rows={2}
                maxLength={1000}
                value={reviewNotes}
                onChange={(e) => setReviewNotes(e.target.value)}
                placeholder="Nota opcional do analista ao aprovar ou rejeitar a sugestão…"
              />
              <div className="flex flex-wrap gap-2">
                <Button
                  size="sm"
                  type="button"
                  disabled={reviewing || loading}
                  onClick={() => void handleReview("APPROVED")}
                >
                  {reviewing ? "Registrando…" : "Aprovar sugestão"}
                </Button>
                <Button
                  size="sm"
                  type="button"
                  variant="outline"
                  className="text-red-600 dark:text-red-400"
                  disabled={reviewing || loading}
                  onClick={() => void handleReview("REJECTED")}
                >
                  Rejeitar sugestão
                </Button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
