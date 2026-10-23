"use client";

import React, { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import {
  type AssetResponse,
  fetchFindingsPage,
  fetchScansPage,
  updateAsset,
} from "@/lib/api";
import {
  canManageScans,
  errorMessage,
  formatDateTime,
  riskLevel,
  SCAN_STATUS_LABEL,
} from "@/lib/soc-utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export interface AssetListFilters {
  search: string;
  environment: string;
  authorization: string;
}

/** Filtragem local da lista de ativos já carregada do backend (lista pequena por organização). */
export function filterAssets(
  assets: AssetResponse[],
  f: AssetListFilters
): AssetResponse[] {
  const q = f.search.trim().toLowerCase();
  return assets.filter((a) => {
    if (f.environment && a.environment !== f.environment) return false;
    if (f.authorization && a.authorization_status !== f.authorization) return false;
    if (!q) return true;
    return [a.name, a.target_url, a.hostname, a.owner_name, ...a.tags].some((v) =>
      v.toLowerCase().includes(q)
    );
  });
}

const inputClass =
  "h-8 rounded-md border border-slate-300 bg-transparent px-2 text-xs dark:border-slate-700";

interface AssetsDirectoryProps {
  token: string;
  role?: string | null;
  orgName: string;
  assets: AssetResponse[];
  selectedAssetId: string | null;
  onManageAuthorization: (assetId: string) => void;
  onAudit: (assetId: string) => void;
  onViewFindings: (assetId: string) => void;
  onOpenScan: (scanId: string) => void;
}

export function AssetsDirectory(props: AssetsDirectoryProps) {
  const [filters, setFilters] = useState<AssetListFilters>({
    search: "",
    environment: "",
    authorization: "",
  });
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const visible = filterAssets(props.assets, filters);

  return (
    <Card>
      <CardHeader>
        <CardTitle>Ativos da Organização ({props.orgName})</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3 text-xs">
        <div className="grid grid-cols-3 gap-2" role="search" aria-label="Filtros de ativos">
          <input aria-label="Buscar ativos" placeholder="Nome, URL, responsável, tag…" className={inputClass} value={filters.search} onChange={(e) => setFilters((f) => ({ ...f, search: e.target.value }))} />
          <select aria-label="Filtrar ativos por ambiente" className={inputClass} value={filters.environment} onChange={(e) => setFilters((f) => ({ ...f, environment: e.target.value }))}>
            <option value="">Todos os ambientes</option>
            {["PRODUCTION", "STAGING", "DEVELOPMENT", "LAB"].map((v) => <option key={v} value={v}>{v}</option>)}
          </select>
          <select aria-label="Filtrar ativos por autorização" className={inputClass} value={filters.authorization} onChange={(e) => setFilters((f) => ({ ...f, authorization: e.target.value }))}>
            <option value="">Toda autorização</option>
            {["PENDING", "VERIFIED", "EXPIRED", "REVOKED"].map((v) => <option key={v} value={v}>{v}</option>)}
          </select>
        </div>

        {props.assets.length === 0 ? (
          <p className="text-slate-500">
            Nenhum ativo cadastrado nesta organização. Utilize o formulário ao lado para registrar o primeiro sistema.
          </p>
        ) : visible.length === 0 ? (
          <p className="text-slate-500" data-testid="assets-empty-filter">Nenhum ativo corresponde aos filtros.</p>
        ) : (
          visible.map((asset) => (
            <AssetRow
              key={asset.id}
              asset={asset}
              {...props}
              expanded={expandedId === asset.id}
              onToggle={() => setExpandedId((cur) => (cur === asset.id ? null : asset.id))}
            />
          ))
        )}
      </CardContent>
    </Card>
  );
}

function AssetRow({
  asset,
  token,
  role,
  selectedAssetId,
  expanded,
  onToggle,
  onManageAuthorization,
  onAudit,
  onViewFindings,
  onOpenScan,
}: AssetsDirectoryProps & {
  asset: AssetResponse;
  expanded: boolean;
  onToggle: () => void;
}) {
  const queryClient = useQueryClient();
  const risk = riskLevel(asset.risk_score);
  const verified = asset.authorization_status === "VERIFIED";
  const [editing, setEditing] = useState(false);
  const [name, setName] = useState(asset.name);
  const [ownerName, setOwnerName] = useState(asset.owner_name);
  const [ownerEmail, setOwnerEmail] = useState(asset.owner_email);
  const [environment, setEnvironment] = useState<AssetResponse["environment"]>(asset.environment);
  const [feedback, setFeedback] = useState<string | null>(null);

  const scansQuery = useQuery({
    queryKey: ["asset-scans", token, asset.id],
    queryFn: () => fetchScansPage(token, { asset_id: asset.id, limit: 5 }),
    enabled: expanded,
  });
  const findingsQuery = useQuery({
    queryKey: ["asset-findings-count", token, asset.id],
    queryFn: () => fetchFindingsPage(token, { asset_id: asset.id, limit: 1 }),
    enabled: expanded,
  });

  const mutation = useMutation({
    mutationFn: () =>
      updateAsset(token, asset.id, {
        name: name.trim(),
        owner_name: ownerName.trim(),
        owner_email: ownerEmail.trim(),
        environment,
      }),
    onSuccess: () => {
      setFeedback("Ativo atualizado.");
      setEditing(false);
      void queryClient.invalidateQueries({ queryKey: ["org-assets"] });
    },
    onError: (e) => setFeedback(errorMessage(e)),
  });

  const canEdit = canManageScans(role);
  const invalidEdit =
    name.trim().length < 2 || ownerName.trim().length < 2 || !/^\S+@\S+\.\S+$/.test(ownerEmail.trim());

  return (
    <div className={`rounded-md border p-3 transition-colors ${selectedAssetId === asset.id ? "border-sky-500 bg-sky-500/5" : "border-slate-200 dark:border-slate-800"}`}>
      <div className="flex items-center justify-between gap-2">
        <span className="text-sm font-bold">{asset.name}</span>
        <div className="flex items-center gap-1.5">
          <Badge variant="outline">{asset.environment}</Badge>
          <Badge variant={verified ? "success" : asset.authorization_status === "REVOKED" ? "critical" : "warning"}>
            {asset.authorization_status}
          </Badge>
          <Badge variant={risk.variant}>Risco {asset.risk_score}/100</Badge>
        </div>
      </div>
      <p className="mt-1 font-mono text-slate-500">{asset.target_url} (Host: {asset.hostname})</p>
      <p className="mt-1 text-slate-500">Responsável: {asset.owner_name} ({asset.owner_email})</p>
      <div className="mt-2 flex flex-wrap gap-2">
        <Button size="sm" variant="secondary" onClick={() => onManageAuthorization(asset.id)}>
          Gerenciar Comprovação de Autorização
        </Button>
        {verified ? (
          <Button size="sm" onClick={() => onAudit(asset.id)}>Auditar este Ativo</Button>
        ) : (
          <span className="self-center text-slate-500">Auditoria bloqueada: autorização não verificada.</span>
        )}
        <Button size="sm" variant="outline" aria-expanded={expanded} onClick={onToggle}>
          {expanded ? "Ocultar detalhes" : "Ver detalhes"}
        </Button>
      </div>

      {expanded && (
        <div className="mt-3 space-y-2 border-t border-slate-200 pt-3 dark:border-slate-800">
          <p>
            Tags: {asset.tags.join(", ") || "—"} · Caminhos excluídos: {asset.excluded_paths.join(", ") || "—"}
          </p>
          <p>
            Vulnerabilidades registradas:{" "}
            <strong>{findingsQuery.isLoading ? "…" : findingsQuery.data?.total ?? 0}</strong>{" "}
            <Button size="sm" variant="outline" onClick={() => onViewFindings(asset.id)}>Acessar resultados</Button>
          </p>
          <div>
            <p className="font-semibold">
              Histórico de auditorias ({scansQuery.data?.total ?? 0})
            </p>
            {scansQuery.isLoading ? (
              <p>Carregando…</p>
            ) : scansQuery.isError ? (
              <p role="alert" className="text-red-500">{errorMessage(scansQuery.error)}</p>
            ) : (scansQuery.data?.items ?? []).length === 0 ? (
              <p className="text-slate-500">Nenhuma auditoria executada neste ativo.</p>
            ) : (
              <ul className="space-y-1">
                {scansQuery.data!.items.map((s) => (
                  <li key={s.id}>
                    {formatDateTime(s.created_at)} · {s.profile_type} · {SCAN_STATUS_LABEL[s.status] ?? s.status}{" "}
                    <Button size="sm" variant="outline" onClick={() => onOpenScan(s.id)}>Abrir</Button>
                  </li>
                ))}
              </ul>
            )}
          </div>

          {canEdit && !editing && (
            <Button size="sm" variant="secondary" onClick={() => setEditing(true)}>Editar metadados</Button>
          )}
          {editing && (
            <form
              className="grid grid-cols-2 gap-2"
              aria-label={`Editar ${asset.name}`}
              onSubmit={(e) => {
                e.preventDefault();
                if (!invalidEdit) mutation.mutate();
              }}
            >
              <input aria-label="Nome do ativo" className={inputClass} value={name} onChange={(e) => setName(e.target.value)} />
              <select aria-label="Ambiente do ativo" className={inputClass} value={environment} onChange={(e) => setEnvironment(e.target.value as AssetResponse["environment"])}>
                {["PRODUCTION", "STAGING", "DEVELOPMENT", "LAB"].map((v) => <option key={v} value={v}>{v}</option>)}
              </select>
              <input aria-label="Responsável" className={inputClass} value={ownerName} onChange={(e) => setOwnerName(e.target.value)} />
              <input aria-label="E-mail do responsável" className={inputClass} value={ownerEmail} onChange={(e) => setOwnerEmail(e.target.value)} />
              {invalidEdit && <p role="alert" className="col-span-2 text-red-500">Informe nome, responsável e e-mail válidos.</p>}
              <div className="col-span-2 space-x-2">
                <Button size="sm" type="submit" disabled={invalidEdit || mutation.isPending}>Salvar</Button>
                <Button size="sm" type="button" variant="outline" onClick={() => setEditing(false)}>Cancelar</Button>
              </div>
            </form>
          )}
          {feedback && <p role="status">{feedback}</p>}
        </div>
      )}
    </div>
  );
}
