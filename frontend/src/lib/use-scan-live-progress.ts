"use client";

import { useEffect, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";

import { type ScanProgressResponse, streamScanProgress } from "@/lib/api";

export type LiveState = "idle" | "connecting" | "live" | "fallback";

export const MAX_STREAM_RECONNECTS = 3;
export const RECONNECT_BASE_DELAY_MS = 1000;

/**
 * Acompanha uma auditoria por SSE. Atualiza o cache `["scan-progress", token, scanId]`
 * com cada evento real do servidor. Após falhas reconecta com backoff limitado e, esgotadas
 * as tentativas, sinaliza "fallback" para que o chamador ative polling controlado.
 */
export function useScanLiveProgress(
  token: string | null,
  scanId: string | null,
  enabled: boolean
): LiveState {
  const queryClient = useQueryClient();
  const [state, setState] = useState<LiveState>("idle");
  const attemptsRef = useRef(0);

  useEffect(() => {
    if (!token || !scanId || !enabled) {
      setState("idle");
      return;
    }
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    attemptsRef.current = 0;

    const connect = async () => {
      setState("connecting");
      try {
        const outcome = await streamScanProgress(
          token,
          scanId,
          (progress) => {
            attemptsRef.current = 0;
            setState("live");
            queryClient.setQueryData(["scan-progress", token, scanId], progress);
          },
          controller.signal
        );
        if (outcome === "ended") {
          setState("idle");
          void queryClient.invalidateQueries({ queryKey: ["org-scans"] });
          void queryClient.invalidateQueries({ queryKey: ["scans-page"] });
          void queryClient.invalidateQueries({ queryKey: ["dashboard-summary"] });
          return;
        }
        throw new Error("timeout");
      } catch (err) {
        if (controller.signal.aborted) return;
        attemptsRef.current += 1;
        if (attemptsRef.current > MAX_STREAM_RECONNECTS) {
          setState("fallback");
          return;
        }
        timer = setTimeout(
          () => void connect(),
          RECONNECT_BASE_DELAY_MS * 2 ** (attemptsRef.current - 1)
        );
        void err;
      }
    };
    void connect();
    return () => {
      controller.abort();
      if (timer) clearTimeout(timer);
    };
  }, [token, scanId, enabled, queryClient]);

  return state;
}

export type { ScanProgressResponse };
