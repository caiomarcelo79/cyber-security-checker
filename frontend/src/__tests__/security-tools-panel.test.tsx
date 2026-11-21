import React from "react";
import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";

import { SecurityToolsPanel } from "@/components/security-tools-panel";

afterEach(() => {
  vi.unstubAllGlobals();
});

it("renderiza os 7 cartões do hub Segurança & Ferramentas SOC", () => {
  render(<SecurityToolsPanel token={null} assets={[]} />);

  expect(screen.getByText("Pentest Assistant")).toBeInTheDocument();
  expect(screen.getByText("PRO")).toBeInTheDocument();
  expect(screen.getByText("Password Tools")).toBeInTheDocument();
  expect(screen.getByText("Forensics")).toBeInTheDocument();
  expect(screen.getByText("Firewall Tester")).toBeInTheDocument();
  expect(screen.getByText("Malware Analysis")).toBeInTheDocument();
  expect(screen.getByText("WiFi Auditor")).toBeInTheDocument();
  expect(screen.getByText("DDoS Analyzer")).toBeInTheDocument();
});

it("gera roteiro WSTG no Pentest Assistant", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () =>
      Response.json({
        target_name: "Aplicação de Laboratório Local",
        asset_type: "WEB_APP",
        environment: "LAB",
        authorization_status: "MANUAL_UNVERIFIED",
        authorization_warning: "Modo de planejamento manual.",
        total_steps: 1,
        automated_covered_steps: 0,
        open_findings_count: 0,
        phases: [
          {
            phase_number: 1,
            name: "1. Reconhecimento e Superfície de Ataque",
            description: "Mapeamento passivo.",
            steps: [
              {
                step_id: "PT-01",
                wstg_ref: "WSTG-INFO-02",
                title: "Fingerprinting de servidor",
                objective: "Identificar banners.",
                safe_technique: "Inspecionar cabeçalhos.",
                mapped_checks: ["CHK-A07"],
                allowed_in_production: true,
                automated_status: "NOT_YET_RUN",
                related_findings_count: 0,
              },
            ],
          },
        ],
      })
    )
  );

  render(<SecurityToolsPanel token={null} assets={[]} />);
  fireEvent.click(
    screen.getByRole("button", { name: /Gerar Roteiro Guiado OWASP WSTG/i })
  );

  expect(
    await screen.findByText(/\[PT-01\] Fingerprinting de servidor/)
  ).toBeInTheDocument();
  expect(screen.getByText("CHK-A07")).toBeInTheDocument();
});

it("permite gerar e auditar senhas em Password Tools", async () => {
  const fetchMock = vi
    .fn()
    .mockResolvedValueOnce(
      Response.json({
        generated: "k9#Xp!2Vm7@Lq4$Tz8Wn",
        mode: "RANDOM",
        length: 20,
        entropy_bits: 131.0,
        strength_label: "Muito Forte",
      })
    )
    .mockResolvedValueOnce(
      Response.json({
        length: 20,
        score: 94,
        classification: "VERY_STRONG",
        pool_size: 94,
        keyspace_entropy_bits: 131.0,
        shannon_entropy_bits: 86.0,
        crack_time_offline_slow: "milhões de anos / séculos",
        crack_time_offline_fast: "milhões de anos / séculos",
        detected_patterns: [],
        compliance_checks: [
          {
            standard: "NIST SP 800-63B (Comprimento mínimo >= 8; recomendado >= 12)",
            passed: true,
            detail: "Comprimento atual: 20 caracteres.",
          },
        ],
        recommendations: ["Senha aderente às recomendações."],
      })
    );
  vi.stubGlobal("fetch", fetchMock);

  render(<SecurityToolsPanel token={null} assets={[]} />);
  fireEvent.click(screen.getByRole("button", { name: /Password Tools/i }));
  fireEvent.click(
    screen.getByRole("button", { name: /Gerar Credencial Segura/i })
  );

  expect(
    await screen.findByText("k9#Xp!2Vm7@Lq4$Tz8Wn")
  ).toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: /Auditar esta senha/i }));
  expect(await screen.findByText(/Score: 94\/100/)).toBeInTheDocument();
  expect(
    screen.getByText(/NIST SP 800-63B \(Comprimento mínimo/)
  ).toBeInTheDocument();
});

it("audita regras e simula pacote no Firewall Tester", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () =>
      Response.json({
        total_rules_parsed: 2,
        unparsed_lines: [],
        posture_score: 50,
        has_default_deny: false,
        parsed_rules: [
          {
            line_number: 1,
            raw: "ALLOW TCP 0.0.0.0/0 5432",
            action: "ALLOW",
            protocol: "TCP",
            source_cidr: "0.0.0.0/0",
            port_spec: "5432",
          },
        ],
        findings: [
          {
            severity: "CRITICAL",
            line_number: 1,
            title: "Serviço administrativo ou banco de dados exposto à internet",
            description: "Linha 1 libera 5432 para 0.0.0.0/0.",
            cwe_id: "CWE-284",
            remediation: "Restrinja o acesso via VPN.",
          },
        ],
        simulation: {
          verdict: "ALLOW",
          matched_line: 1,
          matched_rule: "ALLOW TCP 0.0.0.0/0 5432",
          explanation: "Pacote correspondeu à regra da linha 1 (ALLOW).",
        },
      })
    )
  );

  render(<SecurityToolsPanel token={null} assets={[]} />);
  fireEvent.click(screen.getByRole("button", { name: /Firewall Tester/i }));
  fireEvent.click(
    screen.getByRole("button", { name: /Carregar Regras de Laboratório/i })
  );
  fireEvent.click(
    screen.getByRole("button", { name: /Auditar Regras de Firewall/i })
  );

  expect(await screen.findByText(/Postura: 50\/100/)).toBeInTheDocument();
  expect(
    screen.getByText(/Resultado da Simulação: ALLOW/)
  ).toBeInTheDocument();
  expect(screen.getByText("CWE-284")).toBeInTheDocument();
});

it("escaneia Wi-Fi real via fallback do sensor local e exibe interface ativa e redes", async () => {
  const fetchMock = vi.fn(async (url: string) => {
    if (String(url).includes("/wifi/scan-local")) {
      return Response.json({
        available: false,
        source: "CONTAINER_NO_WIFI_RADIO",
        detail: "Container sem rádio Wi-Fi direto.",
      });
    }
    if (String(url).includes("127.0.0.1:8765/scan")) {
      return Response.json({
        available: true,
        host_os: "Windows",
        tool: "netsh",
        captured_at: "2026-11-21T03:55:00Z",
        raw_scan_output: "SSID 1 : Corp-Real\nAutenticação : WPA2-Personal\nCriptografia : CCMP",
        connected_interface_output: "SSID : Corp-Real\nCanal : 44\nSinal : 96%",
      });
    }
    return Response.json({
      total_networks: 1,
      overall_score: 82,
      evil_twin_suspected: false,
      connected_interface: {
        interface_name: "Wi-Fi",
        adapter_description: "Realtek 8822CE",
        state: "Conectado",
        ssid: "Corp-Real",
        bssid: "b4:c0:c3:01:d0:c0",
        radio_type: "802.11ac",
        authentication: "WPA2-Personal",
        encryption: "CCMP",
        channel: 44,
        signal_percent: 96,
      },
      assessments: [
        {
          ssid: "Corp-Real",
          bssid: "b4:c0:c3:01:d0:c0",
          security_grade: "B",
          authentication: "WPA2-Personal",
          encryption: "CCMP",
          radio_type: "802.11ax",
          band: "5 GHz",
          channel: 44,
          signal_percent: 96,
          issues_count: 0,
        },
      ],
      findings: [],
      hardening_checklist: [],
    });
  });
  vi.stubGlobal("fetch", fetchMock);

  render(<SecurityToolsPanel token={null} assets={[]} />);
  fireEvent.click(screen.getByRole("button", { name: /WiFi Auditor/i }));
  fireEvent.click(
    screen.getByRole("button", { name: /Escanear Wi-Fi Real Agora/i })
  );

  expect(
    await screen.findByText(/Conexão Wi-Fi Ativa: Corp-Real/)
  ).toBeInTheDocument();
  expect(
    screen.getByText(/Captura Real · Sensor Local 127\.0\.0\.1:8765/)
  ).toBeInTheDocument();
  expect(screen.getByText(/5 GHz · Ch 44 · 802\.11ax/)).toBeInTheDocument();
});
