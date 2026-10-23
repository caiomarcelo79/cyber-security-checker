# Mapeamento de Padrões de Segurança (`cyber-security-checker`)

Este documento relaciona os módulos de verificação do `cyber-security-checker` (Módulos A a H) com os referenciais normativos estáveis exigidos na Seção 3 do Prompt Master.

---

## 1. Matriz Normativa por Módulo

| Módulo | OWASP Top 10 (2021) / API (2023) | OWASP ASVS 5.0 | OWASP WSTG v4.2 | CWE Principal | NIST / CIS & MITRE ATT&CK |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **MÓDULO A** — Reconhecimento, HTTPS, TLS, Headers e DNS | `A02:2021` Cryptographic Failures<br>`A05:2021` Security Misconfiguration | `V9.1`, `V9.2`, `V14.4` | `WSTG-CRYP-01`<br>`WSTG-CONF-07`<br>`WSTG-INFO-02` | `CWE-319`, `CWE-693`, `CWE-1021`, `CWE-200` | NIST SC-8, SC-23 / CIS Control 3, 4 / MITRE T1592 |
| **MÓDULO B** — Autenticação e Login | `A07:2021` Identification and Authentication Failures | `V2.1`, `V2.2`, `V3.2`, `V3.3` | `WSTG-ATHN-01`<br>`WSTG-SESS-03`<br>`WSTG-SESS-06` | `CWE-287`, `CWE-384`, `CWE-613`, `CWE-204` | NIST IA-2, IA-5 / CIS Control 5, 6 / MITRE T1078 |
| **MÓDULO C** — Cross-Site Scripting (XSS) Controlado | `A03:2021` Injection | `V5.3.3`, `V14.4.3` | `WSTG-INPV-01`<br>`WSTG-CLNT-01` | `CWE-79`, `CWE-80` | NIST SI-10 / CIS Control 16 / MITRE T1189 |
| **MÓDULO D** — Indicadores Seguros de SQL Injection | `A03:2021` Injection | `V5.3.4`, `V5.3.5` | `WSTG-INPV-05` | `CWE-89`, `CWE-209` | NIST SI-10 / CIS Control 16 / MITRE T1190 |
| **MÓDULO E** — Cookies e Sessões | `A07:2021` Identification and Authentication Failures | `V3.4.1`, `V3.4.2`, `V3.4.3` | `WSTG-SESS-02` | `CWE-614`, `CWE-1004`, `CWE-1275` | NIST SC-23 / CIS Control 16 / MITRE T1539 |
| **MÓDULO F** — Postura de Proteção contra DoS/DDoS | `API4:2023` Unrestricted Resource Consumption | `V11.1.4`, `V13.1` | `WSTG-CONF-01` | `CWE-770`, `CWE-400` | NIST SC-5 / CIS Control 13 / MITRE T1499 |
| **MÓDULO G** — APIs REST e GraphQL | `API1:2023` BOLA<br>`API8:2023` Security Misconfiguration<br>`API9:2023` Improper Inventory | `V13.1`, `V13.2`, `V13.4`, `V14.5` | `WSTG-APIT-01`<br>`WSTG-CLNT-07` | `CWE-942`, `CWE-639`, `CWE-285` | NIST AC-3, SC-7 / CIS Control 16 |
| **MÓDULO H** — Outras Vulnerabilidades e Configurações | `A01:2021` Broken Access Control<br>`A05:2021` Security Misconfiguration | `V4.1`, `V4.2`, `V14.2`, `V14.3` | `WSTG-CONF-04`<br>`WSTG-ATHZ-01`<br>`WSTG-CLNT-04` | `CWE-352`, `CWE-538`, `CWE-548`, `CWE-601` | NIST AC-3, CM-6 / CIS Control 4, 16 |

---

## 2. Regras de Atribuição de CVE e CVSS 4.0

1. **Códigos CVE**: Somente são preenchidos no modelo `NormalizedFinding` quando um componente ou biblioteca tem sua versão exata confirmada com grau de confiança `CERTAIN` e mapeada diretamente a um boletim CVE oficial.
2. **Pontuação CVSS 4.0**: Calculada apenas quando todas as métricas base (`AV`, `AC`, `AT`, `PR`, `UI`, `VC`, `VI`, `VA`, `SC`, `SI`, `SA`) estão tecnicamente fundamentadas.
3. **Diferenciação de Indícios**: Resultados com grau de confiança `TENTATIVE` são obrigatoriamente classificados como `POTENTIAL_VULNERABILITY` pelo `RiskEngine`, jamais como vulnerabilidade confirmada (`VULNERABILITY`).
