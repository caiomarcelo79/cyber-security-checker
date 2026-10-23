"""Script utilitário para validação rápida da fundação local (Fase 1)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent


def run_step(description: str, cmd: list[str]) -> None:
    print(f"[*] Executando: {description} -> {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=ROOT_DIR, check=False)
    if result.returncode != 0:
        print(f"[!] Falha na etapa: {description} (exit code {result.returncode})")
        sys.exit(result.returncode)
    print(f"[OK] {description} concluído com sucesso.\n")


def main() -> None:
    python_exe = sys.executable
    run_step("Testes do Security Engine", [python_exe, "-m", "pytest", "security-engine/tests", "-v"])
    run_step("Testes do Backend e Workers", [python_exe, "-m", "pytest", "backend/tests", "-v"])
    run_step("Testes de Infraestrutura e Integração", [python_exe, "-m", "pytest", "tests", "-v"])
    run_step("Linter Ruff", [python_exe, "-m", "ruff", "check", "security-engine", "backend", "workers", "tests"])
    print("Todas as verificações Python da Fase 1 foram aprovadas.")


if __name__ == "__main__":
    main()
