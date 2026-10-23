"""Registro e descoberta de módulos de segurança (PluginRegistry - Seção 5 e Fase 3)."""

from __future__ import annotations

from security_engine.core.contracts import (
    BaseSecurityModule,
    EnvironmentType,
    ModuleMetadata,
)
from security_engine.modules.builtin_modules import get_builtin_modules


class PluginRegistry:
    """Gerencia o registro, descoberta, habilitação e validação de módulos do security-engine."""

    def __init__(self, register_builtins: bool = True) -> None:
        self._modules: dict[str, BaseSecurityModule] = {}
        self._enabled_state: dict[str, bool] = {}
        if register_builtins:
            for mod in get_builtin_modules():
                self.register(mod, enabled=mod.metadata.enabled_by_default)

    def register(self, module: BaseSecurityModule, enabled: bool | None = None) -> None:
        """Registra um módulo de segurança validando seu contrato."""
        meta = module.metadata
        if not meta.module_id or not meta.module_id.strip():
            raise ValueError("Módulo inválido: module_id não pode ser vazio.")
        self._modules[meta.module_id] = module
        self._enabled_state[meta.module_id] = (
            enabled if enabled is not None else meta.enabled_by_default
        )

    def set_enabled(self, module_id: str, enabled: bool) -> None:
        """Habilita ou desabilita um módulo independentemente sem afetar os demais."""
        if module_id not in self._modules:
            raise KeyError(f"Módulo '{module_id}' não encontrado no PluginRegistry.")
        self._enabled_state[module_id] = enabled

    def is_enabled(self, module_id: str) -> bool:
        """Retorna se um módulo específico está habilitado."""
        return self._enabled_state.get(module_id, False)

    def get_module(self, module_id: str) -> BaseSecurityModule:
        """Obtém a instância de um módulo registrado."""
        if module_id not in self._modules:
            raise KeyError(f"Módulo '{module_id}' não encontrado no PluginRegistry.")
        return self._modules[module_id]

    def list_metadata(self, only_enabled: bool = False) -> list[ModuleMetadata]:
        """Lista os metadados dos módulos registrados."""
        result: list[ModuleMetadata] = []
        for mod_id, mod in self._modules.items():
            if only_enabled and not self._enabled_state.get(mod_id, False):
                continue
            result.append(mod.metadata)
        return result

    def validate_modules_for_environment(
        self,
        module_ids: list[str],
        environment: EnvironmentType,
    ) -> list[str]:
        """Valida se todos os módulos selecionados existem e são permitidos no ambiente alvo.

        Regra (Seção 7): Perfis/módulos invasivos (allow_in_production=False) não devem
        estar disponíveis para alvos de produção por padrão.
        """
        validated: list[str] = []
        for mod_id in module_ids:
            mod = self.get_module(mod_id)
            if environment == EnvironmentType.PRODUCTION and not mod.metadata.allow_in_production:
                raise ValueError(
                    f"O módulo '{mod.metadata.code} ({mod.metadata.name})' possui nível de impacto "
                    f"'{mod.metadata.impact_level.value}' e não é permitido em alvos de PRODUÇÃO."
                )
            validated.append(mod_id)
        return validated


default_registry = PluginRegistry(register_builtins=True)
