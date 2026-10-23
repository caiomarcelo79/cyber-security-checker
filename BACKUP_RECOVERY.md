# BACKUP_RECOVERY.md

## Backup
```powershell
./scripts/backup_db.ps1 -OutDir backups -RetentionDays 14
```
Gera `backups/csc_<timestamp>.dump` (formato custom do `pg_dump`) + `.sha256`. Remove apenas backups do próprio diretório mais antigos que a retenção. Proteja `backups/` (fora do Git, permissões restritas, cópia externa criptografada).

Relatórios persistidos ficam no volume `csc_reports_data`; inclua-o no backup (`docker run --rm -v csc_reports_data:/d -v ${PWD}/backups:/b alpine tar czf /b/reports.tgz -C /d .`).

## Verificação de restauração (ambiente isolado)
```powershell
./scripts/restore_db_verify.ps1 -DumpFile backups/csc_<timestamp>.dump
```
Valida checksum, restaura em container efêmero `csc-restore-test` e imprime nº de tabelas e a revisão Alembic. Testado em 2026-10-23: 18 tabelas, `0003_phase7_automations`.

## Recuperação real
1. `docker compose stop backend worker beat frontend`
2. Restaure no banco ativo somente com autorização explícita: `pg_restore -U postgres -d cybersecuritychecker --clean --if-exists` a partir do dump.
3. `docker compose up -d` e confirme `/api/v1/ready`.
