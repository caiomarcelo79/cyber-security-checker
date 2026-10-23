# Backup lógico do PostgreSQL (container csc-postgres) com retenção. Não exclui nada além de backups antigos do próprio diretório.
param(
    [string]$OutDir = "backups",
    [int]$RetentionDays = 14,
    [string]$Container = "csc-postgres",
    [string]$DbUser = "postgres",
    [string]$DbName = "cybersecuritychecker"
)
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$file = Join-Path $OutDir ("csc_{0}.dump" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
docker exec $Container pg_dump -U $DbUser -d $DbName -Fc -f /tmp/backup.dump
if ($LASTEXITCODE -ne 0) { throw "pg_dump falhou" }
docker cp "${Container}:/tmp/backup.dump" $file
docker exec $Container rm -f /tmp/backup.dump
if (-not (Test-Path $file) -or (Get-Item $file).Length -eq 0) { throw "Backup vazio/ausente" }
(Get-FileHash $file -Algorithm SHA256).Hash | Set-Content "$file.sha256"
Get-ChildItem $OutDir -Filter "csc_*.dump*" | Where-Object LastWriteTime -lt (Get-Date).AddDays(-$RetentionDays) | Remove-Item
Write-Output "Backup OK: $file"
