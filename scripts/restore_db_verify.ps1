# Restaura um dump em um container PostgreSQL EFÊMERO e isolado (nunca toca o banco ativo) e verifica integridade.
param(
    [Parameter(Mandatory = $true)][string]$DumpFile,
    [string]$DbName = "cybersecuritychecker"
)
$ErrorActionPreference = "Stop"
$shaFile = "$DumpFile.sha256"
if (Test-Path $shaFile) {
    if ((Get-FileHash $DumpFile -Algorithm SHA256).Hash -ne (Get-Content $shaFile).Trim()) { throw "Checksum divergente" }
}
$name = "csc-restore-test"
cmd /c "docker rm -f $name >nul 2>&1"
docker run -d --name $name -e POSTGRES_PASSWORD=restore_test -e POSTGRES_DB=$DbName postgres:16-alpine | Out-Null
try {
    for ($i = 0; $i -lt 30; $i++) { cmd /c "docker exec $name pg_isready -h 127.0.0.1 -U postgres -d $DbName >nul 2>&1"; if ($LASTEXITCODE -eq 0) { break }; Start-Sleep 1 }
    docker cp $DumpFile "${name}:/tmp/r.dump"
    docker exec $name pg_restore -U postgres -d $DbName --no-owner /tmp/r.dump
    if ($LASTEXITCODE -ne 0) { throw "pg_restore falhou" }
    docker exec $name psql -U postgres -d $DbName -t -A -c "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'"
    docker exec $name psql -U postgres -d $DbName -t -A -c "SELECT version_num FROM alembic_version"
    Write-Output "Restauração verificada em ambiente isolado."
}
finally { docker rm -f $name | Out-Null }
