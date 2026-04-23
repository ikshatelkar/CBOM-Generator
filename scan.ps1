param(
    [string]$Target = "test repo/hiddify-app-main",
    [string]$Output = "cbom.json"
)

Write-Host "Scanning: $Target"
go run ./cmd/cbom-scanner/... -dir $Target -output $Output
