# PowerShell smoke test for Windows host
Write-Host "Checking Phase 0 Infrastructure (PowerShell)..." -ForegroundColor Cyan

function Test-Endpoint($name, $url) {
    try {
        $res = Invoke-WebRequest -Uri $url -Method Get -TimeoutSec 3 -UseBasicParsing -ErrorAction Stop
        Write-Host "  [PASS] $name is reachable (HTTP $($res.StatusCode))" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "  [WARN] $name is not reachable ($url)" -ForegroundColor Yellow
        return $false
    }
}

Test-Endpoint "OpenSearch" "http://localhost:9200/_cluster/health"
Test-Endpoint "Keycloak" "http://localhost:8080/realms/cyberrange"
Test-Endpoint "MinIO" "http://localhost:9000/minio/health/live"
Test-Endpoint "OpenSearch Dashboards" "http://localhost:5601"
