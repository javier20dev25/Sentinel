$results = "SENTINEL MASTER TEST REPORT`n"
$results += "Generated at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n"
$results += "=================================================`n`n"

$examples = Get-ChildItem "examples/*.sentinel"

foreach ($file in $examples) {
    Write-Host "Validating $($file.Name)..."
    $out = node src/ui/cli/index.js playbook validate $file.FullName
    $results += "## VALIDATION: $($file.Name)`n"
    $results += "Result: $out`n`n"
}

$results += "## SIMULATION: risk-graph-test.sentinel`n"
Write-Host "Simulating risk-graph-test..."
// Using escaped quotes for PowerShell JSON arg
$sim = node src/ui/cli/index.js playbook simulate examples/risk-graph-test.sentinel --context '{\"event\":{\"type\":\"install\"},\"package\":{\"name\":\"test-pkg\"}}'
$results += "Output:`n$sim`n`n"

$results += "## EXPLAIN: oracle-privacy.sentinel`n"
Write-Host "Explaining oracle-privacy..."
$exp = node src/ui/cli/index.js playbook explain examples/oracle-privacy.sentinel --context '{\"event\":{\"changedFiles\":[\"src/crypto/aes.js\"]},\"risk\":{\"band\":\"HIGH\",\"score\":0.85}}'
$results += "Output:`n$exp`n`n"

$results += "## SYSTEM STATUS`n"
$results += "Sync Status:`n"
$results += (node src/ui/cli/index.js sync status)
$results += "`nGraph Stats (axois):`n"
$results += (node src/ui/cli/index.js graph stats package:axois)
$results += "`n"

$results | Out-File -FilePath "docs/TEST_MASTER_REPORT.md" -Encoding utf8
Write-Host "Master test report generated: docs/TEST_MASTER_REPORT.md"
