# Sentinel: Repository Integrity Manifest Generator (v1.0)
# Generates a SHA-256 audit log of all commits for forensic verification.

$manifestPath = "MANIFEST_INTEGRITY.txt"
$results = "SENTINEL REPOSITORY INTEGRITY MANIFEST`n"
$results += "Generated at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n"
$results += "System: $([System.Environment]::MachineName)`n"
$results += "=================================================`n`n"

Write-Host "Collecting git commit hashes and generating checksums..."

# Get all commit hashes and their timestamps
$commits = git log --pretty=format:"%H | %ad | %s" --date=iso

foreach ($line in $commits) {
    $hash = $line.Split("|")[0].Trim()
    # Generate SHA-256 for the commit data string itself as a secondary proof
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($line)
    $checksum = [System.BitConverter]::ToString($sha.ComputeHash($bytes)).Replace("-", "").ToLower()
    
    $results += "COMMIT: $hash`n"
    $results += "DATA:   $line`n"
    $results += "SHA256: $checksum`n"
    $results += "-------------------------------------------------`n"
}

$results | Out-File -FilePath $manifestPath -Encoding utf8
Write-Host "Integrity manifest generated: $manifestPath"
Write-Host "Verification complete. Maintain this file as an immutable audit trail."
