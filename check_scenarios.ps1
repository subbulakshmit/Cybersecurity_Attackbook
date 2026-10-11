$content = Get-Content -Raw -Path 'assessment.js'
$regex = [regex]'id:\s*"sc_([^"]+)",\s*title:\s*"([^"]+)"'
$matches = $regex.Matches($content)
foreach ($m in $matches) {
    Write-Host "sc_$($m.Groups[1].Value) | $($m.Groups[2].Value)"
}
Write-Host "Total scenarios: $($matches.Count)"
