$content = Get-Content -Raw -Path 'app.js'
$regex = [regex]'num:\s*(\d+),\s*id:\s*"([^"]+)",\s*name:\s*"([^"]+)"'
$matches = $regex.Matches($content)
foreach ($m in $matches) {
    Write-Host "$($m.Groups[1].Value) | $($m.Groups[2].Value) | $($m.Groups[3].Value)"
}
Write-Host "Total attacks found: $($matches.Count)"
