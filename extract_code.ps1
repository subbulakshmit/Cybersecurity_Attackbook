$injectFile = 'C:/Users/SubbulakshmiT/.gemini/antigravity-ide/scratch/cyber-attack-book/inject_attacks.ps1'
$txt = [System.IO.File]::ReadAllText($injectFile)

$startMarker = '$newAttacksCode = @''' + "`r`n"
$startIdx = $txt.IndexOf($startMarker)
if ($startIdx -lt 0) {
    # Try LF
    $startMarker = '$newAttacksCode = @''' + "`n"
    $startIdx = $txt.IndexOf($startMarker)
}
$contentStart = $startIdx + $startMarker.Length

$endMarker = "`r`n'@`r`n"
$endIdx = $txt.IndexOf($endMarker, $contentStart)
if ($endIdx -lt 0) {
    $endMarker = "`n'@`n"
    $endIdx = $txt.IndexOf($endMarker, $contentStart)
}

$attacksCode = $txt.Substring($contentStart, $endIdx - $contentStart)
[System.IO.File]::WriteAllText('C:/Users/SubbulakshmiT/.gemini/antigravity-ide/scratch/cyber-attack-book/attacks_84_110.txt', $attacksCode, [System.Text.Encoding]::UTF8)
Write-Host "Extracted attacks code length: $($attacksCode.Length)"
