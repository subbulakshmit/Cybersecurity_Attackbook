$appJsPath = 'C:/Users/SubbulakshmiT/.gemini/antigravity-ide/scratch/cyber-attack-book/app.js'
$content = [System.IO.File]::ReadAllText($appJsPath)

$searchMarker = "// Application State"
$markerIdx = $content.IndexOf($searchMarker)
if ($markerIdx -lt 0) {
    Write-Host "Marker not found!"
    exit 1
}

$bracketIdx = $content.LastIndexOf("];", $markerIdx)
if ($bracketIdx -lt 0) {
    Write-Host "Bracket not found!"
    exit 1
}

# Load the new attacks code from inject_attacks.ps1 or separate file
$attacksFile = 'C:/Users/SubbulakshmiT/.gemini/antigravity-ide/scratch/cyber-attack-book/attacks_84_110.txt'
$newAttacksCode = [System.IO.File]::ReadAllText($attacksFile)

$before = $content.Substring(0, $bracketIdx)
$after = $content.Substring($bracketIdx)

# Check if before ends with closing brace
$trimmedBefore = $before.TrimEnd()

$newContent = $trimmedBefore + ",`r`n" + $newAttacksCode + "`r`n];`r`n`r`n" + $content.Substring($markerIdx)

[System.IO.File]::WriteAllText($appJsPath, $newContent, [System.Text.Encoding]::UTF8)
Write-Host "SUCCESS: Injected attacks into app.js! New length: $($newContent.Length)"
