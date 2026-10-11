$appJsPath = 'C:/Users/SubbulakshmiT/.gemini/antigravity-ide/scratch/cyber-attack-book/app.js'
$content = [System.IO.File]::ReadAllText($appJsPath)

$searchMarker = "// Application State"
$markerIdx = $content.IndexOf($searchMarker)
if ($markerIdx -lt 0) {
    Write-Host "Marker not found!"
    exit 1
}

# Find the last '];' before markerIdx
$bracketIdx = $content.LastIndexOf("];", $markerIdx)
if ($bracketIdx -lt 0) {
    Write-Host "Bracket not found!"
    exit 1
}

Write-Host "Found bracket at index $bracketIdx, marker at $markerIdx"

# Let's inspect the 50 chars before the bracket
$snippet = $content.Substring($bracketIdx - 30, 32)
Write-Host "Snippet before bracket: [$snippet]"
