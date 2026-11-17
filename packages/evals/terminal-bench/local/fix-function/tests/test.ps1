$ok = $false
try {
  . ./calc.ps1
  $ok = ((Get-Average @(2, 4, 6)) -eq 4) -and ((Get-Average @(5)) -eq 5) -and ((Get-Average @(1, 2)) -eq 1.5)
} catch { $ok = $false }
if ($ok) { Set-Content -Path $env:HN_REWARD -Value 1 } else { Set-Content -Path $env:HN_REWARD -Value 0 }
