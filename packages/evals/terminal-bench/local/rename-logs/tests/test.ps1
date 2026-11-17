$ok = $false
try {
  $logs = @(Get-ChildItem logs -Filter *.log)
  $ok = ($logs.Count -eq 0) -and ((Get-Content logs/a.txt -Raw).Trim() -eq 'alpha') -and ((Get-Content logs/b.txt -Raw).Trim() -eq 'beta') -and ((Get-Content logs/c.txt -Raw).Trim() -eq 'gamma')
} catch { $ok = $false }
if ($ok) { Set-Content -Path $env:HN_REWARD -Value 1 } else { Set-Content -Path $env:HN_REWARD -Value 0 }
