$ok = $false
try { $ok = ([int]((Get-Content errors.txt -Raw).Trim()) -eq 3) } catch { $ok = $false }
if ($ok) { Set-Content -Path $env:HN_REWARD -Value 1 } else { Set-Content -Path $env:HN_REWARD -Value 0 }
