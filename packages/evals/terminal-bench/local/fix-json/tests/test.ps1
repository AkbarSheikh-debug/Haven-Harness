$ok = $false
try {
  $c = Get-Content config.json -Raw | ConvertFrom-Json
  $ok = ($c.port -is [int] -or $c.port -is [long]) -and ($c.port -eq 8080) -and ($c.name -eq 'demo') -and ($c.debug -eq $false)
} catch { $ok = $false }
if ($ok) { Set-Content -Path $env:HN_REWARD -Value 1 } else { Set-Content -Path $env:HN_REWARD -Value 0 }
