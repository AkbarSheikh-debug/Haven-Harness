$ok = $false
try {
  $want = (Import-Csv sales.csv | Measure-Object -Property amount -Sum).Sum
  $got = [double]((Get-Content total.txt -Raw).Trim())
  $ok = ($got -eq $want)
} catch { $ok = $false }
if ($ok) { Set-Content -Path $env:HN_REWARD -Value 1 } else { Set-Content -Path $env:HN_REWARD -Value 0 }
