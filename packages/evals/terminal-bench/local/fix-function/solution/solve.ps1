Set-Content -Path calc.ps1 -Value 'function Get-Average($numbers) { return ($numbers | Measure-Object -Average).Average }'
