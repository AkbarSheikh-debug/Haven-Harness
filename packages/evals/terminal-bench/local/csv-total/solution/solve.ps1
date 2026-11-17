$sum = (Import-Csv sales.csv | Measure-Object -Property amount -Sum).Sum
Set-Content -Path total.txt -Value $sum
