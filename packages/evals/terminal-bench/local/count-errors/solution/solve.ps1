$n = (Get-Content app.log | Where-Object { $_ -cmatch 'ERROR' }).Count
Set-Content -Path errors.txt -Value $n
