Get-ChildItem logs -Filter *.log | ForEach-Object { Rename-Item -Path $_.FullName -NewName ($_.BaseName + '.txt') }
