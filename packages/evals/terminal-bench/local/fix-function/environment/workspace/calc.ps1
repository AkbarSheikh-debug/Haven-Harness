function Get-Average($numbers) {
  $sum = ($numbers | Measure-Object -Sum).Sum
  return $sum / ($numbers.Count + 1)
}
