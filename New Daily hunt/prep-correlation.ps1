# Token optimization for the correlation step: instead of having the (expensive) correlation
# hunt read all 6 full markdown reports into context, pre-extract just the findings-json from
# each into one compact array. Correlation then reads this single small file - far fewer input
# tokens, no quality loss (the IPs/users/hosts it correlates on live in the finding/evidence fields).
$dir='D:\Vidhya\New Daily hunt\reports'
$all=@()
foreach($f in (Get-ChildItem $dir -Filter '*-latest.md' -ErrorAction SilentlyContinue | Where-Object { $_.BaseName -ne 'correlation-latest' })){
  $txt=Get-Content $f.FullName -Raw
  $m=[regex]::Match($txt,'(?ms)```findings-json\s*[\r\n]+(.*?)[\r\n]+```')
  if($m.Success){ try { $arr=$m.Groups[1].Value | ConvertFrom-Json; foreach($x in $arr){ $all+=$x } } catch {} }
}
$out="$dir\_merged-findings.json"
($all | ConvertTo-Json -Depth 6 -Compress) | Set-Content -Path $out -Encoding UTF8
Write-Output "prep-correlation: merged $($all.Count) findings into _merged-findings.json"
