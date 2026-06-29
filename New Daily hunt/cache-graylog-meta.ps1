# cache-graylog-meta.ps1
# Refresh the Graylog stream + input ID caches from LIVE data on all 4 GLs so hunts never
# run on stale IDs. Writes:
#   - streams.json       (by_gl: title -> id, active non-internal streams)        [rebuilt]
#   - infra-streams.json (curated categories; IDs refreshed in place by title)    [updated]
#   - inputs.json        (per-GL inputs: title/id/type/port) - the input fallback [rebuilt]
# Existing streams.json + infra-streams.json are backed up before overwrite.
# Auth/plumbing identical to graylog-rest-query.ps1 (BASE_URL + API_TOKEN from .mcp.json).
#   -DryRun : fetch + show the diff, write nothing.
param([switch]$DryRun)
$ErrorActionPreference='Stop'
$proj='D:\Vidhya\New Daily hunt'
$mcp=Get-Content "$proj\.mcp.json" -Raw | ConvertFrom-Json

add-type @"
using System.Net; using System.Security.Cryptography.X509Certificates;
public class GLCacheTrust : ICertificatePolicy { public bool CheckValidationResult(ServicePoint s, X509Certificate c, WebRequest r, int p){return true;} }
"@ -ErrorAction SilentlyContinue
[System.Net.ServicePointManager]::CertificatePolicy=New-Object GLCacheTrust
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12

$GLs='AZ-GL','PROD-GL','DEV-GL','OP-GL'
$internal=@('All events','All system events','All Investigation events','All Investigation messages','Processing and Indexing Failures','All messages','Default Stream')
$junk=@('test','testing','sss')   # scratch/test streams
function Hdr($tok){ $b=[Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($tok+':token')); @{Authorization=('Basic '+$b);'X-Requested-By'='soc-cache';Accept='application/json'} }

# ---- fetch live streams + inputs ----
$liveS=@{}; $liveI=@{}
foreach($gl in $GLs){
  $srv=$mcp.mcpServers.$gl; if(-not $srv){ throw "no .mcp.json entry for $gl" }
  $base=$srv.env.BASE_URL.TrimEnd('/'); $h=Hdr $srv.env.API_TOKEN
  $s  =Invoke-RestMethod -Uri ($base+'/api/streams')        -Headers $h -TimeoutSec 90
  $inp=Invoke-RestMethod -Uri ($base+'/api/system/inputs')  -Headers $h -TimeoutSec 90
  $liveS[$gl]=@($s.streams); $liveI[$gl]=@($inp.inputs)
  Write-Output ("FETCH {0,-8}: {1,3} streams  {2,3} inputs" -f $gl,@($s.streams).Count,@($inp.inputs).Count)
}

# ---- load existing cache (for _meta, known_dead, diff) ----
$old=Get-Content "$proj\streams.json" -Raw | ConvertFrom-Json
$dead=@{}
foreach($gl in $GLs){
  $dead[$gl]=@()
  if($old._meta.known_dead.PSObject.Properties[$gl]){ $dead[$gl]=@($old._meta.known_dead.$gl | ForEach-Object { ($_ -split ' \(')[0].Trim() }) }
}

# ---- build by_gl (active, non-internal, non-junk, non-dead) title->id ----
$byGl=[ordered]@{}
foreach($gl in $GLs){
  $m=[ordered]@{}
  foreach($st in ($liveS[$gl] | Sort-Object title)){
    if($st.disabled){ continue }
    if([string]$st.id -match '^0{23}\d$'){ continue }       # Graylog system streams (incl Default Stream 001)
    $t=([string]$st.title).Trim()
    if(($internal -contains $t) -or ($t -match '^Graylog')){ continue }
    if($junk -contains $t.ToLower()){ continue }            # test/testing/sss scratch streams
    if($dead[$gl] -contains $t){ continue }                 # known-dead per GL (Opensearch/SMA/Pg_bkp/etc.)
    if(-not $m.Contains($t)){ $m[$t]=[string]$st.id }
  }
  $byGl[$gl]=$m
}
Write-Output ""; Write-Output "=== DIFF vs existing streams.json (title -> id) ==="
foreach($gl in $GLs){
  $o=$old.by_gl.$gl; $n=$byGl[$gl]
  $oTitles=@($o.PSObject.Properties.Name)
  foreach($t in $n.Keys){
    $oid = if($o.PSObject.Properties[$t]){ [string]$o.$t } else { $null }
    if(-not $oid){ Write-Output ("  {0}: + NEW   {1} = {2}" -f $gl,$t,$n[$t]) }
    elseif($oid -ne [string]$n[$t]){ Write-Output ("  {0}: ~ ID    {1}  {2} -> {3}" -f $gl,$t,$oid,$n[$t]) }
  }
  foreach($t in $oTitles){ if(-not $n.Contains($t)){ Write-Output ("  {0}: - GONE  {1} (was {2})" -f $gl,$t,[string]$o.$t) } }
}

# ---- build inputs.json (per-GL: title/id/type/port) ----
$inputsOut=[ordered]@{}
foreach($gl in $GLs){
  $arr=@()
  foreach($i in ($liveI[$gl] | Sort-Object title)){
    $port = if($i.attributes -and $i.attributes.PSObject.Properties['port']){ $i.attributes.port } else { $null }
    $arr += [ordered]@{ title=[string]$i.title; id=[string]$i.id; type=([string]$i.type -replace '.*\.',''); port=$port; global=[bool]$i.global }
  }
  $inputsOut[$gl]=$arr
}

# ---- refresh infra-streams.json IDs in place (preserve curation) ----
$infra=Get-Content "$proj\infra-streams.json" -Raw | ConvertFrom-Json
$infraChanges=0
foreach($cat in $infra.categories.PSObject.Properties.Name){
  foreach($gl in $infra.categories.$cat.PSObject.Properties.Name){
    foreach($entry in @($infra.categories.$cat.$gl)){
      $t=([string]$entry.title).Trim()
      if($byGl[$gl].Contains($t)){
        $liveId=[string]$byGl[$gl][$t]
        if([string]$entry.id -ne $liveId){ Write-Output ("  infra[{0}/{1}] {2}: {3} -> {4}" -f $cat,$gl,$t,$entry.id,$liveId); $entry.id=$liveId; $infraChanges++ }
      }
    }
  }
}
Write-Output ("infra-streams.json id changes: {0}" -f $infraChanges)

if($DryRun){ Write-Output ""; Write-Output "DRY RUN - no files written."; return }

# ---- backup then write ----
$bk="$proj\_trash-20260614\cache-backup-$(Get-Date -Format yyyyMMdd-HHmmss)"
New-Item -ItemType Directory -Force -Path $bk | Out-Null
Copy-Item "$proj\streams.json" $bk -Force
Copy-Item "$proj\infra-streams.json" $bk -Force
Write-Output ("backed up streams.json + infra-streams.json -> {0}" -f $bk)

$today=Get-Date -Format 'yyyy-MM-dd'
$meta=[ordered]@{
  purpose   = $old._meta.purpose
  how_to_use= $old._meta.how_to_use
  excluded  = $old._meta.excluded
  note      = $old._meta.note
  resolved  = $today
  known_dead= $old._meta.known_dead
}
$streamsObj=[ordered]@{ _meta=$meta; by_gl=$byGl }
[IO.File]::WriteAllText("$proj\streams.json",   ($streamsObj | ConvertTo-Json -Depth 8),  [Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText("$proj\infra-streams.json",($infra   | ConvertTo-Json -Depth 12), [Text.UTF8Encoding]::new($false))
$inputsObj=[ordered]@{ _meta=[ordered]@{ purpose='Per-GL Graylog INPUT id cache (title->id/type/port). Fallback for hunts: when a stream returns 0 (routing broken) query gl2_source_input:<id> instead. Resolved from /api/system/inputs.'; resolved=$today }; by_gl=$inputsOut }
[IO.File]::WriteAllText("$proj\inputs.json",     ($inputsObj | ConvertTo-Json -Depth 8),  [Text.UTF8Encoding]::new($false))

Write-Output ""
Write-Output ("WROTE streams.json ({0} GLs), infra-streams.json ({1} id fixes), inputs.json" -f $byGl.Count,$infraChanges)
foreach($gl in $GLs){ Write-Output ("  {0,-8}: {1,3} streams cached, {2,3} inputs cached" -f $gl,$byGl[$gl].Count,$inputsOut[$gl].Count) }
