# build-report-workbook.ps1
# Builds ONE multi-tab Excel workbook (reports-noskill\SOC-noskill-report.xlsx)
# from every daily-SOC-noskill-YYYY-MM-DD.csv in reports-noskill - one worksheet
# per date, the TAB NAMED BY THE DATE. Rebuilt fresh each run so it always holds
# today + all prior days as tabs (no new file per day).
# Pure .NET (System.IO.Compression OpenXML) - no Excel, no modules, no internet.
$ErrorActionPreference='Continue'
$proj='D:\Vidhya\New Daily hunt'
$dir="$proj\reports-noskill"
$outXlsx="$dir\SOC-noskill-report.xlsx"

Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue
Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue

function XmlEsc([string]$s){
  if($null -eq $s){ return '' }
  $s = $s -replace '[^\x20-\x7E]',''          # ASCII-only (matches CSV cleaning)
  $s = $s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;'
  return $s
}
function ColLetter([int]$i){                    # 1-based index -> A, B, ... AA
  $s=''
  while($i -gt 0){ $m=($i-1)%26; $s=[char](65+$m)+$s; $i=[int][math]::Floor(($i-1)/26) }
  return $s
}

$csvs = Get-ChildItem $dir -Filter 'daily-SOC-noskill-*.csv' -ErrorAction SilentlyContinue | Sort-Object Name
if(-not $csvs){ Write-Output 'build-workbook: no daily CSVs found - nothing to build.'; return }

# Build one worksheet XML per CSV (tab = date from filename)
$sheets=@()
foreach($f in $csvs){
  $dateName = ($f.BaseName -replace '^daily-SOC-noskill-','')   # YYYY-MM-DD
  if($dateName.Length -gt 31){ $dateName=$dateName.Substring(0,31) }
  $rows=@(); try { $rows=@(Import-Csv $f.FullName) } catch {}
  $cols=@(); if($rows.Count -gt 0){ $cols=@($rows[0].PSObject.Properties.Name) }
  $sb=New-Object System.Text.StringBuilder
  [void]$sb.Append('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>')
  [void]$sb.Append('<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>')
  if($cols.Count -gt 0){
    [void]$sb.Append('<row r="1">')
    for($c=0;$c -lt $cols.Count;$c++){
      [void]$sb.Append('<c r="'+(ColLetter ($c+1))+'1" t="inlineStr" s="1"><is><t xml:space="preserve">'+(XmlEsc $cols[$c])+'</t></is></c>')
    }
    [void]$sb.Append('</row>')
    $r=1
    foreach($row in $rows){
      $r++
      [void]$sb.Append('<row r="'+$r+'">')
      for($c=0;$c -lt $cols.Count;$c++){
        $val=[string]$row.($cols[$c])
        [void]$sb.Append('<c r="'+(ColLetter ($c+1))+$r+'" t="inlineStr"><is><t xml:space="preserve">'+(XmlEsc $val)+'</t></is></c>')
      }
      [void]$sb.Append('</row>')
    }
  }
  [void]$sb.Append('</sheetData></worksheet>')
  $sheets += @{ name=$dateName; xml=$sb.ToString() }
}

# workbook.xml + rels + content-types
$wbSheets=''; $wbRels=''; $ctOverrides=''
for($i=0;$i -lt $sheets.Count;$i++){
  $n=$i+1
  $wbSheets    += '<sheet name="'+(XmlEsc $sheets[$i].name)+'" sheetId="'+$n+'" r:id="rId'+$n+'"/>'
  $wbRels      += '<Relationship Id="rId'+$n+'" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet'+$n+'.xml"/>'
  $ctOverrides += '<Override PartName="/xl/worksheets/sheet'+$n+'.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
}
$wbRels += '<Relationship Id="rIdStyles" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'

$workbookXml  = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>'+$wbSheets+'</sheets></workbook>'
$workbookRels = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'+$wbRels+'</Relationships>'
$contentTypes = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'+$ctOverrides+'</Types>'
$rootRels     = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>'
$stylesXml    = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><name val="Calibri"/></font></fonts><fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills><borders count="1"><border/></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/></cellXfs></styleSheet>'

if(Test-Path $outXlsx){ Remove-Item $outXlsx -Force -ErrorAction SilentlyContinue }
$fs  = [System.IO.File]::Open($outXlsx,[System.IO.FileMode]::Create)
$zip = New-Object System.IO.Compression.ZipArchive -ArgumentList $fs, ([System.IO.Compression.ZipArchiveMode]::Create), $true
function AddZipEntry($zip,$name,$content){
  $e=$zip.CreateEntry($name)
  $w=New-Object System.IO.StreamWriter -ArgumentList $e.Open(), (New-Object System.Text.UTF8Encoding -ArgumentList $false)
  $w.Write($content); $w.Flush(); $w.Dispose()
}
AddZipEntry $zip '[Content_Types].xml' $contentTypes
AddZipEntry $zip '_rels/.rels' $rootRels
AddZipEntry $zip 'xl/workbook.xml' $workbookXml
AddZipEntry $zip 'xl/_rels/workbook.xml.rels' $workbookRels
AddZipEntry $zip 'xl/styles.xml' $stylesXml
for($i=0;$i -lt $sheets.Count;$i++){ AddZipEntry $zip ('xl/worksheets/sheet'+($i+1)+'.xml') $sheets[$i].xml }
$zip.Dispose(); $fs.Close()
Write-Output ("build-workbook: wrote $outXlsx with $($sheets.Count) tab(s): " + (($sheets | ForEach-Object { $_.name }) -join ', '))
