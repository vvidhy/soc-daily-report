param(
    [string]$Environment = "PROD-GL",
    [int]$RangeSeconds = 960,
    [string]$Query = "source:Winlogbeat OR source:Security OR source:Azure OR source:Rsyslog OR source:SFTP OR source:IIS OR source:Fortigate"
)

# Map environment to URL and token
$envMap = @{
    "PROD-GL" = @{
        BaseUrl = "https://siem.casepoint.com"
        Token = "3647ubk4usd0a30o0pjmrsu891uqvfsk2caj3bcdi4tsn5ojtsd"
    }
    "AZ-GL" = @{
        BaseUrl = "https://logs.casepointgov.com"
        Token = "16dq8t4e0enjrbe3pfi7gi6qfpst011ps30187u6srvjm518eptb"
    }
    "DEV-GL" = @{
        BaseUrl = "https://siem.casepoint.in"
        Token = "73v309coo8802g0p6sf7op3mni4dgkb4r1p6k9irgou5o53ovml"
    }
    "OP-GL" = @{
        BaseUrl = "https://siem.secureocp.com"
        Token = "1oaq7u2tlimoe5kv3nqcplk3tv2pntkkrjlp42o6ukol9rr27l9r"
    }
}

$env = $envMap[$Environment]
if (-not $env) {
    Write-Error "Unknown environment: $Environment"
    exit 1
}

$headers = @{
    "X-Graylog-API-Token" = $env.Token
    "Accept" = "application/json"
}

# Build search query - Graylog relative time syntax: 16m = 16 minutes
$searchParams = @{
    query = $Query
    range = 16
    range_type = "relative"
    limit = 1000
    sort = "timestamp:desc"
}

$body = $searchParams | ConvertTo-Json
$uri = "$($env.BaseUrl)/api/search/universal/relative"

try {
    Write-Host "Querying $Environment for last $RangeSeconds seconds..."
    Write-Host "Query: $Query"

    $response = Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -Body $body -ContentType "application/json" -SkipCertificateCheck

    Write-Host "Response received, message count: $($response.result.length)"
    $response | ConvertTo-Json -Depth 10
}
catch {
    Write-Host "Error querying $Environment : $_"
    Write-Host $_.Exception.Response.StatusCode
    exit 1
}
