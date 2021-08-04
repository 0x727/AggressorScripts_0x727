$xml='<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[(EventID=4624)]]</Select>
  </Query>
</QueryList>'
$events = Get-WinEvent -FilterXml $xml
$i=0
Write-Host '登录时间','登录类型','登录账号','登录IP地址'
while ($i -lt $events.length) {
    $time=$events[$i].TimeCreated
    $type=[regex]::matches($events[$i].Message, '登录类型:(.+)') | %{$_.Groups[1].Value.Trim()}
    $user=([regex]::matches($events[$i].Message, '帐户名:(.+)') | %{$_.Groups[1].Value.Trim()})[1]
    $IP=[regex]::matches($events[$i].Message, '源网络地址:(.+)') | %{$_.Groups[1].Value.Trim()}
    Write-Host $time,$user,$type,$IP
    $i++
}