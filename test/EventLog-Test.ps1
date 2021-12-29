<#̷#̷\
#̷\ 
#̷\   ⼕龱ᗪ㠪⼕闩丂ㄒ龱尺 ᗪ㠪ᐯ㠪㇄龱尸爪㠪𝓝ㄒ
#̷\    
#̷\   🇵​​​​​🇴​​​​​🇼​​​​​🇪​​​​​🇷​​​​​🇸​​​​​🇭​​​​​🇪​​​​​🇱​​​​​🇱​​​​​ 🇸​​​​​🇨​​​​​🇷​​​​​🇮​​​​​🇵​​​​​🇹​​​​​ 🇧​​​​​🇾​​​​​ 🇨​​​​​🇴​​​​​🇩​​​​​🇪​​​​​🇨​​​​​🇦​​​​​🇸​​​​​🇹​​​​​🇴​​​​​🇷​​​​​@🇮​​​​​🇨​​​​​🇱​​​​​🇴​​​​​🇺​​​​​🇩​​​​​.🇨​​​​​🇴​​​​​🇲​​​​​
#̷\ 
#̷##>

<#
    .Synopsis
        Test only
    .Description
        Test only
#>



[CmdletBinding(SupportsShouldProcess)]
param(
   [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=0)]
   [int]$Id,
   [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=1)]
   [string]$Description,
   [Parameter(Mandatory=$false)]
   [switch]$Loop
 )

function New-CustomEvent{
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=0)]
        [int]$Id,
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=1)]
        [string]$Description         
    )
    $evt=new-object System.Diagnostics.Eventlog("Setup")
    $evt.Source="MyTest"
    $evtNumber=$Id
    $evtDescription=$Description
    $infoevent=[System.Diagnostics.EventLogEntryType]::Warning
    $evt.WriteEntry($evtDescription,$infoevent,$evtNumber)
}


if($Loop){
    For($i = 0 ; $i -lt 100 ; $i++){
        $Id = $Id+$i
        New-CustomEvent -Id $Id -Description $Description 
        Write-Host "`n=======================================================" -f DarkRed
        Write-Host "Adding Windows Event..." -f DarkYellow -n 
        Write-Host "Done!" -f DarkGreen 
        Sleep 1
    }
}else{
    New-CustomEvent -Id $Id -Description $Description 
    Write-Host "`n=======================================================" -f DarkRed
    Write-Host "Adding Windows Event..." -f DarkYellow -n 
    Write-Host "Done!" -f DarkGreen 
}


