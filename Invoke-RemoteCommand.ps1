##Requires -RunAsAdministrator
#Invoke-RemoteCommand, Copyright © Bartosz Rojek (bartoszrojek@gmail.com), all rights reserved
<#
  .SYNOPSIS
    Invoke-RemoteCommand
  .DESCRIPTION
    Uruchom dowolny kod lub skrypt zdalnie bez konieczności ciągłego podawania danych logowania

  .EXAMPLE
    .\Invoke-RemoteCommand.ps1 -$ComputerName -Code { Get-ChildItem c:\users }

  .EXAMPLE
    .\Invoke-RemoteCommand.ps1 -ServerList .\s1.txt -File Remote-Script-01.ps1

    Przykładowa zawartość pliku s1.txt:

    SERVERFS1
    SERVERPS2,DomainNameForAccount
    169.168.0.1
    169.254.101.1,WORKGROUP
    ServerName,ServerIP,DomainNameForAccount

    UWAGA: Nazwa domeny określa domenę z danych logowania a nie to w jakiej domenie znajduje się server!

  .PARAMETER computername
  Nazwa komputera na któym chcemy zdalnie uruchomić kod lub skrypt
  .PARAMETER Code
  Kod, który chcemy zdalnie uruchomić
  .PARAMETER File
  Nazwa skryptu, który chcemy zdalnie uruchomić
  .PARAMETER UserName
  Globalna nazwa użytkownika dla każdej domeny
  #>
[cmdletbinding()]
param(
    [Alias( 'HostName', 'Server' )]
    [Parameter(Position = 0)]$ComputerName,
    [Parameter(Position = 1)][Alias( 'FilePath' )]
    [string]$File,
    [Parameter(Position = 2)][Alias( 'ScriptBlock' )]
    [scriptblock]$Code,
    [Parameter(Position = 3)]$ArgumentList,
    [Parameter(Position = 4)]$UserName,
    [Parameter(Position = 5)]$ServerList,
    [Parameter(Position = 6)][switch]$DontUseHostNameFromServerList
)

#Universal way to set working directory to script directory, works for PS, ISE, VSCode
$( try { $script:psEditor.GetEditorContext().CurrentFile.Path } catch {} ), $( try { $script:psISE.CurrentFile.Fullpath } catch {} ), $script:MyInvocation.MyCommand.Path | % { $_ | Split-Path -EA 0 | Set-Location }

# Import Credential Manager functions
. .\CredMan.ps1

#region Functions
function Get-CredentialEx {
    param($Message, $UserName)
    if ( $PSVersionTable.PSVersion.Major -ge 3 ) {
        Get-Credential -Message $Message -UserName $UserName
    } else { Get-Credential }
}
function Get-DuplicateIP {
    $tempHT = @{}
    $dataServerDomainIPList.IP | % { $tempHT["$_"] += 1 }
    $tempHT.keys | ? { $tempHT["$_"] -gt 1 } | % { $DuplicateIP = $true ; Write-Host "Duplicate IP found: $_" }
    if ( $DuplicateIP ) { break }
}
function Test-Port {
    Param([cmdletbinding()]
        [Alias('HostName', 'Server')]
        [parameter(Position = 0)]$ComputerName,
        [parameter(Position = 1, Mandatory = $true)]
        [int]$Port
    )
    $test = New-Object System.Net.Sockets.TcpClient
    Try {
        Write-Verbose "$($ComputerName):$Port"
        $test.Connect($ComputerName, $Port)
        Write-Verbose "Connection successful"
        return $true
    } Catch {
        Write-Verbose "Connection failed"
        return $false
    } Finally {
        $test.Close()
    }
}
function Test-PSR {
    param([cmdletbinding()]
        [Alias('HostName', 'Server')]
        [parameter(Position = 0)]$ComputerName,
        [parameter(Position = 1)]$Port = '5985'
    )
    Write-Verbose "Checking $($ComputerName):$Port ... "
    Test-Port $ComputerName $Port
}
function Test-RDP {
    param([cmdletbinding()]
        [Alias('HostName', 'Server')]
        [parameter(Position = 0)]$ComputerName,
        [parameter(Position = 1)]$Port = '3389'
    )
    Write-Verbose "$($ComputerName):$Port"
    Test-Port $ComputerName $Port
}
function Get-ServerDomainIPList {
    param($arg)
    [array]$dataServerDomainIPList = @()
    ( $arg | ? { $_.trim() -ne '' } ).TrimEnd(',') | % {
        $sdip = '' | Select-Object -Property Domain, ComputerName, IP
        if ( $_ -match ',' ) {
            $regex = [regex]"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
            if ( $regex.Matches(( $_ -split ',')[0] ).Success -eq $true ) {
                $sdip.ComputerName = ( $_ -split ',' )[0]
                $sdip.IP = ( $_ -split ',' )[0]
                $sdip.Domain = ( $_ -split ',' )[1]
            } else {
                if (( $_ -split ',' ).Count -eq 2 ) {
                    $sdip.ComputerName = ( $_ -split ',' )[0]
                    $sdip.IP = ( $_ -split ',' )[0]
                    $sdip.Domain = ( $_ -split ',' )[1]
                }
                if (( $_ -split ',' ).Count -ge 3 ) {
                    $sdip.ComputerName = ( $_ -split ',' )[0]
                    $sdip.IP = ( $_ -split ',' )[1]
                    $sdip.Domain = ( $_ -split ',' )[2]
                }
            }
        } else {
            $sdip.ComputerName = $_
            $sdip.IP = $_
        }
        if ( $sdip.Domain -eq '' -or $sdip.Domain -eq $null ) { $sdip.Domain = $standaloneDN }
        if ( $sdip.ComputerName -eq '' -or $sdip.ComputerName -eq $null ) { $sdip.ComputerName = $sdip.IP }
        #Checking PSR port at this point is not good idea, but RDP test can detect mistakes in server names
        if ( Test-RDP $sdip.IP ) {
            $dataServerDomainIPList += $sdip
        } else {
            Write-Host "RDP test failed for $($sdip.IP)"
            $LogRDPPortClosed = "Invoke-RemoteCommand-Log-$currentDateTime-RDP-Port-Closed.txt"
            $sdip.IP | Out-File -FilePath $LogRDPPortClosed -Force -Encoding UTF8 -Append
        }
    }
    return $dataServerDomainIPList
}
function New-CMServerCredentialPair {
    param($dataServerDomainIPList)

    function Set-TempPassword {
        $tempPassword = Read-Host -Prompt "Password for $tempUserName"
        $cred = @{ $tempUserName = $tempPassword }
        $dataDomainCredentialPair.Add( $domain, $cred )
        Remove-Variable -Name cred
    }

    function New-CMRecord {
        $tempUserName = $domain + '\' + $username
        if ( $dataDomainCredentialPair.ContainsKey($domain)) {
            $dataCred = $dataDomainCredentialPair.$domain.ContainsKey($tempUserName)
            if ( $dataCred ) {
                Write-Host "Login data for domain $domain found, using cached credential: $($dataDomainCredentialPair.$domain.keys)"
            } else {
                Set-TempPassword
            }
        } else {
            Set-TempPassword
        }
        New-CMCredential -Target $IP -UserName $dataDomainCredentialPair.$domain.keys -Password $dataDomainCredentialPair.$domain.Values -Comment $ComputerName
    }

    [hashtable]$dataDomainCredentialPair = @{}

    if ( $username -eq '' -or $username -eq $null ) {
        $username = $null
        Write-Host "No global username provided, assuming any matched valid Creditial Manager credentials will work."
    } else {
        Write-Host "Global username was provided, matched valid creditials must have $username as username."
    }

    $dataServerDomainIPList | % {
        $ComputerName = $_.ComputerName
        $domain = $_.domain
        $IP = $_.IP
        $DIPCN = $_.domain + '\' + $_.IP + ' ' + '(' + $_.ComputerName + ')'

        if ( $username ) {
            $CMCred = Get-CMCredential -Target $IP
            if ( $CMCred ) {
                Write-Host "Credential for $DIPCN exist, " -NoNewline
                $tempUserName = $domain + '\' + $UserName
                if ( $CMCred.UserName -eq $tempUserName ) {
                    Write-Host "login data match $tempUserName." -ForegroundColor Green
                } else {
                    Write-Host "login data NOT match: $($CMCred.UserName) | $tempUserName" -ForegroundColor Red
                    New-CMRecord
                }
            } else {
                Write-Host "There is no CMRecord for $IP($ComputerName), global username is: $username"
                New-CMRecord
            }
        } elseif ( $username -eq $null ) {

            $CMCred = Get-CMCredential -Target $IP
            if ( $CMCred ) {
                Write-Host "Credential for $DIPCN exist: $($CMCred.UserName)"
            } else {
                Write-Host "There is no CMRecord for $DIPCN, " -NoNewline
                if ( $dataDomainCredentialPair.ContainsKey($domain)) {
                    $dataCred = $dataDomainCredentialPair.$domain.ContainsKey($tempUserName)
                    Write-Host "login data for domain $domain found, using cached credential: $($dataDomainCredentialPair.$domain.keys)" -ForegroundColor Green
                } else {
                    Write-Host "please provide login data for $domain"
                    $tempUserName = $domain + '\' + (Read-Host -Prompt "Username for $domain")
                    Set-TempPassword
                }
                New-CMCredential -Target $IP -UserName $dataDomainCredentialPair.$domain.keys -Password $dataDomainCredentialPair.$domain.Values -Comment $ComputerName
            }
        }
    }
    Remove-Variable dataDomainCredentialPair
    [GC]::Collect()
}
function Invoke-RemoteCommand {
    param( $dataServerDomainIPList, $ScriptBlock, $ArgumentList )
    if ( $ComputerName -eq $env:COMPUTERNAME ) {
        Invoke-Command -ComputerName $env:COMPUTERNAME -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList -SessionOption $PSSessionOption -JobName ($jobPrefix + $env:COMPUTERNAME) # | Out-Null
    } else {
        $dataServerDomainIPList | % {
            Invoke-Command -ComputerName $_.IP -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList -SessionOption $PSSessionOption -JobName ($jobPrefix + $_.ComputerName) -Authentication Negotiate # | Out-Null
        }
    }

}
#endregion

$jobPrefix = 'IRCJ-'
$standaloneDN = 'WORKGROUP'
$PSSessionOption = New-PSSessionOption -OpenTimeout 1
$currentDateTime = Get-Date -Format yyyy.MM.dd-HH.mm #.ss
#$DontUseHostNameFromServerList = $false

#$ComputerName = "ASD\10.185.168.103#GR345NBFV","WORKGROUP\127.0.0.1#localhost"#,"D1\IP1#Name1","D1\IP2#Name2"
#$ServerList = '.\ServerList.csv'

#$Code = { Get-WmiObject Win32_Service -Filter $filter | Select-Object -First 10 -Property Name, StartName }
#$Code = { tracert -h 1 www.o2.pl }

#$Code = { ls }
$Code = [scriptblock]::Create( $Code )
#$File = 'a.ps1'

if ( $help ) { Show-Info }
if ( $ComputerName -eq '.' ) { $ComputerName = $env:COMPUTERNAME }
if ( !$ComputerName -and !$ServerList ) { 'No server defined' ; break }
if ( !$File -and !$Code ) { 'Provide script which will be executed remotley, use -File or -Code switch.' ; break }
if ( $File -and $Code ) { 'You cannot use -File and -Code together.' ; break }

if ( $File ) {
    $FullName = ( Get-Item $File -EA 0 ).FullName
    if ( $FullName -eq $null ) {
        "There is no $File at $(( Get-Location ).Path )" ; break
    } else {
        [string]$dataFileContent = ( Get-Content -LiteralPath $FullName -Raw ).TrimEnd()
        $Code = [scriptblock]::Create($dataFileContent)
    }
}

if ( $ComputerName ) {

    [array]$dataServerDomainIPList = @()
    $ComputerName | % {
        $sdip = '' | Select-Object -Property Domain, ComputerName, IP
        if ( $_ -notmatch '\\') {
            $sdip.ComputerName = ($_ -split '#')[1]
            $sdip.IP = ($_ -split '#')[0]
        } else {
            $sdip.IP = (($_ -split '\\') -split '#')[1]
            $sdip.ComputerName = (($_ -split '\\') -split '#')[2]
            $sdip.Domain = (($_ -split '\\') -split '#')[0]
        }
        if ( $sdip.Domain -eq '' -or $sdip.Domain -eq $null ) { $sdip.Domain = $standaloneDN }
        if ( $sdip.ComputerName -eq '' -or $sdip.ComputerName -eq $null ) { $sdip.ComputerName = $sdip.IP }
        $dataServerDomainIPList += $sdip
    }

    $dataServerNames = $dataServerDomainIPList.IP -join ','
    $LogPSRPortClosed = "Invoke-RemoteCommand-Log-($dataServerNames)-$currentDateTime-PSR-Port-Closed.txt"
    $LogOffline = "Invoke-RemoteCommand-Log-($dataServerNames)-$currentDateTime-Offline.txt"
    $LogSuccess = "Invoke-RemoteCommand-Log-($dataServerNames)-$currentDateTime-Success.csv"
    $LogFailed = "Invoke-RemoteCommand-Log-($dataServerNames)-$currentDateTime-Failed.csv"

    $dataDomainList = $dataServerDomainIPList.Domain | Select-Object -Unique
}
if ( $ServerList ) {
    if (( Get-Item $ServerList -EA 0 ) -eq $null ) { "There is no $ServerList at $(( Get-Location ).Path)" ; break }
    $ServerListBN = Get-Item $ServerList -EA 0 | Select-Object -ExpandProperty Basename
    $LogPSRPortClosed = "Invoke-RemoteCommand-Log-($ServerListBN)-$currentDateTime-PSR-Port-Closed.txt"
    $LogOffline = "Invoke-RemoteCommand-Log-($ServerListBN)-$currentDateTime-Offline.txt"
    $LogSuccess = "Invoke-RemoteCommand-Log-($ServerListBN)-$currentDateTime-Success.csv"
    $LogFailed = "Invoke-RemoteCommand-Log-($ServerListBN)-$currentDateTime-Failed.csv"

    $dataServerDomainIPList = Get-ServerDomainIPList ( Get-Content $ServerList )
    $dataDomainList = $dataServerDomainIPList.Domain | Select-Object -Unique
}

if ( $DontUseHostNameFromServerList ) { Write-Host "DontUseHostNameFromServerList is enabled, script will be faster but results will contain only IP address" }
if ( !$DontUseHostNameFromServerList ) { Write-Host "DontUseHostNameFromServerList is NOT enabled, script will be slower" }

Get-DuplicateIP

Get-Job -Name "$jobPrefix*" | Remove-Job -Force

if ( $ComputerName -ne $env:COMPUTERNAME ) {
    New-CMServerCredentialPair -dataServerDomainIPList $dataServerDomainIPList
}

Invoke-RemoteCommand -dataServerDomainIPList $dataServerDomainIPList -ScriptBlock $Code -ArgumentList $ArgumentList | Out-Null

$dataJobListRunning = Get-Job -Name "$jobPrefix*" | ? { $_.State -eq 'Running' }
if ( $dataJobListRunning -ne $null ) {
    while ( (Get-Job -Name "$jobPrefix*" | ? { $_.State -eq 'Running' }).count -ne 0 ) { Start-Sleep -seconds 1 ; Write-Host '.' -NoNewline }
}

Write-Host ''

$dataJobListCompleted = Get-Job -Name "$jobPrefix*" | ? { $_.State -eq 'Completed' }
if ( $dataJobListCompleted ) {

    [array]$dataJobReceived = $null
    # Ugly syntax but faster execution
    foreach ( $_ in $dataJobListCompleted ) {
        $singleJobResults = $null
        $ComputerName = $_.Name.Substring($jobPrefix.Length)
        $PSComputerName = $_.Location
        #$LogSuccess = "Invoke-RemoteCommand-Log-($ComputerName)-$currentDateTime-Success.csv"
        $singleJobResults = Receive-Job $_ -Keep

        if (( $singleJobResults | ? { $_.gettype().Name -ne 'String' } ) -eq $null ) {
            $dataJobReceived += $singleJobResults | Select-Object -Property @{ LABEL = 'ComputerName' ; EXPRESSION = { $ComputerName } }, @{ LABEL = 'IP' ; EXPRESSION = { $PSComputerName }}, @{ LABEL = 'Output' ; EXPRESSION = { $singleJobResults }}, * -ExcludeProperty PSComputerName, RunspaceId, PSShowComputerName
            $singleJobResults = (( $singleJobResults.TrimEnd() ) -join "`r`n") # | Select-Object -Property @{ LABEL='ComputerName' ; EXPRESSION= {$ComputerName} },@{ LABEL='IP' ; EXPRESSION={ $PSComputerName }},@{ LABEL='Output' ; EXPRESSION={ $singleJobResults }},* -ExcludeProperty PSComputerName,RunspaceId,PSShowComputerName
            $singleJobResults | Out-File -LiteralPath $LogSuccess -Append -Force -Encoding utf8
        } else {
            if ( $DontUseHostNameFromServerList ) {
                $dataJobReceived += $singleJobResults
            } else {
                $singleJobResults = $singleJobResults | Select-Object -Property @{ LABEL = 'ComputerName' ; EXPRESSION = {$ComputerName} }, @{ LABEL = 'IP' ; EXPRESSION = { $PSComputerName }}, * -ExcludeProperty PSComputerName, RunspaceId, PSShowComputerName
                $dataJobReceived += $singleJobResults
            }
            $singleJobResults | % { Export-Csv -InputObject $_ -LiteralPath $LogSuccess -Append -NoTypeInformation -Force }
        }

    }
    #$dataJobReceived
    Write-Host "Completed jobs: $($dataJobListCompleted.count)" -ForegroundColor Green
    #$dataJobReceived | % { Export-Csv -InputObject $_ -LiteralPath $LogSuccess -Append -NoTypeInformation -Force }
}

$dataJobListFailed = Get-Job -Name "$jobPrefix*" | ? { $_.State -eq 'Failed' }
if ( $dataJobListFailed ) {
    # Ugly syntax but faster execution
    $dataJobFailed = foreach ( $_ in $dataJobListFailed ) {
        $ComputerName = ( $_.Name ).Substring($jobPrefix.Length)
        $PSComputerName = $_.location
        $_ | Select-Object -Property @{ LABEL = 'ComputerName' ; EXPRESSION = { $ComputerName }}, @{ LABEL = 'IP' ; EXPRESSION = { $PSComputerName }}, State
    }
    $dataJobFailed
    Write-Host "Failed jobs: $($dataJobListFailed.count)" -ForegroundColor Red
    $dataJobFailed | Export-Csv -LiteralPath $LogFailed -NoTypeInformation -Force
}

