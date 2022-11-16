# ***********************************************************************
# * All sample code is provided by OSIsoft for illustrative purposes only.
# * These examples have not been thoroughly tested under all conditions.
# * OSIsoft provides no guarantee nor implies any reliability, 
# * serviceability, or function of these programs.
# * ALL PROGRAMS CONTAINED HEREIN ARE PROVIDED TO YOU "AS IS" 
# * WITHOUT ANY WARRANTIES OF ANY KIND. ALL WARRANTIES INCLUDING 
# * THE IMPLIED WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY
# * AND FITNESS FOR A PARTICULAR PURPOSE ARE EXPRESSLY DISCLAIMED.
# ************************************************************************

param(
    [Parameter(Position = 0, Mandatory = $true, ParameterSetName = "reinit")]
    [switch] $Reinitialize,

    [Parameter(Position = 0, Mandatory = $true, ParameterSetName = "create")]
    [switch] $Create,

    [Parameter(Position = 1, Mandatory = $true, ParameterSetName = "create")]
    [string] $PICollectiveName,

    [Parameter(Position = 1, Mandatory = $true, ParameterSetName = "reinit")]
    [Parameter(Position = 2, Mandatory = $true, ParameterSetName = "create")]
    [string] $PIPrimaryName,

    [Parameter(Position = 2, Mandatory = $true, ParameterSetName = "reinit")]
    [Parameter(Position = 3, Mandatory = $true, ParameterSetName = "create")]
    [string[]] $PISecondaryNames,

    [Parameter(Position = 3, Mandatory = $true, ParameterSetName = "reinit")]
    [Parameter(Position = 4, Mandatory = $true, ParameterSetName = "create")]
    [Int32] $NumberOfArchivesToBackup,

    [Parameter(Position = 4, Mandatory = $true, ParameterSetName = "reinit")]
    [Parameter(Position = 5, Mandatory = $true, ParameterSetName = "create")]
    [string] $BackupLocationOnPrimary,

    [Parameter(Position = 5, Mandatory = $false, ParameterSetName = "reinit")]
    [Parameter(Position = 6, Mandatory = $false, ParameterSetName = "create")]
    [switch] $ExcludeFutureArchives
)

if ((Test-Path '.\SendPrimaryPublicCertToSecondaries.ps1') -eq $false) {
    Write-Error 'missing file: SendPrimaryPublicCertToSecondaries.ps1'
    return
}
if ((Test-Path '.\SendSecondaryPublicCertToPrimary.ps1') -eq $false) {
    Write-Error 'missing file: SendSecondaryPublicCertToPrimary.ps1'
    return
}
if ($Reinitialize -eq $true) {
    $activity = "Reinitalizing Collective from Primary " + $PIPrimaryName
}
else {
    $activity = "Creating Collective " + $PICollectiveName
}

$status = "Connecting to server " + $PIPrimaryName
Write-Progress -Activity $activity -Status $status

$connection = Connect-PIDataArchive -PIDataArchiveMachineName $PIPrimaryName -ErrorAction Stop

[Version] $v395 = "3.4.395"
[Version] $v410 = "3.4.410"
[String] $firstPathArchiveSet1;
$includeSet1 = $false
if ($ExcludeFutureArchives -eq $false -and
    $connection.ServerVersion -gt $v395) {
    Write-Progress -Activity $activity -Status "Getting primary archive"
    $archives = Get-PIArchiveInfo -ArchiveSet 0 -Connection $connection
    $primaryArchive = $archives.ArchiveFileInfo[0].Path

    try {
        $firstPathArchiveSet1 = (Get-PIArchiveInfo -ArchiveSet 1 -Connection $connection -ErrorAction SilentlyContinue).ArchiveFileInfo[0].Path
        if ($firstPathArchiveSet1 -eq $null) {
            # There are no future archives registered
            $includeSet1 = $false
        }
        else {
            # There is at least one future archive registered
            $includeSet1 = $true
        }
    }
    catch {
        $includeSet1 = $false
    }
}
else {
    Write-Progress -Activity $activity -Status "Getting primary archive"
    $archives = Get-PIArchiveInfo -Connection $connection
    $primaryArchive = $archives.ArchiveFileInfo[0].Path
}

if ($Reinitialize -eq $true) {
    ###########################################################
    # Verify connection is the primary member of a collective #
    ###########################################################
    if ($connection.CurrentRole.Type -ne "Primary") {
        Write-Host "Error:" $connection.Address.Host "is not the primary member of a collective."
        exit(-1)
    }

    ##############################################
    # Verify secondary names specified are valid #
    ##############################################
    Write-Progress -Activity $activity -Status "Verifying secondary is part of collective"
    $collectiveMembers = (Get-PICollective -Connection $connection).Members 

    foreach ($secondary in $PISecondaryNames) {
        [bool]$found = $false
        foreach ($member in $collectiveMembers) {
            if ($member.Role -eq "Secondary") {
                if ($member.Name -eq $secondary) {
                    $found = $true
                }
            }
        }

        if ($found -eq $false) {
            Write-Host "Error:" $secondary "is not a secondary node of collective" $connection.Name
            exit(-2)
        }
    }	
}
else {
    #####################################################################
    # Verify primary name specified is not already part of a collective #
    #####################################################################
    if ($connection.CurrentRole.Type -ne "Unspecified") {
        Write-Host "Error:" $PIPrimaryName "is already part of a collective."
        exit(-3)
    }
	
    ###########################################
    # Write collective information to primary #
    ###########################################

    Write-Progress -Activity $activity -Status "Writing collective information to primary"
    $collective = New-PICollective -Name $PICollectiveName -Secondaries $PISecondaryNames -Connection $connection
    ForEach ($secondary in $PISecondaryNames) {
        $path = (Connect-PIDataArchive $secondary | Get-PIDataArchiveDetails).Path
        if ($path -And ($path -contains '.') -And ([bool]($path -as [IPAddress] -eq 'false'))) {		
            $fqdn = $path
        }
        else {
            $wmiHost = Get-WmiObject win32_computersystem -ComputerName $secondary
            $fqdn = $wmiHost.DNSHostName + "." + $wmiHost.Domain
        }
        $collective | Set-PICollectiveMember -Name $secondary -Path $fqdn
    }
}

if ($connection.ServerVersion -ge $v410) {
    ###########################################################
    # Exchange public certificates between collective members #
    ###########################################################
    $storePath = 'OSIsoft LLC Certificates'
    .\SendPrimaryPublicCertToSecondaries.ps1 $PIPrimaryName $storePath $PISecondaryNames
    .\SendSecondaryPublicCertToPrimary.ps1 $PIPrimaryName $PISecondaryNames $storePath
}


####################################################
# Get the PI directory for each of the secondaries #
####################################################

$destinationPIPaths = @{}
foreach ($secondary in $PISecondaryNames) {
    $session = New-PSSession -ComputerName $secondary -ErrorAction Stop -WarningAction Stop
    $destinationPIPaths.Add($secondary, (Invoke-Command -Session $session -ScriptBlock { (Get-ItemProperty (Get-Item HKLM:\Software\PISystem\PI).PSPath).InstallationPath } ))
    Remove-PSSession -Id $session.ID
}

############################
# Stop all the secondaries #
############################

foreach ($secondary in $PISecondaryNames) {
    $status = "Stopping secondary node " + $secondary
    Write-Progress -Activity $activity -Status $status -CurrentOperation "Retrieving dependent services..."
    $pinetmgrService = Get-Service -Name "pinetmgr" -ComputerName $secondary
    $dependentServices = Get-Service -InputObject $pinetmgrService -DependentServices
    $index = 1
    foreach ($dependentService in $dependentServices) {
        if ($dependentService.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
            Write-Progress -Activity $activity -Status $status -CurrentOperation ("Stopping " + $dependentService.DisplayName) -PercentComplete (($index / ($dependentServices.Count + 1)) * 100)
            Stop-Service -InputObject $dependentService -Force -ErrorAction Stop -WarningAction SilentlyContinue
        }
        $index++
    }
    Write-Progress -Activity $activity -Status $status -CurrentOperation ("Stopping " + $pinetmgrService.Name) -PercentComplete 100
    Stop-Service -InputObject $pinetmgrService -Force -WarningAction SilentlyContinue -ErrorAction Sto
}

###########################
# Flush the archive cache #
###########################

Write-Progress -Activity $activity -Status ("Flushing archive cache on server " + $connection.Name)
Clear-PIArchiveQueue -Connection $connection

#########################
# Backup Primary Server #
#########################

$status = "Backing up PI Server " + $connection.Name
Write-Progress -Activity $activity -Status $status -CurrentOperation "Initializing..."
Start-PIBackup -Connection $connection -BackupLocation $BackupLocationOnPrimary -Exclude pimsgss, SettingsAndTimeoutParameters -ErrorAction Stop
$state = Get-PIBackupState -Connection $connection
while ($state.IsInProgress -eq $true) {
    [int32]$pc = [int32]$state.BackupProgress.OverallPercentComplete
    Write-Progress -Activity $activity -Status $status -CurrentOperation $state.CurrentBackupProgress.CurrentFile -PercentComplete $pc
    Start-Sleep -Milliseconds 500
    $state = Get-PIBackupState -Connection $connection
}

$backupInfo = Get-PIBackupReport -Connection $connection -LastReport

###################################################
# Create restore file for each of the secondaries #
###################################################

foreach ($secondary in $PISecondaryNames) {
    Write-Progress -Activity $activity -Status "Creating secondary restore files" -CurrentOperation $secondary
    $secondaryArchiveDirectory = Split-Path $primaryArchive
    if ($includeSet1 -eq $false) {
        New-PIBackupRestoreFile -Connection $connection -OutputDirectory ($BackupLocationOnPrimary + "\" + $secondary) -NumberOfArchives $NumberOfArchivesToBackup -HistoricalArchiveDirectory $secondaryArchiveDirectory
    }
    else {
        $secondaryArchiveSet1Directory = Split-Path $firstPathArchiveSet1
        $newArchiveDirectories = $secondaryArchiveDirectory, $secondaryArchiveSet1Directory
        New-PIBackupRestoreFile -Connection $connection -OutputDirectory ($BackupLocationOnPrimary + "\" + $secondary) -NumberOfArchives $NumberOfArchivesToBackup -ArchiveSetDirectories $newArchiveDirectories
    }
}

#################################
# Copy Backup to each secondary #
#################################

$backupLocationUNC = "\\" + $PIPrimaryName + "\" + $BackupLocationOnPrimary.SubString(0, 1) + "$" + $BackupLocationOnPrimary.Substring(2)

foreach ($item in $backupInfo.Files) {
    $totalSize += $item.Size
}

foreach ($secondary in $PISecondaryNames) {
    $destinationUNCPIRoot = "\\" + $secondary + "\" + $destinationPIPaths.$secondary.Substring(0, 1) + "$" + $destinationPIPaths.$secondary.Substring(2)

    $status = "Copying backup to secondary node"
    $currentSize = 0
    foreach ($file in $backupInfo.Files) {
        $currentSize += $file.Size
        Write-Progress -Activity $activity -Status $status -CurrentOperation $file.Name -PercentComplete (($currentSize / $totalSize) * 100)
        $sourceUNCFile = "\\" + $connection.Address.Host + "\" + $file.Destination.SubString(0, 1) + "$" + $file.Destination.Substring(2)
        if ($file.ComponentDescription.StartsWith("Archive") -eq $true) {
            $destinationFilePath = Split-Path $file.Destination
            if ($destinationFilePath.EndsWith("arcFuture") -eq $true) {
                $destinationUNCPath = "\\" + $secondary + "\" + $secondaryArchiveSet1Directory.Substring(0, 1) + "$" + $secondaryArchiveSet1Directory.Substring(2)
            }
            else {
                $destinationUNCPath = "\\" + $secondary + "\" + $secondaryArchiveDirectory.Substring(0, 1) + "$" + $secondaryArchiveDirectory.Substring(2)
            }
        }
        else {
            $destinationUNCPath = $destinationUNCPIRoot + (Split-Path $file.Destination).Replace($BackupLocationOnPrimary, "")
        }

        if ((Test-Path -Path $destinationUNCPath) -eq $false) {
            New-Item -Path $destinationUNCPath -ItemType Directory | Out-Null
        }

        Copy-Item -Path $sourceUNCFile -Destination $destinationUNCPath

        $index++
    }

    $piarstatUNC = $backupLocationUNC + "\" + $secondary
    Copy-Item -Path ($piarstatUNC + "\piarstat.dat") -Destination ($destinationUNCPIRoot + "\dat")
    # We only need this file for one server, it's ok to delete it now
    Remove-Item -Path ($piarstatUNC + "\piarstat.dat")
}

########################
# Cleanup backup files #
########################
Start-Sleep -Seconds 30
foreach ($file in $backupInfo.Files) {
    $sourceUNCFile = "\\" + $PIPrimaryName + "\" + $file.Destination.SubString(0, 1) + "$" + $file.Destination.Substring(2)
    Remove-Item -Path $sourceUNCFile
}

[Int32]$count = (Get-ChildItem $backupLocationUNC -Recurse | where {$_.psIsContainer -eq $false}).Count

if ($count -eq 0) {
    Write-Progress -Activity $activity -Status "Removing empty backup directories."
    Remove-Item -Path $backupLocationUNC -Recurse
}

#########################
# Start all secondaries #
#########################

[string[]] $piServices = "pinetmgr", "pimsgss", "pilicmgr", "piupdmgr", "pibasess", "pisnapss", "piarchss", "pibackup"

foreach ($secondary in $PISecondaryNames) {
    foreach ($service in $piServices) {
        $service = Get-Service -ComputerName $secondary -Name $service
        Write-Progress -Activity $activity -Status ("Starting secondary node " + $secondary) -CurrentOperation ("Starting " + $service.DisplayName)
        Start-Service -InputObject $service -WarningAction SilentlyContinue
    }
}
# SIG # Begin signature block
# MIIpTgYJKoZIhvcNAQcCoIIpPzCCKTsCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA/P20mGtMDGfCe
# /HhO7O6Br8Qm7VRDBaSHcKzT44JT6qCCDhkwggawMIIEmKADAgECAhAIrUCyYNKc
# TJ9ezam9k67ZMA0GCSqGSIb3DQEBDAUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNV
# BAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yMTA0MjkwMDAwMDBaFw0z
# NjA0MjgyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcg
# UlNBNDA5NiBTSEEzODQgMjAyMSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw
# ggIKAoICAQDVtC9C0CiteLdd1TlZG7GIQvUzjOs9gZdwxbvEhSYwn6SOaNhc9es0
# JAfhS0/TeEP0F9ce2vnS1WcaUk8OoVf8iJnBkcyBAz5NcCRks43iCH00fUyAVxJr
# Q5qZ8sU7H/Lvy0daE6ZMswEgJfMQ04uy+wjwiuCdCcBlp/qYgEk1hz1RGeiQIXhF
# LqGfLOEYwhrMxe6TSXBCMo/7xuoc82VokaJNTIIRSFJo3hC9FFdd6BgTZcV/sk+F
# LEikVoQ11vkunKoAFdE3/hoGlMJ8yOobMubKwvSnowMOdKWvObarYBLj6Na59zHh
# 3K3kGKDYwSNHR7OhD26jq22YBoMbt2pnLdK9RBqSEIGPsDsJ18ebMlrC/2pgVItJ
# wZPt4bRc4G/rJvmM1bL5OBDm6s6R9b7T+2+TYTRcvJNFKIM2KmYoX7BzzosmJQay
# g9Rc9hUZTO1i4F4z8ujo7AqnsAMrkbI2eb73rQgedaZlzLvjSFDzd5Ea/ttQokbI
# YViY9XwCFjyDKK05huzUtw1T0PhH5nUwjewwk3YUpltLXXRhTT8SkXbev1jLchAp
# QfDVxW0mdmgRQRNYmtwmKwH0iU1Z23jPgUo+QEdfyYFQc4UQIyFZYIpkVMHMIRro
# OBl8ZhzNeDhFMJlP/2NPTLuqDQhTQXxYPUez+rbsjDIJAsxsPAxWEQIDAQABo4IB
# WTCCAVUwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUaDfg67Y7+F8Rhvv+
# YXsIiGX0TkIwHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0P
# AQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMDMHcGCCsGAQUFBwEBBGswaTAk
# BggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAC
# hjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9v
# dEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAcBgNVHSAEFTATMAcGBWeBDAED
# MAgGBmeBDAEEATANBgkqhkiG9w0BAQwFAAOCAgEAOiNEPY0Idu6PvDqZ01bgAhql
# +Eg08yy25nRm95RysQDKr2wwJxMSnpBEn0v9nqN8JtU3vDpdSG2V1T9J9Ce7FoFF
# UP2cvbaF4HZ+N3HLIvdaqpDP9ZNq4+sg0dVQeYiaiorBtr2hSBh+3NiAGhEZGM1h
# mYFW9snjdufE5BtfQ/g+lP92OT2e1JnPSt0o618moZVYSNUa/tcnP/2Q0XaG3Ryw
# YFzzDaju4ImhvTnhOE7abrs2nfvlIVNaw8rpavGiPttDuDPITzgUkpn13c5Ubdld
# AhQfQDN8A+KVssIhdXNSy0bYxDQcoqVLjc1vdjcshT8azibpGL6QB7BDf5WIIIJw
# 8MzK7/0pNVwfiThV9zeKiwmhywvpMRr/LhlcOXHhvpynCgbWJme3kuZOX956rEnP
# LqR0kq3bPKSchh/jwVYbKyP/j7XqiHtwa+aguv06P0WmxOgWkVKLQcBIhEuWTatE
# QOON8BUozu3xGFYHKi8QxAwIZDwzj64ojDzLj4gLDb879M4ee47vtevLt/B3E+bn
# KD+sEq6lLyJsQfmCXBVmzGwOysWGw/YmMwwHS6DTBwJqakAwSEs0qFEgu60bhQji
# WQ1tygVQK+pKHJ6l/aCnHwZ05/LWUpD9r4VIIflXO7ScA+2GRfS0YW6/aOImYIbq
# yK+p/pQd52MbOoZWeE4wggdhMIIFSaADAgECAhAPU7nOpIHX2AURH287XM6zMA0G
# CSqGSIb3DQEBCwUAMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcg
# UlNBNDA5NiBTSEEzODQgMjAyMSBDQTEwHhcNMjIwNzEzMDAwMDAwWhcNMjMwODAy
# MjM1OTU5WjBmMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEUMBIG
# A1UEBxMLU2FuIExlYW5kcm8xFTATBgNVBAoTDE9TSXNvZnQsIExMQzEVMBMGA1UE
# AxMMT1NJc29mdCwgTExDMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA
# vvUpI/RMd0etxSSqHSbhyPm/7pRPL/f0i/x2olGznPFkzv/r0eI/ANvtWI8GSRuU
# U6HL/tExJrd3BYZNM+y78mZScEBACLWAsP6PrREOXPEb4WryIddu7PLVBlmkXRvO
# BFeiIkm/cQMZ5/2zBa3JM5Ox+W7wWxOqvU6TrHtWaG+E3bOppi5XnS3VC0IRfWDn
# gSzaSCIR8M7PQo9dnVclneqbjunk24Nc4nNgMsNclThLiX+8MlE2GwFw0z3aheQk
# wC9MuWuOrFeLbd8u45qJmXnGPFjsrB8T+1G8cs5A66f7jxW1/8A8L1hYlJ67D01u
# ySCao5nHXLyrGBScEvc0HLPHY2esOf9ZSKK76U52EcFkv8rexaxjiOeUqL1tTofy
# 0rmXvfjz7fVUB2XnLTKjbrf7CdwzK07ZifOlwvUhCDcoe5HatsuKBc4js695oGDm
# 7oeorEbDoEsn0JxEA+ZcmW7YE1/z1QCeua1caaj4WLUZdD/NctcYRXRC64WHOCnI
# 0mtxtIRAtnXdJkMG1v7T1OTrSQdpJa/DBhYfSnVMbQ0HBdwdPj5+7M/4vuNRY5PG
# 2s6sc/fNdOEcTwZpqd4oIgchwKXlz/D6l5Y/REOJvR7NtqiyCuGQPf0NoUkJB78M
# Cdi8JmM4FrUXJaPTWWqZFdHhi/1fvt+fzTnrMQ1Id/kCAwEAAaOCAgYwggICMB8G
# A1UdIwQYMBaAFGg34Ou2O/hfEYb7/mF7CIhl9E5CMB0GA1UdDgQWBBS0iFWmypnR
# uL0Z6XGSDXm8oY6WujAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUH
# AwMwgbUGA1UdHwSBrTCBqjBToFGgT4ZNaHR0cDovL2NybDMuZGlnaWNlcnQuY29t
# L0RpZ2lDZXJ0VHJ1c3RlZEc0Q29kZVNpZ25pbmdSU0E0MDk2U0hBMzg0MjAyMUNB
# MS5jcmwwU6BRoE+GTWh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRy
# dXN0ZWRHNENvZGVTaWduaW5nUlNBNDA5NlNIQTM4NDIwMjFDQTEuY3JsMD4GA1Ud
# IAQ3MDUwMwYGZ4EMAQQBMCkwJwYIKwYBBQUHAgEWG2h0dHA6Ly93d3cuZGlnaWNl
# cnQuY29tL0NQUzCBlAYIKwYBBQUHAQEEgYcwgYQwJAYIKwYBBQUHMAGGGGh0dHA6
# Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBcBggrBgEFBQcwAoZQaHR0cDovL2NhY2VydHMu
# ZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0Q29kZVNpZ25pbmdSU0E0MDk2
# U0hBMzg0MjAyMUNBMS5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOC
# AgEAvG+uJmPKqu+YBqcbyR2BmGDSiiU+510qD7BlxTpA7LgvQOEfszG2LPhk8uoI
# /QTm2SR+EKm21HYfoJd50wDNSVk1gDhYBi78HTk8e0TuhgcC+C6nQlygGXLYNuQu
# sfyEofV99OZcjrzJ3bl2th2EkCQHD6BBCuZlsXZlOF1HYXeyNf+FLzqC1E8BtV+k
# fCMi8cbwLpr+ZitY6wrE5Rnnd5jWhu9af1mm8UWcnt9yef67N6bCrNZFjy3zf5bS
# Vo7yIZb88Tsw2xbqAnWkBDvFhaCsEqXktbjQQydRIGrImpY7URvvXNSN8/V+bp1/
# PJwOOm4iq/d+jjrFJxpNIgDGjXx5YU9DtJk7o6zmVO0KidfHb578YxL3Ugj+I9ds
# oykeKKsnb/4EdnvHKyzv45bpZ3HI96q7+rx0N5Q9HDBR6XVTopJFB01t00nKyxTB
# 3Kq8TX5Qb+8omlrG3XEou6QqsmizfecHcpHxQh2hNtnamfAj253+joKES3kQWch/
# 9lDET0f5+ZvB7eERRhOFQcazv/J4Bl4yvPfPcJVeq0q12lkulHiOGACu1JoCDAIB
# YyqAuh1xmfV/za/aVYnh2GkbHqTEH4U+jkkyTzo/lftxzh8zkOwZGmK8hG2oLlKk
# 3gbIhtAHY4vZjeP6cJwRNpxg12nbe25nQ6vuvIsuJ6eS59QxghqLMIIahwIBATB9
# MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UE
# AxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcgUlNBNDA5NiBTSEEz
# ODQgMjAyMSBDQTECEA9Tuc6kgdfYBREfbztczrMwDQYJYIZIAWUDBAIBBQCggZ4w
# GQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisG
# AQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEINyjM5RUZBpFRBF26IYV3K1LeKGwezxu
# jFrWTYSQG02hMDIGCisGAQQBgjcCAQwxJDAioSCAHmh0dHA6Ly90ZWNoc3VwcG9y
# dC5vc2lzb2Z0LmNvbTANBgkqhkiG9w0BAQEFAASCAgA4TCFHHfGZOeOQEdh8KAxs
# TEUEdVNYnxE4nQ619cEwHrKc98azoA1jSCuu4WbElcQvXeWFgVn+vB8VMIzAa7O9
# FKPtOO4rqYtkNmjP1RNxqyfWjHGq+YYjlgGDpfMbhTM9S4hQiVNnTjREcevGpR9v
# XHA9INsfGa6W0EG/lRyLhi+2XnoDy0laBcQQgqTDWnbnr4Vd2T7lPyqmsxVv7P/V
# 9K1rghKUdRnaAqLcvLLefp0cTI0fcQxPrqzodwDO2k1nEkSvL8TxCm4sL1h0Y64P
# bma4wK5vsOgJCjVVmd0vtsOnkp3oABDZ++oOZ/dEXumMhWMI2fC4+m0gXs6YLmaD
# 6CFOwjFZ6xpDBkm9GShaz6FT/4k6i/+XjhwM5kg1aMC0FktlvfV8FyMzhDO1w8qo
# U0bS1ivDNdBpJQfSdFey9QcNwBaoDyDySkyBnBEu8piYwZor7xobpWj66G56EjCP
# BRnuYkGsvBF2Cvk4eAxmmi8lXS5bPfg77k5TrqfwyNPNhv6k9hs59GDxf6/FhBoX
# dYW/uZWK2Vb/gy+a69xJyH6sewxqxJPmK3vraIRCamDVgclZKsu9I75nfV7LRXAi
# Zbn5KIuMlp1XuiM6RGmd2sLjPnaAeWWnmKGO/hLOCe1OuyV+6cGd6nmeOpjejdqJ
# yhjl6hKzo8R1sXaZsFwaoqGCFz4wghc6BgorBgEEAYI3AwMBMYIXKjCCFyYGCSqG
# SIb3DQEHAqCCFxcwghcTAgEDMQ8wDQYJYIZIAWUDBAIBBQAweAYLKoZIhvcNAQkQ
# AQSgaQRnMGUCAQEGCWCGSAGG/WwHATAxMA0GCWCGSAFlAwQCAQUABCAq48IDmqtz
# asN9sWmRMf5TT3P16AiM3T84A5Jrwtzp2gIRALE/0Tw53gG5ldADcnf45K0YDzIw
# MjIxMDI3MDEyNzA3WqCCEwcwggbAMIIEqKADAgECAhAMTWlyS5T6PCpKPSkHgD1a
# MA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2Vy
# dCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNI
# QTI1NiBUaW1lU3RhbXBpbmcgQ0EwHhcNMjIwOTIxMDAwMDAwWhcNMzMxMTIxMjM1
# OTU5WjBGMQswCQYDVQQGEwJVUzERMA8GA1UEChMIRGlnaUNlcnQxJDAiBgNVBAMT
# G0RpZ2lDZXJ0IFRpbWVzdGFtcCAyMDIyIC0gMjCCAiIwDQYJKoZIhvcNAQEBBQAD
# ggIPADCCAgoCggIBAM/spSY6xqnya7uNwQ2a26HoFIV0MxomrNAcVR4eNm28klUM
# YfSdCXc9FZYIL2tkpP0GgxbXkZI4HDEClvtysZc6Va8z7GGK6aYo25BjXL2JU+A6
# LYyHQq4mpOS7eHi5ehbhVsbAumRTuyoW51BIu4hpDIjG8b7gL307scpTjUCDHufL
# ckkoHkyAHoVW54Xt8mG8qjoHffarbuVm3eJc9S/tjdRNlYRo44DLannR0hCRRinr
# PibytIzNTLlmyLuqUDgN5YyUXRlav/V7QG5vFqianJVHhoV5PgxeZowaCiS+nKrS
# nLb3T254xCg/oxwPUAY3ugjZNaa1Htp4WB056PhMkRCWfk3h3cKtpX74LRsf7CtG
# GKMZ9jn39cFPcS6JAxGiS7uYv/pP5Hs27wZE5FX/NurlfDHn88JSxOYWe1p+pSVz
# 28BqmSEtY+VZ9U0vkB8nt9KrFOU4ZodRCGv7U0M50GT6Vs/g9ArmFG1keLuY/ZTD
# cyHzL8IuINeBrNPxB9ThvdldS24xlCmL5kGkZZTAWOXlLimQprdhZPrZIGwYUWC6
# poEPCSVT8b876asHDmoHOWIZydaFfxPZjXnPYsXs4Xu5zGcTB5rBeO3GiMiwbjJ5
# xwtZg43G7vUsfHuOy2SJ8bHEuOdTXl9V0n0ZKVkDTvpd6kVzHIR+187i1Dp3AgMB
# AAGjggGLMIIBhzAOBgNVHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADAWBgNVHSUB
# Af8EDDAKBggrBgEFBQcDCDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1s
# BwEwHwYDVR0jBBgwFoAUuhbZbU2FL3MpdpovdYxqII+eyG8wHQYDVR0OBBYEFGKK
# 3tBh/I8xFO2XC809KpQU31KcMFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwz
# LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFJTQTQwOTZTSEEyNTZUaW1l
# U3RhbXBpbmdDQS5jcmwwgZAGCCsGAQUFBwEBBIGDMIGAMCQGCCsGAQUFBzABhhho
# dHRwOi8vb2NzcC5kaWdpY2VydC5jb20wWAYIKwYBBQUHMAKGTGh0dHA6Ly9jYWNl
# cnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFJTQTQwOTZTSEEyNTZU
# aW1lU3RhbXBpbmdDQS5jcnQwDQYJKoZIhvcNAQELBQADggIBAFWqKhrzRvN4Vzcw
# /HXjT9aFI/H8+ZU5myXm93KKmMN31GT8Ffs2wklRLHiIY1UJRjkA/GnUypsp+6M/
# wMkAmxMdsJiJ3HjyzXyFzVOdr2LiYWajFCpFh0qYQitQ/Bu1nggwCfrkLdcJiXn5
# CeaIzn0buGqim8FTYAnoo7id160fHLjsmEHw9g6A++T/350Qp+sAul9Kjxo6UrTq
# vwlJFTU2WZoPVNKyG39+XgmtdlSKdG3K0gVnK3br/5iyJpU4GYhEFOUKWaJr5yI+
# RCHSPxzAm+18SLLYkgyRTzxmlK9dAlPrnuKe5NMfhgFknADC6Vp0dQ094XmIvxwB
# l8kZI4DXNlpflhaxYwzGRkA7zl011Fk+Q5oYrsPJy8P7mxNfarXH4PMFw1nfJ2Ir
# 3kHJU7n/NBBn9iYymHv+XEKUgZSCnawKi8ZLFUrTmJBFYDOA4CPe+AOk9kVH5c64
# A0JH6EE2cXet/aLol3ROLtoeHYxayB6a1cLwxiKoT5u92ByaUcQvmvZfpyeXupYu
# hVfAYOd4Vn9q78KVmksRAsiCnMkaBXy6cbVOepls9Oie1FqYyJ+/jbsYXEP10Cro
# 4mLueATbvdH7WwqocH7wl4R44wgDXUcsY6glOJcB0j862uXl9uab3H4szP8XTE0A
# otjWAQ64i+7m4HJViSwnGWH2dwGMMIIGrjCCBJagAwIBAgIQBzY3tyRUfNhHrP0o
# ZipeWzANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGln
# aUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhE
# aWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwHhcNMjIwMzIzMDAwMDAwWhcNMzcwMzIy
# MjM1OTU5WjBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4x
# OzA5BgNVBAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGlt
# ZVN0YW1waW5nIENBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAxoY1
# BkmzwT1ySVFVxyUDxPKRN6mXUaHW0oPRnkyibaCwzIP5WvYRoUQVQl+kiPNo+n3z
# nIkLf50fng8zH1ATCyZzlm34V6gCff1DtITaEfFzsbPuK4CEiiIY3+vaPcQXf6sZ
# Kz5C3GeO6lE98NZW1OcoLevTsbV15x8GZY2UKdPZ7Gnf2ZCHRgB720RBidx8ald6
# 8Dd5n12sy+iEZLRS8nZH92GDGd1ftFQLIWhuNyG7QKxfst5Kfc71ORJn7w6lY2zk
# psUdzTYNXNXmG6jBZHRAp8ByxbpOH7G1WE15/tePc5OsLDnipUjW8LAxE6lXKZYn
# LvWHpo9OdhVVJnCYJn+gGkcgQ+NDY4B7dW4nJZCYOjgRs/b2nuY7W+yB3iIU2YIq
# x5K/oN7jPqJz+ucfWmyU8lKVEStYdEAoq3NDzt9KoRxrOMUp88qqlnNCaJ+2RrOd
# OqPVA+C/8KI8ykLcGEh/FDTP0kyr75s9/g64ZCr6dSgkQe1CvwWcZklSUPRR8zZJ
# TYsg0ixXNXkrqPNFYLwjjVj33GHek/45wPmyMKVM1+mYSlg+0wOI/rOP015LdhJR
# k8mMDDtbiiKowSYI+RQQEgN9XyO7ZONj4KbhPvbCdLI/Hgl27KtdRnXiYKNYCQEo
# AA6EVO7O6V3IXjASvUaetdN2udIOa5kM0jO0zbECAwEAAaOCAV0wggFZMBIGA1Ud
# EwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFLoW2W1NhS9zKXaaL3WMaiCPnshvMB8G
# A1UdIwQYMBaAFOzX44LScV1kTN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIBhjAT
# BgNVHSUEDDAKBggrBgEFBQcDCDB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGG
# GGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDovL2Nh
# Y2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYD
# VR0fBDwwOjA4oDagNIYyaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0
# VHJ1c3RlZFJvb3RHNC5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9
# bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQB9WY7Ak7ZvmKlEIgF+ZtbYIULhsBguEE0T
# zzBTzr8Y+8dQXeJLKftwig2qKWn8acHPHQfpPmDI2AvlXFvXbYf6hCAlNDFnzbYS
# lm/EUExiHQwIgqgWvalWzxVzjQEiJc6VaT9Hd/tydBTX/6tPiix6q4XNQ1/tYLaq
# T5Fmniye4Iqs5f2MvGQmh2ySvZ180HAKfO+ovHVPulr3qRCyXen/KFSJ8NWKcXZl
# 2szwcqMj+sAngkSumScbqyQeJsG33irr9p6xeZmBo1aGqwpFyd/EjaDnmPv7pp1y
# r8THwcFqcdnGE4AJxLafzYeHJLtPo0m5d2aR8XKc6UsCUqc3fpNTrDsdCEkPlM05
# et3/JWOZJyw9P2un8WbDQc1PtkCbISFA0LcTJM3cHXg65J6t5TRxktcma+Q4c6um
# AU+9Pzt4rUyt+8SVe+0KXzM5h0F4ejjpnOHdI/0dKNPH+ejxmF/7K9h+8kaddSwe
# Jywm228Vex4Ziza4k9Tm8heZWcpw8De/mADfIBZPJ/tgZxahZrrdVcA6KYawmKAr
# 7ZVBtzrVFZgxtGIJDwq9gdkT/r+k0fNX2bwE+oLeMt8EifAAzV3C+dAjfwAL5HYC
# JtnwZXZCpimHCUcr5n8apIUP/JiW9lVUKx+A+sDyDivl1vupL0QVSucTDh3bNzga
# oSv27dZ8/DCCBY0wggR1oAMCAQICEA6bGI750C3n79tQ4ghAGFowDQYJKoZIhvcN
# AQEMBQAwZTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcG
# A1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEkMCIGA1UEAxMbRGlnaUNlcnQgQXNzdXJl
# ZCBJRCBSb290IENBMB4XDTIyMDgwMTAwMDAwMFoXDTMxMTEwOTIzNTk1OVowYjEL
# MAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3
# LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAv+aQc2jeu+RdSjwwIjBp
# M+zCpyUuySE98orYWcLhKac9WKt2ms2uexuEDcQwH/MbpDgW61bGl20dq7J58soR
# 0uRf1gU8Ug9SH8aeFaV+vp+pVxZZVXKvaJNwwrK6dZlqczKU0RBEEC7fgvMHhOZ0
# O21x4i0MG+4g1ckgHWMpLc7sXk7Ik/ghYZs06wXGXuxbGrzryc/NrDRAX7F6Zu53
# yEioZldXn1RYjgwrt0+nMNlW7sp7XeOtyU9e5TXnMcvak17cjo+A2raRmECQecN4
# x7axxLVqGDgDEI3Y1DekLgV9iPWCPhCRcKtVgkEy19sEcypukQF8IUzUvK4bA3Vd
# eGbZOjFEmjNAvwjXWkmkwuapoGfdpCe8oU85tRFYF/ckXEaPZPfBaYh2mHY9WV1C
# doeJl2l6SPDgohIbZpp0yt5LHucOY67m1O+SkjqePdwA5EUlibaaRBkrfsCUtNJh
# besz2cXfSwQAzH0clcOP9yGyshG3u3/y1YxwLEFgqrFjGESVGnZifvaAsPvoZKYz
# 0YkH4b235kOkGLimdwHhD5QMIR2yVCkliWzlDlJRR3S+Jqy2QXXeeqxfjT/JvNNB
# ERJb5RBQ6zHFynIWIgnffEx1P2PsIV/EIFFrb7GrhotPwtZFX50g/KEexcCPorF+
# CiaZ9eRpL5gdLfXZqbId5RsCAwEAAaOCATowggE2MA8GA1UdEwEB/wQFMAMBAf8w
# HQYDVR0OBBYEFOzX44LScV1kTN8uZz/nupiuHA9PMB8GA1UdIwQYMBaAFEXroq/0
# ksuCMS1Ri6enIZ3zbcgPMA4GA1UdDwEB/wQEAwIBhjB5BggrBgEFBQcBAQRtMGsw
# JAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBDBggrBgEFBQcw
# AoY3aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElE
# Um9vdENBLmNydDBFBgNVHR8EPjA8MDqgOKA2hjRodHRwOi8vY3JsMy5kaWdpY2Vy
# dC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3JsMBEGA1UdIAQKMAgwBgYE
# VR0gADANBgkqhkiG9w0BAQwFAAOCAQEAcKC/Q1xV5zhfoKN0Gz22Ftf3v1cHvZqs
# oYcs7IVeqRq7IviHGmlUIu2kiHdtvRoU9BNKei8ttzjv9P+Aufih9/Jy3iS8UgPI
# TtAq3votVs/59PesMHqai7Je1M/RQ0SbQyHrlnKhSLSZy51PpwYDE3cnRNTnf+hZ
# qPC/Lwum6fI0POz3A8eHqNJMQBk1RmppVLC4oVaO7KTVPeix3P0c2PR3WlxUjG/v
# oVA9/HYJaISfb8rbII01YBwCA8sgsKxYoA5AY8WYIsGyWfVVa88nq2x2zm8jLfR+
# cWojayL/ErhULSd+2DrZ8LaHlv1b0VysGMNNn3O3AamfV6peKOK5lDGCA3YwggNy
# AgEBMHcwYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTsw
# OQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVT
# dGFtcGluZyBDQQIQDE1pckuU+jwqSj0pB4A9WjANBglghkgBZQMEAgEFAKCB0TAa
# BgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwHAYJKoZIhvcNAQkFMQ8XDTIyMTAy
# NzAxMjcwN1owKwYLKoZIhvcNAQkQAgwxHDAaMBgwFgQU84ciTYYzgpI1qZS8vY+W
# 6f4cfHMwLwYJKoZIhvcNAQkEMSIEIERhEShdLd67DMTv14LJGumLyql1dOkJJlfo
# +zsK/QI8MDcGCyqGSIb3DQEJEAIvMSgwJjAkMCIEIMf04b4yKIkgq+ImOr4axPxP
# 5ngcLWTQTIB1V6Ajtbb6MA0GCSqGSIb3DQEBAQUABIICAKOqG4MglOr05jGInWBN
# iXPCf3YQ1dGqjfxsRbmeS/6alXqo25E2FGGmeC/XmR3yPeVXSwRIwq/UbrneoiOB
# EyvJUrFgY/Ymh+TwBqFsifQeixJzBgr7aadoPu2t4YGP0DMZ/5zo99T8mlm4PnY8
# KRITxKTEZPUOC80fNttuDqaxqnH8YDp0hr9K3BVBQxvVeV4idfrG06kYpUvdzybm
# EBfk/Jxy359NZCk6Fa4DmW+dBDBdSfhoVzT5v5cFsfwM1JvAUok2n/9aPP8Ko9lS
# bL4ZsO0yGchu3vNt2Dffwzi/tBBWwqeWYReQTImbpL8WBONiH2iKvTCrU6Tq1ESY
# SADWUbYKVm2t6v/ud0acjLgSnY3EMQeAzeaau75xaLPdowQN9VmLSyysQHP6sySL
# HQ0iu+nKTP0y0Z7ggQ5AHA2VvfZVF1aWql+j7eueqyZe/kU8K50TgN4M9ItImIFv
# xW7x23gm3hdPZj1kVIJ/5MiCz0727ZzfIBM6IA83kECJpJtnPj0r6GbkWiK4Vhb4
# 1nnJ96MQmg+rWsOdKktQz/aaNGgdu2hi8x8S7GiFBXxYLJU3lHfoJPdScnyoosNC
# 6jalxs+v524n/mhDi47KTyCibdOduEH5LXqJK4/La32JdW9rGjHoNZbMfI0/MSDO
# HMQousLESE3MNNOLzZQXypY+
# SIG # End signature block
