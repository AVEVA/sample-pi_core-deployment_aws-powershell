﻿[CmdletBinding()]
param(
    # Domain Net BIOS Name, e.g. 'mypi'.
    [Parameter(Mandatory)]
    [ValidateNotNullorEmpty()]
    [string]$DomainNetBiosName,

    # "Fully qualified domain name (FQDN) of the forest root domain e.g. mypi.int"
    [Parameter(Mandatory)]
    [ValidateNotNullorEmpty()]
    [String]$DomainDNSName,

    # Username of domain admin account. Also the AWS SSM Parameter Store parameter name. Used to retrieve the account password.
    [Parameter(Mandatory)]
    [ValidateNotNullorEmpty()]
    [string]$DomainAdminUserName,
    
    # AF Server service account name. Also the AWS SSM Parameter Store parameter name. Used to retrieve the account password.
    [Parameter(Mandatory)]
    [ValidateNotNullorEmpty()]
    [String]$PIAFServiceAccountName,

    # Default PI Data Archive
    [Parameter(Mandatory)]
    [ValidateNotNullorEmpty()]
    [String]$DefaultPIDataArchive,

    # Setup Kit PI Installer Product ID
    [Parameter(Mandatory)]
    [ValidateNotNullorEmpty()]
    [String]$SetupKitsS3PIProductID,

    # Default AF Server
    [Parameter()]
    [ValidateNotNullorEmpty()]
    [String]$DefaultPIAFServer = $env:COMPUTERNAME,

    # Name used to identify AF load balanced endpoint for HA deployments. Used to create DNS CName record.
    [Parameter(Mandatory)]
    [ValidateNotNullorEmpty()]
    [String]$AFLoadBalancedName = 'PIAF',

    # SQL Server to install PIFD database. This should be the primary SQL server hostname.
    [Parameter(Mandatory)]
    [ValidateNotNullorEmpty()]
    [String]$DefaultSqlServer,

    # SQL Server Always On Listener.
    [Parameter()]
    [ValidateNotNullorEmpty()]
    [String]$SqlServerAOListener = 'AG0-Listener',

    # Primary domain controller targeted for service account creation.
    [Parameter(Mandatory)]
    [ValidateNotNullorEmpty()]
    [String]$PrimaryDomainController,

    # DNS record of internal Elastic Load Balancer. Used for AF HA endpoint.
    [Parameter()]
    $ElasticLoadBalancerDnsRecord,

    # Name Prefix for the stack resource tagging.
    [Parameter(Mandatory)]
    [ValidateNotNullorEmpty()]
    [String]$NamePrefix
)


try {
    # Set to enable catch to Write-AWSQuickStartException
    $ErrorActionPreference = "Stop"

    Import-Module $psscriptroot\IPHelper.psm1
    Import-Module SqlServer -RequiredVersion 21.1.18218

    # Set Local Configuration Manager
    Configuration LCMConfig {
        LocalConfigurationManager {
            RebootNodeIfNeeded = $true
            ActionAfterReboot  = 'ContinueConfiguration'
            ConfigurationMode  = 'ApplyOnly'
            CertificateID      = (Get-ChildItem Cert:\LocalMachine\My)[0].Thumbprint
        }
    }

    LCMConfig
    Set-DscLocalConfigurationManager -Path .\LCMConfig


    # Set Configuration Data. Certificate used for credential encryption.
    $ConfigurationData = @{
        AllNodes = @(
            @{
                NodeName             = $env:COMPUTERNAME
                CertificateFile      = 'C:\dsc.cer'
                PSDscAllowDomainUser = $true
            }
        )
    }

    # Get exisitng service account password from AWS System Manager Parameter Store.
    $DomainAdminPassword =  (Get-SSMParameterValue -Name "/$NamePrefix/$DomainAdminUserName" -WithDecryption $True).Parameters[0].Value
	$PIAFServiceAccountPassword =  (Get-SSMParameterValue -Name "/$NamePrefix/$PIAFServiceAccountName" -WithDecryption $True).Parameters[0].Value

    # Generate credential object for domain admin account.
    $secureDomainAdminPassword = ConvertTo-SecureString $DomainAdminPassword -AsPlainText -Force
    $domainCredential = New-Object System.Management.Automation.PSCredential -ArgumentList ("$DomainNetBiosName\$DomainAdminUserName", $secureDomainAdminPassword)


    # EC2 Configuration
    Configuration PIAF0Config {

        param(
            # PI AF Server Install settings
            [string]$afServer = $env:COMPUTERNAME,
            [string]$piServer = $DefaultPIDataArchive,
            [string]$PIHOME = 'F:\Program Files (x86)\PIPC',
            [string]$PIHOME64 = 'F:\Program Files\PIPC',
            [string]$PI_INSTALLDIR = 'F:\PI',
            [string]$PIAFSvcAccountUsername = $PIAFServiceAccountName,
            [string]$PIAFSvcAccountPassword = $PIAFServiceAccountPassword,
            [string]$PIAFSqlDB = "PIFD"
        )

        Import-DscResource -ModuleName PSDesiredStateConfiguration
        Import-DscResource -ModuleName xStorage -ModuleVersion 3.4.0.0
        Import-DscResource -ModuleName xNetworking -ModuleVersion 5.7.0.0
        Import-DscResource -ModuleName xPendingReboot -ModuleVersion 0.4.0.0
        Import-DscResource -ModuleName xActiveDirectory -ModuleVersion 3.0.0.0
        Import-DscResource -ModuleName xDnsServer -ModuleVersion 1.15.0.0
        Import-DscResource -ModuleName SqlServerDsc -ModuleVersion 13.2.0.0
        Import-DscResource -ModuleName xWindowsUpdate

        # Generate credential for AF Server service account.
        $securePIAFServiceAccountPassword = ConvertTo-SecureString $PIAFSvcAccountPassword -AsPlainText -Force
        $domainServiceAccountCredential = New-Object System.Management.Automation.PSCredential -ArgumentList ("$DomainNetBiosName\$PIAFSvcAccountUsername", $securePIAFServiceAccountPassword)

        # Under HA deployment scenarios, substitute the primary SQL Server hostname for the SQL Always On Listener Name.
        # This is used in the installation arguments for PI AF. This value gets configured in the AFService.exe.config specifying which SQL instance to connect to.
        if ($ElasticLoadBalancerDnsRecord) {
            Write-Verbose -Message "HA deployment detected. PIAF install will use the following SQL target: $SqlServerAOListener" -Verbose
            $FDSQLDBSERVER = $SqlServerAOListener
        }
        else {
            Write-Verbose -Message "Single instance deployment detected. PIAF install will use the following SQL target: $DefaultSqlServer" -Verbose
            $FDSQLDBSERVER = $DefaultSqlServer
        }

        Node $env:COMPUTERNAME {

            #region ### 1. VM PREPARATION ### 
            # 1A. Check for new volumes. The uninitialized disk number may vary depending on EC2 type (i.e. temp disk or no temp disk). This logic will test to find the disk number of an uninitialized disk.
            $disks = Get-Disk | Where-Object 'partitionstyle' -eq 'raw' | Sort-Object number
            if ($disks) {
                # Elastic Block Storage for Binary Files
                xWaitforDisk Volume_F {
                    DiskID           = $disks[0].number
                    retryIntervalSec = 30
                    retryCount       = 20
                }
                xDisk Volume_F {
                    DiskID      = $disks[0].number
                    DriveLetter = 'F'
                    FSFormat    = 'NTFS'
                    FSLabel     = 'Apps'
                    DependsOn   = '[xWaitforDisk]Volume_F'
                }
            }

            # 1B. Create Rules to open PI AF Ports
            xFirewall PIAFSDKClientFirewallRule {
                Direction   = 'Inbound'
                Name        = 'PI-System-PI-AFSDK-Client-TCP-In'
                DisplayName = 'PI System PI AFSDK Client (TCP-In)'
                Description = 'Inbound rule for PI AFSDK to allow TCP traffic for access to the AF Server.'
                Group       = 'PI Systems'
                Enabled     = 'True'
                Action      = 'Allow'
                Protocol    = 'TCP'
                LocalPort   = '5457'
                Ensure      = 'Present'
            }

            xFirewall PISQLClientFirewallRule {
                Direction   = 'Inbound'
                Name        = 'PI-System-PI-SQL-Client-TCP-In'
                DisplayName = 'PI System PI SQL AF Client (TCP-In)'
                Description = 'Inbound rule for PI SQL for AF Clients to allow TCP traffic for access to the AF Server.'
                Group       = 'PI Systems'
                Enabled     = 'True'
                Action      = 'Allow'
                Protocol    = 'TCP'
                LocalPort   = '5459'
                Ensure      = 'Present'
            }
            #endregion ### 1. VM PREPARATION ###


            #region ### 2. INSTALL AND SETUP ###
            # 2A i. Used for PI AF Service account creation.
            WindowsFeature ADPS {
                Name   = 'RSAT-AD-PowerShell'
                Ensure = 'Present'
            }

            xADUser ServiceAccount_PIAF {
                DomainName                    = $DomainNetBiosName
                UserName                      = $PIAFSvcAccountUsername
                CannotChangePassword          = $true
                Description                   = 'PI AF Server service account.'
                DomainAdministratorCredential = $domainCredential
                Enabled                       = $true
                Ensure                        = 'Present'
                Password                      = $domainServiceAccountCredential
                DomainController              = $PrimaryDomainController
                DependsOn                     = '[WindowsFeature]ADPS'
            }

            # 2A ii - To have the PI AF SQL Database work with SQL Always On, we use a domain group "AFSERVERS" instead of a local group.
            # This requires a modification to the AF Server install scripts per documentation: 
            # This maps the SQL User 'AFServers' maps to this domain group instead of the local group, providing security mapping consistency across SQL nodes.
            xADGroup CreateAFServersGroup {
                GroupName        = 'AFServers'
                Description      = 'Service Accounts with Access to PIFD databases'
                Category         = 'Security'
                Ensure           = 'Present'
                GroupScope       = 'Global'
                MembersToInclude = $PIAFSvcAccountUsername
                Credential       = $domainCredential
                DomainController = $PrimaryDomainController
                DependsOn        = '[WindowsFeature]ADPS'
            }

            # If a load balancer DNS record is passed, then this will generate a DNS CName. This entry is used as the AF Server load balanced endpoint.
            if ($ElasticLoadBalancerDnsRecord) {
                # Tools needed to write DNS Records
                WindowsFeature DNSTools {
                    Name   = 'RSAT-DNS-Server'
                    Ensure = 'Present'
                }

                # Adds a CName DSN record used to point to internal Elastic Load Balancer DNS record
                xDnsRecord AFLoadBanacedEndPoint {
                    Name                 = 'PIAF'
                    Target               = $ElasticLoadBalancerDnsRecord
                    Type                 = 'CName'
                    Zone                 = $DomainDNSName
                    DependsOn            = '[WindowsFeature]DnsTools'
                    DnsServer            = $PrimaryDomainController
                    Ensure               = 'Present'
                    PsDscRunAsCredential = $domainCredential
                }
            }

            #2B. Install .NET Framework 4.8
            xHotFix NETFramework {
                Path = 'C:\media\NETFramework\windows10.0-kb4486129.msu'
                Id = 'KB4486129'
                Ensure = 'Present'
            }
            
            # 2C. Initiate any outstanding reboots.
            xPendingReboot RebootNETFramework {
                Name      = 'PostNETFrameworkInstall'
                DependsOn = '[xHotFix]NETFramework'
            }

            #2D. Install PI AF Server with Client Tools
            Package PISystem {
                Name                 = 'PI Server 2018 Installer'
                Path                 = 'C:\media\PIServer\PIServerInstaller.exe'
                ProductId            = $SetupKitsS3PIProductID
                Arguments            = "/silent ADDLOCAL=FD_SQLServer,FD_SQLScriptExecution,FD_AppsServer,FD_AFExplorer,FD_AFAnalysisMgmt,FD_AFDocs,PiPowerShell PIHOME=""$PIHOME"" PIHOME64=""$PIHOME64"" AFSERVER=""$afServer"" PISERVER=""$piServer"" SENDTELEMETRY=""0"" AFSERVICEACCOUNT=""$DomainNetBiosName\$PIAFSvcAccountUsername"" AFSERVICEPASSWORD=""$PIAFServiceAccountPassword"" FDSQLDBNAME=""PIFD"" FDSQLDBSERVER=""$FDSQLDBSERVER"" AFACKNOWLEDGEBACKUP=""1"" PI_ARCHIVESIZE=""1024"""
                Ensure               = 'Present'
                LogPath              = "$env:ProgramData\PISystem_install.log"
                PsDscRunAsCredential = $domainCredential   # Cred with access to SQL. Necessary for PIFD database install.
                ReturnCode           = 0, 3010
                DependsOn            = '[xHotFix]NETFramework', '[xPendingReboot]RebootNETFramework'
            }

            # This updates the AFSerers user in SQL from a local group to the domain group
            Script UpdateAFServersUser {
                GetScript            = {
                    return @{
                        'Resource' = 'UpdateAFServersUser'
                    }
                }

                # Forces SetScript execution everytime
                TestScript           = {
                    return $false
                }

                SetScript            = {
                    Write-Verbose -Message "Setting Server account to remove for existing AFServers role: ""serverAccount=$using:DefaultSqlServer\AFServers"""
                    Write-Verbose -Message "Setting Domain account to set for AFServers role:             ""domainAccount=[$using:DomainNetBIOSName\AFServers]"""

                    # Arguments to pass as a variable to SQL script. These are the account to remove and the one to update with.
                    $accounts = "domainAccount=[$using:DomainNetBIOSName\AFServers]", "serverAccount=$using:DefaultSqlServer\AFServers"
                    
                    Write-Verbose -Message "Executing SQL command to invoke script 'c:\media\PIAF\UpdateAFServersUser.sql' to update AFServers user on SQL Server ""$using:DefaultSqlServer"""
                    Invoke-Sqlcmd -InputFile 'c:\media\PIAF\UpdateAFServersUser.sql' -Variable $accounts -Serverinstance $using:DefaultSqlServer -Verbose -ErrorAction Stop
                }
                DependsOn            = '[Package]PISystem'
                PsDscRunAsCredential = $domainCredential   # Cred with access to SQL. Necessary for alter SQL settings.
            }

            # If a load balancer DNS record is passed, then will initiate replication of PIFD to SQL Secondary.
            if ($ElasticLoadBalancerDnsRecord) {

                # Required when placed in an AG
                SqlDatabaseRecoveryModel PIFD {
                    InstanceName         = 'MSSQLServer'
                    Name                 = 'PIFD'
                    RecoveryModel        = 'Full'
                    ServerName           = $DefaultSqlServer
                    PsDscRunAsCredential = $domainCredential
                    DependsOn            = '[Package]PISystem'
                }

                # Adds PIFD to AG and replicas to secondary SQL Server.
                SqlAGDatabase AddPIDatabaseReplicas {
                    AvailabilityGroupName = 'SQLAG0'
                    BackupPath            = "\\$DefaultSqlServer\Backup"
                    DatabaseName          = $PIAFSqlDB
                    InstanceName          = 'MSSQLSERVER'
                    ServerName            = $DefaultSqlServer
                    Ensure                = 'Present'
                    PsDscRunAsCredential  = $domainCredential
                    DependsOn             = '[Package]PISystem', '[SqlDatabaseRecoveryModel]PIFD'
                }

                # Script resource to rename the AF Server so that it takes on the Load Balanced endpoint name.
                # This is necessary so PI Vision web.config can point to AF load balanced endpoint whose AF Server name must match the AF LB DNS name.
                Script RenameAfServer {
                    GetScript            = {
                        return @{
                            Value = 'RenameAfServer'
                        }
                    }

                    # Tests whether the default AF Server's name already matches the load balancer name.
                    TestScript           = {
                        try {
                            $afServerName = (Get-AfServer -Default -ErrorAction Stop -Verbose | Connect-AFServer -ErrorAction Stop -Verbose).Name
                            if ($afServerName -eq $using:AFLoadBalancedName) {
                                Write-Verbose -Message "AF Server name '$afServerName' already matches AF load balancer name '$($using:AFLoadBalancedName)'. Skipping RenameAfServer." -Verbose
                                return $true
                            }
                            else {
                                Write-Verbose -Message "AF Server name '$afServerName' does NOT matches AF load balancer name '$($using:AFLoadBalancedName)'. Executing RenameAfServer." -Verbose
                                return $false
                            }
                        }

                        catch {
                            Write-Error $_
                            throw 'Failed to test AF Server with AF load balancer name.'
                        }
                    }

                    SetScript            = {
                        Try {
                            $VerbosePreference = $using:VerbosePreference

                            # Load assemblies necessary to use AFSDK
                            $null = [System.Reflection.Assembly]::LoadWithPartialName('OSIsoft.AFSDKCommon')
                            $null = [System.Reflection.Assembly]::LoadWithPartialName('OSIsoft.AFSDK')

                            # Create AF Server object.
                            $PISystems = New-Object -TypeName OSIsoft.AF.PISystems -Verbose
                            Write-Verbose -Message "New PISystem object created. Default PISystem: '$($PISystems.DefaultPISystem.Name)'" -Verbose

                            # Connect to AF Server.
                            $AfServerConnection = $PISystems.Item($($PISystems.DefaultPISystem.Name))
                            Write-Verbose -Message "OLD AF Server Name: '$($AfServerConnection.Name)'" -Verbose

                            # Rename AF Server. Must happen while connected to AF Server.
                            $AfServerConnection.PISystem.Name = $($using:AFLoadBalancedName)
                            Write-Verbose -Message "NEW AF Server Name: '$($AfServerConnection.Name)'" -Verbose

                            # Apply and CheckIn. The change should take effect immediately from line above, but applied for good measure.
                            $AfServerConnection.ApplyChanges()
                            $AfServerConnection.CheckIn()
                        }

                        Catch {
                            Write-Error $_
                            throw 'Failed to rename AF Server.'
                        }
                    }
                    # NB - Must use PsDscRunAsCredential and not Credential to execute under correct context and privileges.
                    PsDscRunAsCredential = $domainCredential
                }
            }

            # 2C. Set AFSERVER SPN on service account.
			xADServicePrincipalName 'SPN01'
			{
				ServicePrincipalName = $("AFSERVER/" + $env:COMPUTERNAME)
				Account              = $PIAFSvcAccountUsername 
				PsDscRunAsCredential = $domainCredential
 				DependsOn			 = '[WindowsFeature]ADPS'
			}
			xADServicePrincipalName 'SPN02'
			{
				ServicePrincipalName = $("AFSERVER/" + $env:COMPUTERNAME + "." + $DomainDNSName)
				Account              = $PIAFSvcAccountUsername 
				PsDscRunAsCredential = $domainCredential
 				DependsOn			 = '[WindowsFeature]ADPS'
			}

			if($ElasticLoadBalancerDnsRecord){
				xADServicePrincipalName 'SPN03'
				{
					ServicePrincipalName = $("HTTP/" + $AFLoadBalancedName)
					Account              = $PIAFSvcAccountUsername 
					PsDscRunAsCredential = $domainCredential
 					DependsOn			 = '[WindowsFeature]ADPS'
				}
				xADServicePrincipalName 'SPN04'
				{
					ServicePrincipalName = $("HTTP/" + $AFLoadBalancedName + "." + $DomainDNSName)
					Account              = $PIAFSvcAccountUsername 
					PsDscRunAsCredential = $domainCredential
 					DependsOn			 = '[WindowsFeature]ADPS'
				}
			}

            # 2E. Initiate any outstanding reboots.
            xPendingReboot RebootPISystem {
                Name      = 'PostPIInstall'
                DependsOn = '[Package]PISystem'
            }
            #endregion ### 2. INSTALL AND SETUP ###
			
            #region ### Set firewall rules ###
			Script SetNetFirewallRule {
                GetScript = {
                    return @{
                        Value = 'SetNetFirewallRule'
                    }
                }

                # Forces SetScript execution everytime
                TestScript = {
                    return $false
                }

                SetScript = {
                    Try {
						# Enable remote service management for COTS
						Set-NetFirewallRule -DisplayGroup "Remote Service Management" -Enabled True
						Set-NetFirewallRule -DisplayName "File and Printer Sharing (Echo Request - ICMPv4-In)" -Enabled True
                    }
                    Catch {
                        $CheckSource = Get-EventLog -LogName Application -Source AWSQuickStartStatus -ErrorAction SilentlyContinue
                        if (!$CheckSource) {New-EventLog -LogName Application -Source 'AWSQuickStartStatus' -Verbose}  # Check for source to avoid throwing exception if already present.

                        Write-EventLog -LogName Application -Source 'AWSQuickStartStatus' -EntryType Information -EventId 0 -Message  $_
                    }
                }
				PsDscRunAsCredential = $domainCredential
                DependsOn  = '[Package]PISystem'
            }
            #endregion Set firewall rules ###

            #region ### 4. SIGNAL WAITCONDITION ###

            # Writes output to the AWS CloudFormation Init Wait Handle (Indicating script completed)
            # To ensure it triggers only at the end of the script, set DependsOn to include all resources.
            Script Write-AWSQuickStartStatus {
                GetScript  = {@( Value = 'WriteAWSQuickStartStatus' )}
                TestScript = {$false}
                SetScript  = {

                    # Ping WaitHandle to increment Count and indicate DSC has completed.
                    # Note: Manually passing a unique ID (used DSC Configuation ane 'pida0config') to register as a unique signal. See Ref for details.
                    # Ref: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-signal.html
                    Write-Verbose "Getting Handle" -Verbose
                    $handle = Get-AWSQuickStartWaitHandle -ErrorAction SilentlyContinue
                    Invoke-Expression "cfn-signal.exe -e 0 -i 'piaf0config' '$handle'"

                    # Write to Application Log to record status update.
                    $CheckSource = Get-EventLog -LogName Application -Source AWSQuickStartStatus -ErrorAction SilentlyContinue
                    if (!$CheckSource) {New-EventLog -LogName Application -Source 'AWSQuickStartStatus' -Verbose}  # Check for source to avoid throwing exception if already present.
                    Write-EventLog -LogName Application -Source 'AWSQuickStartStatus' -EntryType Information -EventId 0 -Message "Write-AWSQuickStartStatus function was triggered."
                }
                DependsOn  = '[xFirewall]PIAFSDKClientFirewallRule', '[xFirewall]PISQLClientFirewallRule', '[WindowsFeature]ADPS', '[xADUser]ServiceAccount_PIAF', '[Package]PISystem', '[xPendingReboot]RebootPISystem'
            }
            #endregion ### 4. SIGNAL WAITCONDITION ###
        }
    }

    # Compile and Execute Configuration
    PIAF0Config -ConfigurationData $ConfigurationData
    Start-DscConfiguration -Path .\PIAF0Config -Wait -Verbose -Force -ErrorVariable ev
}

catch {
    # If any expectations are thrown, output to CloudFormation Init.
    $_ | Write-AWSQuickStartException
}
# SIG # Begin signature block
# MIIpTQYJKoZIhvcNAQcCoIIpPjCCKToCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDxnS9pcd4qplQe
# 9PkzwibblvDKAvk9GzU3ndekMiooFKCCDhkwggawMIIEmKADAgECAhAIrUCyYNKc
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
# 3gbIhtAHY4vZjeP6cJwRNpxg12nbe25nQ6vuvIsuJ6eS59QxghqKMIIahgIBATB9
# MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UE
# AxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcgUlNBNDA5NiBTSEEz
# ODQgMjAyMSBDQTECEA9Tuc6kgdfYBREfbztczrMwDQYJYIZIAWUDBAIBBQCggZ4w
# GQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisG
# AQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIEQDf6MEr2TPsJiqdopm+6jddTwkXYIV
# 4QlIwzmE74+YMDIGCisGAQQBgjcCAQwxJDAioSCAHmh0dHA6Ly90ZWNoc3VwcG9y
# dC5vc2lzb2Z0LmNvbTANBgkqhkiG9w0BAQEFAASCAgBjMtK6rKNsbJzlFku8UTeL
# vTmfNB27DQKRopLlmNenOHDxFfX+uYkAjLeEGxw3hDUGVnmgLMpOxxzV9IMpFSN3
# ML9dD/0F1etCwYyVAy+R1R4Cg5uKVXzl4iGzOpzzYbsVNVJzqCxOtpM8s3nPH5E4
# 70VLX4+eSFdHQf1kAuq2+IcOi1jXq1wO+bjdLHpW9TI0a+pLRgboxyTbzU0dv0kT
# EQxi5PZy/Bd/0F2FktvuzEVIa5s6JSAWScKInrCTW6BijDc+jHTJpFY8Yu0Krj7n
# fF56+wyABodUc1LXg4nK79Db1WEk7EzW9fm4q3OO1rr8Pp1j2VwWI7ab637Wigcz
# Bd8rjNeY/gKDrQBp3G2cKwDyA8NUdFpoGuN+BCJwvGH+WQsGJ3lZJO2hJiQcM3Ph
# O+URI84i7LFaRYTO4+NUuKRWWDJ0SYKp+zQHpJ738qiEgXz6lxg8Jn/S0s/x7RkP
# UNPSi0sSZXUt8hvLbZDB2UGl4IwvYqqeMFaEYdKbqxtqlNCEjSgteofoDXH3d8eF
# +67gjvhmhRq7Kza2Ly56hrTHnUashcsSYOoXJSCacYd//6pg6iKsGD+PC5q9UUfm
# 3F0+PKOjaABKGA2vn2EL9J5fDqfnupCmT33JYKizfAeU0xF/kI21Xyj0Hq2SR6D0
# nma65FFFo/NICannksDXVKGCFz0wghc5BgorBgEEAYI3AwMBMYIXKTCCFyUGCSqG
# SIb3DQEHAqCCFxYwghcSAgEDMQ8wDQYJYIZIAWUDBAIBBQAwdwYLKoZIhvcNAQkQ
# AQSgaARmMGQCAQEGCWCGSAGG/WwHATAxMA0GCWCGSAFlAwQCAQUABCCoc07hxK42
# 6FPHilulC/2goAClys2K6M8idvBP+P3eNAIQfhhpGsGYIYnIQJ1LCMq1ihgPMjAy
# MjEwMjcwMTI3MDBaoIITBzCCBsAwggSooAMCAQICEAxNaXJLlPo8Kko9KQeAPVow
# DQYJKoZIhvcNAQELBQAwYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0
# LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hB
# MjU2IFRpbWVTdGFtcGluZyBDQTAeFw0yMjA5MjEwMDAwMDBaFw0zMzExMjEyMzU5
# NTlaMEYxCzAJBgNVBAYTAlVTMREwDwYDVQQKEwhEaWdpQ2VydDEkMCIGA1UEAxMb
# RGlnaUNlcnQgVGltZXN0YW1wIDIwMjIgLSAyMIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEAz+ylJjrGqfJru43BDZrboegUhXQzGias0BxVHh42bbySVQxh
# 9J0Jdz0Vlggva2Sk/QaDFteRkjgcMQKW+3KxlzpVrzPsYYrppijbkGNcvYlT4Dot
# jIdCriak5Lt4eLl6FuFWxsC6ZFO7KhbnUEi7iGkMiMbxvuAvfTuxylONQIMe58ty
# SSgeTIAehVbnhe3yYbyqOgd99qtu5Wbd4lz1L+2N1E2VhGjjgMtqedHSEJFGKes+
# JvK0jM1MuWbIu6pQOA3ljJRdGVq/9XtAbm8WqJqclUeGhXk+DF5mjBoKJL6cqtKc
# tvdPbnjEKD+jHA9QBje6CNk1prUe2nhYHTno+EyREJZ+TeHdwq2lfvgtGx/sK0YY
# oxn2Off1wU9xLokDEaJLu5i/+k/kezbvBkTkVf826uV8MefzwlLE5hZ7Wn6lJXPb
# wGqZIS1j5Vn1TS+QHye30qsU5Thmh1EIa/tTQznQZPpWz+D0CuYUbWR4u5j9lMNz
# IfMvwi4g14Gs0/EH1OG92V1LbjGUKYvmQaRllMBY5eUuKZCmt2Fk+tkgbBhRYLqm
# gQ8JJVPxvzvpqwcOagc5YhnJ1oV/E9mNec9ixezhe7nMZxMHmsF47caIyLBuMnnH
# C1mDjcbu9Sx8e47LZInxscS451NeX1XSfRkpWQNO+l3qRXMchH7XzuLUOncCAwEA
# AaOCAYswggGHMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB
# /wQMMAoGCCsGAQUFBwMIMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwH
# ATAfBgNVHSMEGDAWgBS6FtltTYUvcyl2mi91jGogj57IbzAdBgNVHQ4EFgQUYore
# 0GH8jzEU7ZcLzT0qlBTfUpwwWgYDVR0fBFMwUTBPoE2gS4ZJaHR0cDovL2NybDMu
# ZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0UlNBNDA5NlNIQTI1NlRpbWVT
# dGFtcGluZ0NBLmNybDCBkAYIKwYBBQUHAQEEgYMwgYAwJAYIKwYBBQUHMAGGGGh0
# dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBYBggrBgEFBQcwAoZMaHR0cDovL2NhY2Vy
# dHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0UlNBNDA5NlNIQTI1NlRp
# bWVTdGFtcGluZ0NBLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAVaoqGvNG83hXNzD8
# deNP1oUj8fz5lTmbJeb3coqYw3fUZPwV+zbCSVEseIhjVQlGOQD8adTKmyn7oz/A
# yQCbEx2wmIncePLNfIXNU52vYuJhZqMUKkWHSphCK1D8G7WeCDAJ+uQt1wmJefkJ
# 5ojOfRu4aqKbwVNgCeijuJ3XrR8cuOyYQfD2DoD75P/fnRCn6wC6X0qPGjpStOq/
# CUkVNTZZmg9U0rIbf35eCa12VIp0bcrSBWcrduv/mLImlTgZiEQU5QpZomvnIj5E
# IdI/HMCb7XxIstiSDJFPPGaUr10CU+ue4p7k0x+GAWScAMLpWnR1DT3heYi/HAGX
# yRkjgNc2Wl+WFrFjDMZGQDvOXTXUWT5Dmhiuw8nLw/ubE19qtcfg8wXDWd8nYive
# QclTuf80EGf2JjKYe/5cQpSBlIKdrAqLxksVStOYkEVgM4DgI974A6T2RUflzrgD
# QkfoQTZxd639ouiXdE4u2h4djFrIHprVwvDGIqhPm73YHJpRxC+a9l+nJ5e6li6F
# V8Bg53hWf2rvwpWaSxECyIKcyRoFfLpxtU56mWz06J7UWpjIn7+NuxhcQ/XQKuji
# Yu54BNu90ftbCqhwfvCXhHjjCANdRyxjqCU4lwHSPzra5eX25pvcfizM/xdMTQCi
# 2NYBDriL7ubgclWJLCcZYfZ3AYwwggauMIIElqADAgECAhAHNje3JFR82Ees/Shm
# Kl5bMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdp
# Q2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERp
# Z2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yMjAzMjMwMDAwMDBaFw0zNzAzMjIy
# MzU5NTlaMGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7
# MDkGA1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1l
# U3RhbXBpbmcgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDGhjUG
# SbPBPXJJUVXHJQPE8pE3qZdRodbSg9GeTKJtoLDMg/la9hGhRBVCX6SI82j6ffOc
# iQt/nR+eDzMfUBMLJnOWbfhXqAJ9/UO0hNoR8XOxs+4rgISKIhjf69o9xBd/qxkr
# PkLcZ47qUT3w1lbU5ygt69OxtXXnHwZljZQp09nsad/ZkIdGAHvbREGJ3HxqV3rw
# N3mfXazL6IRktFLydkf3YYMZ3V+0VAshaG43IbtArF+y3kp9zvU5EmfvDqVjbOSm
# xR3NNg1c1eYbqMFkdECnwHLFuk4fsbVYTXn+149zk6wsOeKlSNbwsDETqVcplicu
# 9Yemj052FVUmcJgmf6AaRyBD40NjgHt1biclkJg6OBGz9vae5jtb7IHeIhTZgirH
# kr+g3uM+onP65x9abJTyUpURK1h0QCirc0PO30qhHGs4xSnzyqqWc0Jon7ZGs506
# o9UD4L/wojzKQtwYSH8UNM/STKvvmz3+DrhkKvp1KCRB7UK/BZxmSVJQ9FHzNklN
# iyDSLFc1eSuo80VgvCONWPfcYd6T/jnA+bIwpUzX6ZhKWD7TA4j+s4/TXkt2ElGT
# yYwMO1uKIqjBJgj5FBASA31fI7tk42PgpuE+9sJ0sj8eCXbsq11GdeJgo1gJASgA
# DoRU7s7pXcheMBK9Rp6103a50g5rmQzSM7TNsQIDAQABo4IBXTCCAVkwEgYDVR0T
# AQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUuhbZbU2FL3MpdpovdYxqII+eyG8wHwYD
# VR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMG
# A1UdJQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYY
# aHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2Fj
# ZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNV
# HR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRU
# cnVzdGVkUm9vdEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1s
# BwEwDQYJKoZIhvcNAQELBQADggIBAH1ZjsCTtm+YqUQiAX5m1tghQuGwGC4QTRPP
# MFPOvxj7x1Bd4ksp+3CKDaopafxpwc8dB+k+YMjYC+VcW9dth/qEICU0MWfNthKW
# b8RQTGIdDAiCqBa9qVbPFXONASIlzpVpP0d3+3J0FNf/q0+KLHqrhc1DX+1gtqpP
# kWaeLJ7giqzl/Yy8ZCaHbJK9nXzQcAp876i8dU+6WvepELJd6f8oVInw1YpxdmXa
# zPByoyP6wCeCRK6ZJxurJB4mwbfeKuv2nrF5mYGjVoarCkXJ38SNoOeY+/umnXKv
# xMfBwWpx2cYTgAnEtp/Nh4cku0+jSbl3ZpHxcpzpSwJSpzd+k1OsOx0ISQ+UzTl6
# 3f8lY5knLD0/a6fxZsNBzU+2QJshIUDQtxMkzdwdeDrknq3lNHGS1yZr5Dhzq6YB
# T70/O3itTK37xJV77QpfMzmHQXh6OOmc4d0j/R0o08f56PGYX/sr2H7yRp11LB4n
# LCbbbxV7HhmLNriT1ObyF5lZynDwN7+YAN8gFk8n+2BnFqFmut1VwDophrCYoCvt
# lUG3OtUVmDG0YgkPCr2B2RP+v6TR81fZvAT6gt4y3wSJ8ADNXcL50CN/AAvkdgIm
# 2fBldkKmKYcJRyvmfxqkhQ/8mJb2VVQrH4D6wPIOK+XW+6kvRBVK5xMOHds3OBqh
# K/bt1nz8MIIFjTCCBHWgAwIBAgIQDpsYjvnQLefv21DiCEAYWjANBgkqhkiG9w0B
# AQwFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVk
# IElEIFJvb3QgQ0EwHhcNMjIwODAxMDAwMDAwWhcNMzExMTA5MjM1OTU5WjBiMQsw
# CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cu
# ZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC/5pBzaN675F1KPDAiMGkz
# 7MKnJS7JIT3yithZwuEppz1Yq3aaza57G4QNxDAf8xukOBbrVsaXbR2rsnnyyhHS
# 5F/WBTxSD1Ifxp4VpX6+n6lXFllVcq9ok3DCsrp1mWpzMpTREEQQLt+C8weE5nQ7
# bXHiLQwb7iDVySAdYyktzuxeTsiT+CFhmzTrBcZe7FsavOvJz82sNEBfsXpm7nfI
# SKhmV1efVFiODCu3T6cw2Vbuyntd463JT17lNecxy9qTXtyOj4DatpGYQJB5w3jH
# trHEtWoYOAMQjdjUN6QuBX2I9YI+EJFwq1WCQTLX2wRzKm6RAXwhTNS8rhsDdV14
# Ztk6MUSaM0C/CNdaSaTC5qmgZ92kJ7yhTzm1EVgX9yRcRo9k98FpiHaYdj1ZXUJ2
# h4mXaXpI8OCiEhtmmnTK3kse5w5jrubU75KSOp493ADkRSWJtppEGSt+wJS00mFt
# 6zPZxd9LBADMfRyVw4/3IbKyEbe7f/LVjHAsQWCqsWMYRJUadmJ+9oCw++hkpjPR
# iQfhvbfmQ6QYuKZ3AeEPlAwhHbJUKSWJbOUOUlFHdL4mrLZBdd56rF+NP8m800ER
# ElvlEFDrMcXKchYiCd98THU/Y+whX8QgUWtvsauGi0/C1kVfnSD8oR7FwI+isX4K
# Jpn15GkvmB0t9dmpsh3lGwIDAQABo4IBOjCCATYwDwYDVR0TAQH/BAUwAwEB/zAd
# BgNVHQ4EFgQU7NfjgtJxXWRM3y5nP+e6mK4cD08wHwYDVR0jBBgwFoAUReuir/SS
# y4IxLVGLp6chnfNtyA8wDgYDVR0PAQH/BAQDAgGGMHkGCCsGAQUFBwEBBG0wazAk
# BggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEMGCCsGAQUFBzAC
# hjdodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURS
# b290Q0EuY3J0MEUGA1UdHwQ+MDwwOqA4oDaGNGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0
# LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwEQYDVR0gBAowCDAGBgRV
# HSAAMA0GCSqGSIb3DQEBDAUAA4IBAQBwoL9DXFXnOF+go3QbPbYW1/e/Vwe9mqyh
# hyzshV6pGrsi+IcaaVQi7aSId229GhT0E0p6Ly23OO/0/4C5+KH38nLeJLxSA8hO
# 0Cre+i1Wz/n096wwepqLsl7Uz9FDRJtDIeuWcqFItJnLnU+nBgMTdydE1Od/6Fmo
# 8L8vC6bp8jQ87PcDx4eo0kxAGTVGamlUsLihVo7spNU96LHc/RzY9HdaXFSMb++h
# UD38dglohJ9vytsgjTVgHAIDyyCwrFigDkBjxZgiwbJZ9VVrzyerbHbObyMt9H5x
# aiNrIv8SuFQtJ37YOtnwtoeW/VvRXKwYw02fc7cBqZ9Xql4o4rmUMYIDdjCCA3IC
# AQEwdzBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5
# BgNVBAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0
# YW1waW5nIENBAhAMTWlyS5T6PCpKPSkHgD1aMA0GCWCGSAFlAwQCAQUAoIHRMBoG
# CSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAcBgkqhkiG9w0BCQUxDxcNMjIxMDI3
# MDEyNzAwWjArBgsqhkiG9w0BCRACDDEcMBowGDAWBBTzhyJNhjOCkjWplLy9j5bp
# /hx8czAvBgkqhkiG9w0BCQQxIgQgKKYOnQLPfZiNlTZI/D2mPCsYsWLFWm9hHGgf
# 8ciJ8P0wNwYLKoZIhvcNAQkQAi8xKDAmMCQwIgQgx/ThvjIoiSCr4iY6vhrE/E/m
# eBwtZNBMgHVXoCO1tvowDQYJKoZIhvcNAQEBBQAEggIAs79Q6s45CIftIRDtPiyp
# z6novNLV6jR/Xt0fIAVnx4hPQCeu5vAEk1fjFPiDAR5/rG4yp3DER+PKEuILS5BW
# D4WpPK8+ZspjImwLD6hwmfYnl7pNIIuPBGHtKGIfjHiTdXaKV6MJF3YQfZ7khJvB
# Y6i53e1ulA78aMAUxCrmGkvuWQ4J7nmQ5nuRzczpaa7qc002fHUqTytRy5iEXeiD
# CypzwnR8hkkS1elQXqOxrMMhwWCYfBCcFeyccgyKqJfZws+o6brc4wje+EYUZhX+
# OHD/cPnrT0LsAj9T9YlDo+zm4B8uFfxTHLuTAZNlnnHkRVE0k6MX+wBXrycxww4T
# Q01JLmhXrBTZiNqbt1NV4vmr54PpjpckbueYjhO1i4qbqg5Fg7aVJQ59QC8X8K02
# WyqwSCadEoRDydYI5Ztbj44QN3s9RtLvAKxpM+24QVHa0jHChqn57pOVQhpKwvLP
# EkakCnARaOOhrVVOk9YxJ3fJLh16aoN/SXxGE28fKUPvaRoLaZjb8mIyEJI6GGIu
# nB0xQku3g82cbxi5bJdgq2eLTyojpB8nhDbYEY12HYSnO6nLfhU/RFyCOOU6hOui
# VtWYlW79NEv+bFSAmZYzLVEbqRmxeQ7zUy+nEMF9BMO7sCEnSzWXszQi2WbKXjWJ
# 21TBJ2w28PWQG4r2z89z+T0=
# SIG # End signature block
