<#

.SYNOPSIS
    PowerShell script to update common settings in the Windows remote access phonebook configuration file.

.PARAMETER AllUserConnection
    Identifies the VPN connection is configured for all users.

.PARAMETER DisableClassBasedDefaultRoute
    Enables or disable the class-based default route.

.PARAMETER DisableCredentialCaching
    Enable or disable credential caching.

.PARAMETER DisableIkeMobility
    Setting to disable IKE mobility.

.PARAMETER InterfaceMetric
    Defines the interface metric to be used for the VPN connection.

.PARAMETER NetworkOutageTime
    Defines the network outage time when IKE mobility is enabled.

.PARAMETER ProfileName
    The name of the VPN connection to update settings for.

.PARAMETER RasphonePath
    Specifies the path to the rasphone.pbk file. This parameter may be required when running this script using SCCM or other systems management tools that deploy software to the user but run in the SYSTEM context.

.PARAMETER SetPreferredProtocol
    Defines the preferred VPN protocol.

.PARAMETER UseRasCredentials
    Enables or disables the usage of the VPN credentials for SSO against systems behind the VPN.

.PARAMETER UseWinlogonCredential
    Enables or disables the usage of the user's credentials used to log on to Windows for VPN authentication.

.PARAMETER UseWinlogonCredential
    Enables or disables the registration of the VPN clients IP address in internal DNS.

.EXAMPLE
    .\Update-Rasphone.ps1 -ProfileName 'Always On VPN' -SetPreferredProtocol IKEv2 -InterfaceMetric 15 -DisableIkeMobility

    Running this command will update the preferred protocol setting to IKEv2, the interface metric to 15, and disables IKE mobility on the VPN connection "Always On VPN".

.EXAMPLE
    .\Update-Rasphone.ps1 -ProfileName 'Always On VPN Device Tunnel' -InterfaceMetric 15 -NetworkOutageTime 60 -AllUserConnection

    Running this command will update the interface metric to 15 and the IKEv2 network outage time to 60 seconds for the device tunnel VPN connection "Always On VPN Device Tunnel".

.DESCRIPTION
    Always On VPN administrators may need to adjust settings for VPN connections that are not exposed in the Microsoft Intune user interface, ProfileXML, or native PowerShell commands. This script allows administrators to edit some of the commonly edited settings in the Windows remote access phonebook configuration file.

.LINK
    https://directaccess.richardhicks.com/

.NOTES
    Version:        2.22
    Creation Date:  April 9, 2020
    Last Updated:   September 24, 2021
    Author:         Richard Hicks
    Organization:   Richard M. Hicks Consulting, Inc.
    Contact:        rich@richardhicks.com
    Web Site:       https://directaccess.richardhicks.com/

#>

[CmdletBinding(SupportsShouldProcess)]

Param (

    # VPN Profile name to change the VPNStrategy from
    $ProfileName = 'VPN Connection Name',
    
    # Set protocol to change to
    # IKEv2 = IKEv2 is attempted followed by SSTP
    # IKEv2Only = Only IKEv2 is attempted
    # SSTP = SSTP is attempted first
    # SSTPOnly = Only SSTP is attempted
    # Automatic = Default setting
    $SetPreferredProtocol = 'IKEv2',




    [string]$RasphonePath,
    [string]$InterfaceMetric,
    [ValidateSet('True', 'False')]
    [string]$DisableIkeMobility,
    [ValidateSet('60', '120', '300', '600', '1200', '1800')]
    [string]$NetworkOutageTime,
    [ValidateSet('True', 'False')]
    [string]$UseRasCredentials,
    [ValidateSet('True', 'False')]
    [string]$UseWinlogonCredential,
    [ValidateSet('True', 'False')]
    [string]$DisableClassBasedDefaultRoute,
    [ValidateSet('True', 'False')]
    [string]$DisableCredentialCaching,
    [ValidateSet('True', 'False')]
    [string]$RegisterDNS,
    [Alias("DeviceTunnel")]
    [switch]$AllUserConnection

)

# // Exit script if options to disable IKE mobility and define a network outage time are both enabled
If ($DisableIkeMobility -And $NetworkOutageTime) {

    Write-Warning 'The option to disable IKE mobility and set a network outage time are mutually exclusive. Please choose one and run this command again.'
    Exit  

}

# // Define rasphone.pbk file path
$users = Get-ChildItem (Join-Path -Path $env:SystemDrive -ChildPath 'Users') -Exclude 'Public', '_adm*', 'ADMINI~*'
if ($null -ne $users) {
    foreach ($user in $users) {
        $progPath = Join-Path -Path $user.FullName -ChildPath "AppData\Roaming\Microsoft\Network\Connections\Pbk\"
        $RasphonePath = Join-Path -Path $user.FullName -ChildPath "AppData\Roaming\Microsoft\Network\Connections\Pbk\rasphone.pbk"
    }
}
# Backup pbk
    $RasphoneBackupPath = Join-Path $progPath -ChildPath "rasphone_$(Get-Date -Format FileDateTime).bak"

$users = Get-ChildItem (Join-Path -Path $env:SystemDrive -ChildPath 'Users') -Exclude 'Public', '_adm*', 'ADMINI~*'

# // Ensure that rasphone.pbk exists
If (!(Test-Path $RasphonePath)) {

    Write-Warning "The file $RasphonePath does not exist. Exiting script."
    Exit

}

# // Create backup of rasphone.pbk
Write-Verbose "Backing up existing rasphone.pbk file to $RasphoneBackupPath..."
Copy-Item $RasphonePath $RasphoneBackupPath

# // Create empty VPN profile settings hashtable
$Settings = @{ }

# // Set preferred VPN protocol
If ($SetPreferredProtocol) {

    Switch ($SetPreferredProtocol) {

        IKEv2 { $Value = '14' }
        IKEv2Only { $Value = '7' }
        SSTP { $Value = '6' }
        SSTPOnly { $Value = '5' }
        Automatic { $Value = '0' }

    }
    
    $Settings.Add('VpnStrategy', $Value)

}

# // Set IPv4 and IPv6 interface metrics
If ($InterfaceMetric) {

    $Settings.Add('IpInterfaceMetric', $InterfaceMetric)
    $Settings.Add('Ipv6InterfaceMetric', $InterfaceMetric)
}

# // Disable IKE mobility
If ($DisableIkeMobility) {

    Switch ($DisableIkeMobility) {

        True { $Value = '1'}
        False { $Value = '0'}

    }

    $Settings.Add('DisableMobility', $Value)
    $Settings.Add('NetworkOutageTime', '0')

}

# // If IKE mobility is enabled, define network outage time
If ($NetworkOutageTime) {

    $Settings.Add('DisableMobility', '0')
    $Settings.Add('NetworkOutageTime', $NetworkOutageTime)

}

# // Define use of VPN credentials for SSO to on-premises resources (helpful for non-domain joined clients)
If ($UseRasCredentials) {

    Switch ($UseRasCredentials) {

        True { $Value = '1' }
        False { $Value = '0' }

    }

    $Settings.Add('UseRasCredentials', $Value)

}

# // Define use of logged on user's Windows credentials for automatic VPN logon (helpful when MS-CHAP v2 authentication is configured)
If ($UseWinlogonCredential) {

    Switch ($UseWinlogonCredential) {

        True { $Value = '1' }
        False { $Value = '0' }

    }

    $Settings.Add('AutoLogon', $Value)

}

# // Enable or disable the class-based default route
If ($DisableClassBasedDefaultRoute) {

    Switch ($DisableClassBasedDefaultRoute) {

        True { $Value = '1' }
        False { $Value = '0' }

    }

    $Settings.Add('DisableClassBasedDefaultRoute', $Value)

}

# // Enable or disable credential caching
If ($DisableCredentialCaching) {

    Switch ($DisableCredentialCaching) {

        True { $Value = '0' }
        False { $Value = '1' }

    }

    $Settings.Add('CacheCredentials', $Value)

}

# // Enable or disable VPN adapter DNS registration
If ($RegisterDNS) {

    Switch ($RegisterDNS) {

        True { $Value = '1' }
        False { $Value = '0' }

    }

    $Settings.Add('IpDnsFlags', $Value)

}

# // Function to update rasphone.pbk
Function Update-RASPhoneBook {

    [CmdletBinding(SupportsShouldProcess)]

    Param (

        [string]$Path,
        [string]$ProfileName,
        [hashtable]$Settings

    )

    $pattern = "(\[.*\])"
    $c = Get-Content $path -Raw
    $p = [System.Text.RegularExpressions.Regex]::Split($c, $pattern, "IgnoreCase") | Where-Object { $_ }

    # // Create a hashtable of VPN profiles
    Write-Verbose "Initializing a hashtable for VPN profiles from $path..."
    $profHash = [ordered]@{}

    For ($i = 0; $i -lt $p.count; $i += 2) {

        Write-Verbose "Adding $($p[$i]) to VPN profile hashtable..."
        $profhash.Add($p[$i], $p[$i + 1])

    }

    # // An array to hold changed values for -Passthru
    $pass = @()

    Write-Verbose "Found the following VPN profiles: $($profhash.keys -join ',')."

    $compare = "[$Profilename]"
    
    Write-Verbose "Searching for VPN profile $compare..."
    # // Need to make sure to get the exact profile
    $SelectedProfile = $profHash.GetEnumerator() | Where-Object { $_.name -eq $compare }

    If ($SelectedProfile) {

        Write-Verbose "Updating $($SelectedProfile.key)"
        $pass += $SelectedProfile.key

        $Settings.GetEnumerator() | ForEach-Object {

            $SettingName = $_.name
            Write-Verbose "Searching for setting $Settingname..."
            $Value = $_.Value
            $thisName = "$SettingName=.*\s?`n"
            $thatName = "$SettingName=$value`n"
            If ($SelectedProfile.Value -match $thisName) {

                Write-Verbose "Setting $SettingName = $Value."
                $SelectedProfile.value = $SelectedProfile.value -replace $thisName, $thatName
                $pass += ($ThatName).TrimEnd()
                # // Set a flag indicating the file should be updated
                $ChangeMade = $True

            }

            Else {

                Write-Warning "Could not find an entry for $SettingName under [$($SelectedProfile.key)]."

            }

        } #ForEach setting

        If ($ChangeMade) {

            # // Update the VPN profile hashtable
            $profhash[$Selectedprofile.key] = $Selectedprofile.value

        }

    } #If found

    Else {

        Write-Warning "VPN Profile [$profilename] not found."

    }

    # // Only update the file if changes were made
    If (($ChangeMade) -AND ($pscmdlet.ShouldProcess($path, "Update RAS PhoneBook"))) {

        Write-Verbose "Updating $Path"
        $output = $profHash.Keys | ForEach-Object { $_ ; ($profhash[$_] | Out-String).trim(); "`n" }
        $output | Out-File -FilePath $Path -Encoding ascii

    } #Whatif

} #close function

Update-RasphoneBook -Path $RasphonePath -ProfileName $ProfileName -Settings $Settings
