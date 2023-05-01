# Function to ping a host
function Test-HostPing {
    param (
        [Parameter(Mandatory = $true)]
        [string] $Host
    )

    $result = Test-Connection -ComputerName $Host -Count 1 -Quiet

    if ($result) {
        Write-Host "Ping to $Host succeeded."
    } else {
        Write-Host "Ping to $Host failed."
    }
}

# Function to resolve a hostname to IP address
function Resolve-HostName {
    param (
        [Parameter(Mandatory = $true)]
        [string] $HostName
    )

    try {
        $ip = [System.Net.Dns]::GetHostAddresses($HostName)
        Write-Host "Resolved IP address(es) for $HostName: $($ip -join ', ')"
    } catch {
        Write-Host "Error resolving hostname: $_"
    }
}

# Function to resolve an IP address to a hostname
function Resolve-IPAddress {
    param (
        [Parameter(Mandatory = $true)]
        [string] $IPAddress
    )

    try {
        $host = [System.Net.Dns]::GetHostEntry($IPAddress)
        Write-Host "Resolved hostname for $IPAddress: $($host.HostName)"
    } catch {
        Write-Host "Error resolving IP address: $_"
    }
}

function Get-DnsRecord {
    param (
        [Parameter(Mandatory = $true)]
        [string] $Domain,
        [string] $RecordType = "A"
    )

    try {
        $records = Resolve-DnsName -Name $Domain -Type $RecordType
        $records | Format-Table
    } catch {
        Write-Host "Error querying DNS records: $_"
    }
}

function Get-NetworkInterface {
    $interfaces = Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, LinkSpeed, MacAddress, MediaType
    $interfaces | Format-Table
}

function Set-NetworkInterfaceStatus {
    param (
        [Parameter(Mandatory = $true)]
        [string] $InterfaceName,
        [string] $Status
    )

    if ($Status -eq "Enable") {
        Enable-NetAdapter -Name $InterfaceName
    } elseif ($Status -eq "Disable") {
        Disable-NetAdapter -Name $InterfaceName
    } else {
        Write-Host "Invalid status. Use 'Enable' or 'Disable'."
    }
}

function Get-RoutingTable {
    $routes = Get-NetRoute -AddressFamily IPv4 | Select-Object DestinationPrefix, NextHop, RouteMetric, InterfaceAlias
    $routes | Format-Table
}

function Get-NetworkConnections {
    $connections = Get-NetTCPConnection | Where-Object { $_.State -eq "Established" } | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State
    $connections | Format-Table
}

function Test-NetworkBandwidth {
    param (
        [Parameter(Mandatory = $true)]
        [string] $RemoteHost,
        [int] $Duration = 10
    )

    $result = Test-NetConnection -ComputerName $RemoteHost -TraceRoute -DiagnoseRouting
    $bandwidth = $result.TraceRoute | Measure-Object -Property ResponseTime -Average
    $averageResponseTime = [math]::Round($bandwidth.Average, 2)
    Write-Host "Average response time over $Duration seconds: $averageResponseTime ms"
}

function Set-IPAddress {
    param (
        [Parameter(Mandatory = $true)]
        [string] $InterfaceName,
        [string] $IPAddress,
        [string] $SubnetMask,
        [string] $DefaultGateway,
        [string] $DnsServer
    )

    New-NetIPAddress -InterfaceAlias $InterfaceName -IPAddress $IPAddress -PrefixLength $SubnetMask -DefaultGateway $DefaultGateway
    Set-DnsClientServerAddress -InterfaceAlias $InterfaceName -ServerAddresses $DnsServer
}

function Test-MultipleHosts {
    param (
        [Parameter(Mandatory = $true)]
        [string[]] $Hosts
    )

    foreach ($host in $Hosts) {
        $ping = Test-Connection -ComputerName $host -Count 1 -ErrorAction SilentlyContinue
        if ($ping) {
            Write-Host "$host is online"
        } else {
            Write-Host "$host is offline"
        }
    }
}

function New-NetworkShare {
    param (
        [Parameter(Mandatory = $true)]
        [string] $ShareName,
        [string] $Path,
        [string] $Description = ''
    )

    New-SmbShare -Name $ShareName -Path $Path -Description $Description -FullAccess Everyone
}

function Remove-NetworkShare {
    param (
        [Parameter(Mandatory = $true)]
        [string] $ShareName
    )

    Remove-SmbShare -Name $ShareName -Force
}

function Get-FileServerSessions {
    $sessions = Get-SmbSession | Select-Object ClientComputerName, ClientUserName, NumOpens
    $sessions | Format-Table
}

function Get-OpenFiles {
    $files = Get-SmbOpenFile | Select-Object Path, ClientComputerName, ClientUserName
    $files | Format-Table
}

function Test-RemotePort {
    param (
        [Parameter(Mandatory = $true)]
        [string] $RemoteHost,
        [int] $Port
    )

    $result = Test-NetConnection -ComputerName $RemoteHost -Port $Port

    if ($result.TcpTestSucceeded) {
        Write-Host "Port $Port is open on $RemoteHost"
    } else {
        Write-Host "Port $Port is closed on $RemoteHost"
    }
}

function Get-NetworkSpeed {
    param (
        [Parameter(Mandatory = $true)]
        [string] $InterfaceName
    )

    $speed = Get-NetAdapterAdvancedProperty -Name $InterfaceName -RegistryKeyword "SpeedDuplex" | Select-Object -ExpandProperty DisplayValue
    Write-Host "Current speed and duplex settings for $InterfaceName: $speed"
}

function Set-NetworkSpeed {
    param (
        [Parameter(Mandatory = $true)]
        [string] $InterfaceName,
        [string] $SpeedDuplex
    )

    Set-NetAdapterAdvancedProperty -Name $InterfaceName -RegistryKeyword "SpeedDuplex" -RegistryValue $SpeedDuplex
}

function Get-WiFiNetworks {
    $networks = Get-NetNeighbor -AddressFamily IPv4 | Select-Object ifIndex, State, LinkLayerAddress, IPAddress
    $networks | Format-Table
}

function Get-NetworkRoutes {
    $routes = Get-NetRoute -AddressFamily IPv4 | Select-Object ifIndex, DestinationPrefix, NextHop, RouteMetric
    $routes | Format-Table
}

function Add-NetworkRoute {
    param (
        [Parameter(Mandatory = $true)]
        [string] $Destination,
        [string] $NextHop,
        [int] $InterfaceIndex,
        [int] $RouteMetric
    )

    New-NetRoute -DestinationPrefix $Destination -NextHop $NextHop -InterfaceIndex $InterfaceIndex -RouteMetric $RouteMetric
}

function Remove-NetworkRoute {
    param (
        [Parameter(Mandatory = $true)]
        [string] $Destination,
        [string] $NextHop
    )

    Remove-NetRoute -DestinationPrefix $Destination -NextHop $NextHop -Confirm:$false
}

function Get-NetworkShares {
    param (
        [Parameter(Mandatory = $true)]
        [string] $RemoteComputer
    )

    Get-WmiObject -Class Win32_Share -ComputerName $RemoteComputer | Select-Object Name, Path, Description
}

function Test-RemoteManagement {
    param (
        [Parameter(Mandatory = $true)]
        [string] $RemoteComputer
    )

    $result = Test-WSMan -ComputerName $RemoteComputer

    if ($result) {
        Write-Host "Remote management is available on $RemoteComputer"
    } else {
        Write-Host "Remote management is not available on $RemoteComputer"
    }
}

function Invoke-RemoteCommand {
    param (
        [Parameter(Mandatory = $true)]
        [string] $RemoteComputer,
        [string] $Command
    )

    Invoke-Command -ComputerName $RemoteComputer -ScriptBlock {Invoke-Expression $args[0]} -ArgumentList $Command
}

function New-VirtualSwitch {
    param (
        [Parameter(Mandatory = $true)]
        [string] $SwitchName,
        [string] $SwitchType = "Internal"
    )

    New-VMSwitch -Name $SwitchName -SwitchType $SwitchType
}

function Remove-VirtualSwitch {
    param (
        [Parameter(Mandatory = $true)]
        [string] $SwitchName
    )

    Remove-VMSwitch -Name $SwitchName -Force
}

function Get-NetworkProfiles {
    Get-NetConnectionProfile | Select-Object InterfaceAlias, NetworkCategory, IPv4Connectivity, IPv6Connectivity
}

function Set-NetworkProfile {
    param (
        [Parameter(Mandatory = $true)]
        [string] $InterfaceName,
        [string] $Profile
    )

    $profile = $Profile.ToLower()

    if ($profile -eq "public" -or $profile -eq "private" -or $profile -eq "domain") {
        Get-NetConnectionProfile -InterfaceAlias $InterfaceName | Set-NetConnectionProfile -NetworkCategory $Profile
    } else {
        Write-Host "Invalid network profile. Please use 'Public', 'Private', or 'Domain'."
    }
}

function Get-NetworkUsage {
    $networkUsage = Get-NetAdapterStatistics | Select-Object Name, BytesReceived, BytesSent
    $networkUsage | Format-Table
}

function Get-NetworkAdapterProperties {
    param (
        [Parameter(Mandatory = $true)]
        [string] $InterfaceName
    )

    $properties = Get-NetAdapter -Name $InterfaceName | Get-NetAdapterAdvancedProperty | Select-Object DisplayName, DisplayValue
    $properties | Format-Table
}

function Set-DnsSettings {
    param (
        [Parameter(Mandatory = $true)]
        [string] $InterfaceName,
        [string[]] $DnsServers
    )

    Set-DnsClientServerAddress -InterfaceAlias $InterfaceName -ServerAddresses $DnsServers
}

function Get-NetworkAdapterInfo {
    param (
        [Parameter(Mandatory = $true)]
        [string] $InterfaceName
    )

    $adapterInfo = Get-NetAdapter -Name $InterfaceName | Select-Object Name, InterfaceDescription, Status, MacAddress, MediaType, LinkSpeed
    $adapterInfo | Format-Table
}

function Get-ListeningSockets {
    $sockets = Get-NetTCPConnection | Where-Object { $_.State -eq "Listen" } | Select-Object LocalAddress, LocalPort, State
    $sockets | Format-Table
}

function Test-LocalVulnerabilities {
    # Check for missing Microsoft security updates
    Write-Host "Checking for missing Microsoft security updates..."
    $missingUpdates = Get-CimInstance -Class Win32_QuickFixEngineering | Where-Object { $_.HotFixID.StartsWith("KB") } | Sort-Object -Property InstalledOn -Descending
    if ($missingUpdates) {
        Write-Host "The following Microsoft security updates are missing on this machine:"
        $missingUpdates | Format-Table -AutoSize
    } else {
        Write-Host "No missing Microsoft security updates found."
    }

    # Check for missing third-party software updates
    Write-Host "Checking for missing third-party software updates..."
    $vulnSoftware = Find-PSAttackVulnerability -Category Software | Where-Object { $_.Severity -gt 0 }
    if ($vulnSoftware) {
        Write-Host "The following third-party software has known vulnerabilities and may need updating:"
        $vulnSoftware | Select-Object Name, Severity, VulnerabilityID, Url | Format-Table -AutoSize
    } else {
        Write-Host "No missing third-party software updates found."
    }

    # Scan for known vulnerabilities in running processes and services
    Write-Host "Scanning for known vulnerabilities in running processes and services..."
    $vulnProcesses = Find-PSAttackVulnerability -Category Process
    if ($vulnProcesses) {
        Write-Host "The following running processes or services have known vulnerabilities:"
        $vulnProcesses | Select-Object Name, Severity, VulnerabilityID, Url | Format-Table -AutoSize
    } else {
        Write-Host "No vulnerabilities found in running processes or services."
    }

    # Scan for known vulnerabilities in installed software
    Write-Host "Scanning for known vulnerabilities in installed software..."
    $vulnInstalledSoftware = Find-PSAttackVulnerability -Category Software
    if ($vulnInstalledSoftware) {
        Write-Host "The following installed software has known vulnerabilities:"
        $vulnInstalledSoftware | Select-Object Name, Severity, VulnerabilityID, Url | Format-Table -AutoSize
    } else {
        Write-Host "No vulnerabilities found in installed software."
    }

    # Scan for open ports and services
    Write-Host "Scanning for open ports and services..."
    $openPorts = Test-NetConnection -InformationLevel Quiet -ComputerName localhost -Port 1,3,7,9,13,17,19,21,22,23,25,37,53,79,80,88,106,110,113,119,123,135,137,138,139,143,161,162,389,443,445,464,515,587,631,636,691,1433,1521,1701,1723,1900,2000,2049,2082,2083,2086,2087,2095,2096,2181,2222,2375,2376,3389,4443

# Function to perform system security checks
function Test-SystemSecurity {
    [CmdletBinding()]
    param()

    $results = @()

    # Windows updates
    $windowsUpdates = Get-WindowsUpdate -IsInstalled | Where-Object -Property IsInstalled -EQ -Value $true | Select-Object -Property Title, Description, InstalledOn | Sort-Object -Property InstalledOn | Select-Object -First 10
    if ($windowsUpdates) {
        $windowsUpdatesStatus = "Not up to date"
    } else {
        $windowsUpdatesStatus = "Up to date"
    }
    $results += [pscustomobject]@{
        Check = "Windows updates"
        Result = $windowsUpdatesStatus
    }

    # Antivirus status
    $antivirusStatus = Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct | Select-Object -Property displayName, productState | Sort-Object -Property displayName
    if ($antivirusStatus) {
        $antivirusEnabled = $antivirusStatus | Where-Object -Property productState -Match -Value "^397"
        if ($antivirusEnabled) {
            $antivirusStatus = "Enabled"
        } else {
            $antivirusStatus = "Disabled"
        }
    } else {
        $antivirusStatus = "Not found"
    }
    $results += [pscustomobject]@{
        Check = "Antivirus status"
        Result = $antivirusStatus
    }

    # Firewall status
    $firewallStatus = Get-NetFirewallProfile | Select-Object -Property Name, Enabled | Sort-Object -Property Name
    if ($firewallStatus) {
        $firewallEnabled = $firewallStatus | Where-Object -Property Enabled -EQ -Value True
        if ($firewallEnabled) {
            $firewallStatus = "Enabled"
        } else {
            $firewallStatus = "Disabled"
        }
    } else {
        $firewallStatus = "Not found"
    }
    $results += [pscustomobject]@{
        Check = "Firewall status"
        Result = $firewallStatus
    }

    # Open ports
    $openPorts = Test-NetConnection -ComputerName $env:COMPUTERNAME | Where-Object -Property TcpTestSucceeded -EQ -Value True | Select-Object -Property ComputerName, RemotePort | Sort-Object -Property RemotePort | Select-Object -First 10
    if ($openPorts) {
        $openPortsStatus = "Found"
    } else {
        $openPortsStatus = "None found"
    }
    $results += [pscustomobject]@{
        Check = "Open ports"
        Result = $openPortsStatus
    }

    # Weak passwords
    $weakPasswords = Get-LocalUser | Where-Object -Property PasswordNeverExpires -EQ -Value False | Where-Object -Property PasswordLastSet -NE -Value $null | Select-Object -Property Name, PasswordLastSet | Sort-Object -Property PasswordLastSet | Select-Object -First 10
    if ($weakPasswords) {
        $weakPasswordsStatus = "Found"
    } else {
        $weakPasswordsStatus = "None found"
    }
    $results += [pscustomobject]@{
        Check = "Weak passwords"
        Result = $weakPasswordsStatus
    }

     # Admin rights
    $adminRights = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($adminRights) {
        $adminRightsStatus = "Enabled"
    } else {
        $adminRightsStatus = "Not enabled"
    }
    $results += [pscustomobject]@{
        Check = "Admin rights"
        Result = $adminRightsStatus
    }

    # Unauthorized access
    $unauthorizedAccess = Get-EventLog -LogName Security -InstanceId 4625 -Newest 1 -ErrorAction SilentlyContinue
    if ($unauthorizedAccess) {
        $unauthorizedAccessStatus = "Found"
    } else {
    $unauthorizedAccessStatus = "None found"
    }
    $results += [pscustomobject]@{
        Check = "Unauthorized access"
        Result = $unauthorizedAccessStatus
    }

    # Suspicious processes
    $suspiciousProcesses = Get-Process | Where-Object { $_.Path -eq $null -and $_.SessionId -eq 0 } | Select-Object -Property Name, ProcessName, Id
    if ($suspiciousProcesses) {
        $suspiciousProcessesStatus = "Found"
    } else {
        $suspiciousProcessesStatus = "None found"
    }

    $results = [pscustomobject]@{
        Check = "System security checks"
        Result = $null
    } | Select-Object Check, Result

    $results += [pscustomobject]@{
        Check = "Windows updates"
        Result = $windowsUpdatesStatus
    }

    $results += [pscustomobject]@{
        Check = "Antivirus status"
        Result = $antivirusStatus
    }

    $results += [pscustomobject]@{
        Check = "Firewall status"
        Result = $firewallStatus
    }

    $results += [pscustomobject]@{
        Check = "Open ports"
        Result = $openPortsStatus
    }

    $results += [pscustomobject]@{
        Check = "Weak passwords"
        Result = $weakPasswordsStatus
    }

    $results += [pscustomobject]@{
        Check = "Outdated software"
        Result = $outdatedSoftwareStatus
    }

    $results += [pscustomobject]@{
        Check = "Admin rights"
        Result = $adminRightsStatus
    }

    $results += [pscustomobject]@{
        Check = "Unauthorized access"
        Result = $unauthorizedAccessStatus
    }

    $results += [pscustomobject]@{
        Check = "Suspicious processes"
        Result = $suspiciousProcessesStatus
    }

    $results | Format-Table -AutoSize
