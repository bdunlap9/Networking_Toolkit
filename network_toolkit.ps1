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
