Sure! Here's a basic README file for your PowerShell script:

# Network Toolbox PowerShell script

The Network Toolbox PowerShell script is a collection of functions that can be used to manage and troubleshoot network connections on a Windows machine.

## Usage

To use the script, simply open PowerShell and run the script using the command:

```
.\Network-Toolbox.ps1
```

This will load all of the functions into the PowerShell session, making them available for use.

Each function in the script is designed to perform a specific network-related task. To use a function, simply call it by name, passing in any required parameters. For example:

```
Test-HostPing -Host google.com
```

This will ping the host "google.com" and return the results.

## Functions

The following functions are included in the script:

- Test-HostPing: Pings a specified host and returns the results.
- Resolve-HostName: Resolves a hostname to an IP address.
- Resolve-IPAddress: Resolves an IP address to a hostname.
- Get-DnsRecord: Queries DNS records for a specified domain.
- Get-NetworkInterface: Gets information about network interfaces.
- Set-NetworkInterfaceStatus: Enables or disables a network interface.
- Get-RoutingTable: Displays the routing table for the machine.
- Get-NetworkConnections: Displays information about established network connections.
- Test-NetworkBandwidth: Tests the network bandwidth between two hosts.
- Set-IPAddress: Sets the IP address and related network settings for a specified interface.
- Test-MultipleHosts: Pings multiple hosts and returns the results.
- New-NetworkShare: Creates a new network share.
- Remove-NetworkShare: Removes an existing network share.
- Get-FileServerSessions: Displays information about sessions connected to a file server.
- Get-OpenFiles: Displays information about files currently open on a file server.
- Test-RemotePort: Tests if a remote port is open.
- Get-NetworkSpeed: Gets the current speed and duplex settings for a network interface.
- Set-NetworkSpeed: Sets the speed and duplex settings for a network interface.
- Get-WiFiNetworks: Displays information about nearby WiFi networks.
- Get-NetworkRoutes: Displays information about network routes.
- Add-NetworkRoute: Adds a new network route.
- Remove-NetworkRoute: Removes an existing network route.
- Get-NetworkShares: Displays information about network shares on a remote machine.
- Test-RemoteManagement: Tests if remote management is available on a remote machine.
- Invoke-RemoteCommand: Runs a command on a remote machine.
- New-VirtualSwitch: Creates a new virtual network switch.
- Remove-VirtualSwitch: Removes an existing virtual network switch.
- Get-NetworkProfiles: Displays information about network profiles.
- Set-NetworkProfile: Sets the network profile for a specific interface.

## Requirements

The Network Toolbox PowerShell script requires PowerShell version 5.0 or later, and it has been tested on Windows 10 and Windows Server 2016.

## Disclaimer

This script is provided as-is, with no warranty or support. Use at your own risk. The author is not responsible for any damages or losses that may occur from the use of this script.
