# Open issue 12: IPv6 outside the tunnel.
#
# The tunnel carries IPv4 only. Without this guard, a host with IPv6 can send IPv6 traffic around the
# tunnel. This script adds one Windows Firewall rule that blocks outbound IPv6 to the global unicast,
# unique-local, link-local and multicast ranges. IPv6 loopback (::1) is not in those ranges, so it keeps
# working. Windows Firewall gives block rules priority over allow rules, which is why the rule lists the
# ranges and does not block ::/0. Run from an elevated PowerShell (Run as administrator). It changes
# firewall rules only, not the network adapters.
#
#   .\ipv6_guard.ps1 -Enable     # add the block rule (idempotent)
#   .\ipv6_guard.ps1 -Disable    # remove it again
#   .\ipv6_guard.ps1 -Status     # show whether it is present (default when no switch is given)
#
# Side effect: link-local (fe80::/10) traffic is blocked too, so IPv6 neighbour discovery on the local
# link stops. The tunnel does not use IPv6, so this is intended.

[CmdletBinding()]
param(
    [switch]$Enable,
    [switch]$Disable,
    [switch]$Status
)

$ErrorActionPreference = 'Stop'
$ruleName = 'ioessa-block-ipv6-out'
$ranges = @('2000::/3', 'fc00::/7', 'fe80::/10', 'ff00::/8')

function Show-Status {
    $r = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if ($r) { "{0}: present, action {1}, enabled {2}" -f $ruleName, $r.Action, $r.Enabled }
    else { "{0}: not present" -f $ruleName }
}

if ($Disable) {
    Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    Show-Status
    return
}

if ($Enable) {
    if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -Action Block -Protocol Any `
            -RemoteAddress $ranges -Profile Any | Out-Null
    }
    Show-Status
    return
}

Show-Status
