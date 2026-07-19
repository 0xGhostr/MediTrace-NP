"""
USB device detection — tries Windows WMI/PowerShell when available.
Falls back to session-tracked simulation state (no crash without pywin32).
"""
import json
import platform
import subprocess


def _run_powershell(script, timeout=8):
    try:
        result = subprocess.run(
            ['powershell', '-NoProfile', '-Command', script],
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
        )
        if result.returncode != 0 or not result.stdout.strip():
            return []
        return json.loads(result.stdout)
    except Exception:
        return []


def detect_usb_devices_windows():
    """Detect removable USB drives via PowerShell (no pywin32 required)."""
    script = r'''
$items = @()
Get-CimInstance Win32_DiskDrive | Where-Object {
    $_.InterfaceType -eq "USB" -or $_.PNPDeviceID -match "^USBSTOR\\"
} | ForEach-Object {
    $disk = $_
    $vendor = ""
    $product = ""
    if ($disk.PNPDeviceID -match "VID_([0-9A-Fa-f]{4})") { $vendor = $Matches[1].ToUpper() }
    if ($disk.PNPDeviceID -match "PID_([0-9A-Fa-f]{4})") { $product = $Matches[1].ToUpper() }
    $diskSerial = ($disk.SerialNumber | Out-String).Trim()
    $pnpSerial = (($disk.PNPDeviceID -split "\\")[-1] -replace "&0$", "").Trim()
    Get-CimAssociatedInstance -InputObject $disk -ResultClassName Win32_DiskPartition | ForEach-Object {
        Get-CimAssociatedInstance -InputObject $_ -ResultClassName Win32_LogicalDisk | ForEach-Object {
            $vol = $_
            $stableSerial = if ($diskSerial) {
                "WINUSB-" + ($diskSerial -replace "\s", "")
            } elseif ($pnpSerial) {
                "WINPNP-" + ($pnpSerial -replace "\s", "")
            } elseif ($vol.VolumeSerialNumber) {
                "WINVOL-" + $vol.VolumeSerialNumber
            } else { $null }
            if ($stableSerial) {
                $items += @{
                    usb_name = if ($vol.VolumeName) { $vol.VolumeName } elseif ($disk.Model) { $disk.Model } else { "Removable USB" }
                    usb_serial = $stableSerial
                    vendor_id = $vendor
                    product_id = $product
                    usb_size = if ($vol.Size) { [math]::Round($vol.Size / 1GB, 1).ToString() + "GB" } else { "" }
                    drive_letter = $vol.DeviceID
                }
            }
        }
    }
}
if ($items.Count -eq 0) {
    Get-CimInstance Win32_LogicalDisk -Filter "DriveType=2" | ForEach-Object {
        $vol = $_
        if ($vol.VolumeSerialNumber) {
            $items += @{
                usb_name = if ($vol.VolumeName) { $vol.VolumeName } else { "Removable USB" }
                usb_serial = "WINVOL-" + $vol.VolumeSerialNumber
                vendor_id = ""
                product_id = ""
                usb_size = if ($vol.Size) { [math]::Round($vol.Size / 1GB, 1).ToString() + "GB" } else { "" }
                drive_letter = $vol.DeviceID
            }
        }
    }
}
if ($items.Count -eq 0) { Write-Output "[]" } else { $items | ConvertTo-Json -Compress }
'''
    data = _run_powershell(script)
    if isinstance(data, dict):
        return [data]
    return data if isinstance(data, list) else []


def get_session_usb_devices(session):
    """Return USB devices stored in session (simulation / client-reported)."""
    devices = session.get('connected_usb_devices', [])
    return devices if isinstance(devices, list) else []


def detect_connected_usb(session=None):
    """
    Return list of connected USB device dicts.
    Priority: real Windows detection → session simulation state.
    """
    devices = []
    if platform.system() == 'Windows':
        devices = detect_usb_devices_windows()
    if not devices and session is not None:
        devices = get_session_usb_devices(session)
    return devices
