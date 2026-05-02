/*
    VAXINX Default YARA Rules
    Educational defensive rules only.
    Add your own .yar files to the rules/ directory — all are loaded automatically.
*/

rule SuspiciousPowerShellEncoded
{
    meta:
        description = "Detects base64-encoded PowerShell execution patterns"
        severity    = "HIGH"
        family      = "Script"
    strings:
        $enc1 = "EncodedCommand" nocase
        $enc2 = "FromBase64String" nocase
        $enc3 = "powershell" nocase
        $iex  = "IEX" nocase
        $iex2 = "Invoke-Expression" nocase
    condition:
        ($enc3 and ($enc1 or $enc2)) or ($iex or $iex2)
}

rule RansomwareKeywords
{
    meta:
        description = "Common ransomware note and behavior keywords"
        severity    = "CRITICAL"
        family      = "Ransomware"
    strings:
        $r1 = "your files have been encrypted" nocase
        $r2 = "send bitcoin" nocase
        $r3 = "pay ransom" nocase
        $r4 = "decrypt your files" nocase
        $r5 = "CryptEncrypt" nocase
        $r6 = "CryptGenRandom" nocase
        $r7 = "VirtualProtect" nocase
        $r8 = ".locked" nocase
        $r9 = ".encrypted" nocase
    condition:
        2 of them
}

rule SuspiciousNetworkActivity
{
    meta:
        description = "Indicators of suspicious outbound network calls in scripts"
        severity    = "HIGH"
        family      = "Downloader"
    strings:
        $n1 = "WebClient" nocase
        $n2 = "DownloadString" nocase
        $n3 = "DownloadFile" nocase
        $n4 = "Invoke-WebRequest" nocase
        $n5 = "Net.WebClient" nocase
        $n6 = "curl " nocase
        $n7 = "wget " nocase
        $n8 = "certutil" nocase
    condition:
        2 of them
}

rule ShellcodePatterns
{
    meta:
        description = "Shellcode-like byte sequences — NOP sleds, common prologues"
        severity    = "CRITICAL"
        family      = "Shellcode"
    strings:
        $nop_sled   = { 90 90 90 90 90 90 90 90 }
        $int3_chain = { CC CC CC CC CC CC CC CC }
        $call_pop   = { E8 00 00 00 00 5? }
    condition:
        any of them
}

rule MaliciousMacroIndicators
{
    meta:
        description = "VBA macro patterns used in malicious Office documents"
        severity    = "HIGH"
        family      = "MacroMalware"
    strings:
        $m1 = "AutoOpen" nocase
        $m2 = "Auto_Open" nocase
        $m3 = "Document_Open" nocase
        $m4 = "Shell(" nocase
        $m5 = "WScript.Shell" nocase
        $m6 = "CreateObject" nocase
        $m7 = "environ(" nocase
    condition:
        ($m1 or $m2 or $m3) and ($m4 or $m5 or $m6)
}

rule SuspiciousRegistryPersistence
{
    meta:
        description = "Registry keys commonly used for malware persistence"
        severity    = "HIGH"
        family      = "Persistence"
    strings:
        $r1 = "CurrentVersion\\Run" nocase
        $r2 = "CurrentVersion\\RunOnce" nocase
        $r3 = "reg add" nocase
        $r4 = "HKEY_CURRENT_USER" nocase
        $r5 = "HKCU" nocase
        $r6 = "schtasks" nocase
        $r7 = "at.exe" nocase
    condition:
        ($r3 or $r6 or $r7) and ($r1 or $r2 or $r4 or $r5)
}

rule CredentialHarvesting
{
    meta:
        description = "Patterns associated with credential dumping and harvesting"
        severity    = "CRITICAL"
        family      = "Spyware"
    strings:
        $c1 = "mimikatz" nocase
        $c2 = "sekurlsa" nocase
        $c3 = "lsass" nocase
        $c4 = "SAMDump" nocase
        $c5 = "hashdump" nocase
        $c6 = "GetPassword" nocase
        $c7 = "procdump" nocase
    condition:
        any of them
}

rule DisguisedExecutable
{
    meta:
        description = "Executable with misleading double extension"
        severity    = "HIGH"
        family      = "Trojan"
    strings:
        $d1 = ".pdf.exe" nocase
        $d2 = ".txt.exe" nocase
        $d3 = ".doc.exe" nocase
        $d4 = ".jpg.exe" nocase
        $d5 = ".mp3.exe" nocase
        $d6 = ".pdf.vbs" nocase
        $d7 = ".txt.vbs" nocase
    condition:
        any of them
}

rule SuspiciousBase64Blob
{
    meta:
        description = "Large base64-encoded blobs — often used to hide payloads"
        severity    = "MEDIUM"
        family      = "Obfuscation"
    strings:
        // Base64-encoded 'MZ' (PE header) — TVqQ
        $b64_pe = "TVqQAAMAAAAEAAAA" nocase
        // Very long base64 string (80+ chars of valid base64 chars)
        $b64_long = /[A-Za-z0-9+\/]{80,}={0,2}/
    condition:
        $b64_pe or (2 of ($b64_long))
}
