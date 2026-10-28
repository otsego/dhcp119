<#
.SYNOPSIS
Encodes or decodes DHCP Option 119 (domain search list) values.

.DESCRIPTION
Windows PowerShell port of the browser-based DHCP Option 119 encoder.
Encoding supports Mikrotik RouterOS, Cisco IOS, hexadecimal, spaced hexadecimal,
and systemd-networkd C-string formats. Decoding auto-detects those formats.

Option119.ps1 - DHCP Option 119 encoder/decoder for Windows PowerShell
Copyright (C) 2020 John J. Jordan
Licensed under the GNU General Public License v3 or later.

.EXAMPLE
.\Option119.ps1 -Domain example.com, corp.example.com

.EXAMPLE
.\Option119.ps1 -Domain example.com -Format Mikrotik

.EXAMPLE
.\Option119.ps1 -Decode "0x07'example'0x03'com'0x00"
#>
[CmdletBinding(DefaultParameterSetName = 'Library')]
param(
    [Parameter(ParameterSetName = 'Encode', Mandatory = $true, Position = 0, ValueFromRemainingArguments = $true)]
    [string[]] $Domain,

    [Parameter(ParameterSetName = 'Encode')]
    [ValidateSet('All', 'Mikrotik', 'Cisco', 'Hex', 'SpacedHex', 'Systemd')]
    [string] $Format = 'All',

    [Parameter(ParameterSetName = 'Decode', Mandatory = $true)]
    [string] $Decode
)

Set-StrictMode -Version 2.0

function Split-Option119Input {
    param([string[]] $Value)

    $result = @()
    foreach ($item in $Value) {
        $result += @($item.ToLowerInvariant() -split '[\s,]+' | Where-Object { $_.Length -gt 0 })
    }
    return $result
}

function ConvertTo-Option119Encoded {
    param([Parameter(Mandatory = $true)][string[]] $Domains)

    $refs = @{}
    $result = New-Object System.Collections.Generic.List[object]

    foreach ($entry in $Domains) {
        $name = $entry.ToLowerInvariant()
        if ($name -match '[^\x00-\x7F]') { throw 'Domain names must be ASCII; use punycode for IDNs' }
        if ($name.EndsWith('..')) { throw 'Domain cannot end with multiple periods' }
        if ($name.EndsWith('.')) { $name = $name.Substring(0, $name.Length - 1) }
        if ($name.Length -eq 0) { throw 'Empty domain' }

        $branched = $false
        $t = 0
        while ($t -lt $name.Length) {
            $subdomain = $name.Substring($t)
            if ($refs.ContainsKey($subdomain)) {
                $ptr = 0xC000 -bor [int] $refs[$subdomain]
                $result.Add([int] (($ptr -shr 8) -band 0xFF))
                $result.Add([int] ($ptr -band 0xFF))
                $branched = $true
                break
            }

            if ($result.Count -le 0x3FFF) { $refs[$subdomain] = $result.Count }

            $dot = $name.IndexOf('.', $t)
            if ($dot -lt 0) { $dot = $name.Length }
            if ($dot -eq $t) { throw 'Empty segment' }
            if (($dot - $t) -gt 63) { throw 'Domain label cannot exceed 63 characters' }

            $result.Add([int] ($dot - $t))
            foreach ($char in $name.Substring($t, $dot - $t).ToCharArray()) { $result.Add($char) }
            $t = $dot + 1
        }

        if (-not $branched) { $result.Add([int] 0) }
    }

    return , $result.ToArray()
}

function Get-Option119OctetHex {
    param($Value)

    if ($Value -is [char]) { $Value = [int] $Value }
    return ([int] $Value).ToString('X2')
}

function ConvertTo-Option119Mikrotik {
    param([object[]] $Encoded)

    $builder = New-Object System.Text.StringBuilder
    $i = 0
    while ($i -lt $Encoded.Count) {
        if ($Encoded[$i] -is [char]) {
            $segment = New-Object System.Text.StringBuilder
            while ($i -lt $Encoded.Count -and $Encoded[$i] -is [char]) {
                [void] $segment.Append($Encoded[$i])
                $i++
            }
            $text = $segment.ToString()
            if ($text -match '^[0-9]+$') { [void] $builder.Append('s') }
            [void] $builder.Append("'$text'")
        }
        else {
            [void] $builder.Append('0x')
            while ($i -lt $Encoded.Count -and -not ($Encoded[$i] -is [char])) {
                [void] $builder.Append((Get-Option119OctetHex $Encoded[$i]))
                $i++
            }
        }
    }
    return $builder.ToString()
}

function ConvertTo-Option119Hex {
    param([object[]] $Encoded, [string] $Separator = '')

    return (($Encoded | ForEach-Object { Get-Option119OctetHex $_ }) -join $Separator)
}

function ConvertTo-Option119Cisco {
    param([object[]] $Encoded)

    $builder = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $Encoded.Count; $i++) {
        if ($i -gt 0 -and $i % 2 -eq 0) { [void] $builder.Append('.') }
        [void] $builder.Append((Get-Option119OctetHex $Encoded[$i]))
    }
    return $builder.ToString()
}

function ConvertTo-Option119CString {
    param([object[]] $Encoded)

    $builder = New-Object System.Text.StringBuilder
    foreach ($value in $Encoded) {
        if ($value -is [char]) { [void] $builder.Append($value) }
        else { [void] $builder.Append('\x').Append((Get-Option119OctetHex $value)) }
    }
    return $builder.ToString()
}

function ConvertTo-Option119 {
    param([Parameter(Mandatory = $true)][string[]] $Domain)

    $domains = @(Split-Option119Input $Domain)
    if ($domains.Count -eq 0) { throw 'Empty input' }
    $encoded = ConvertTo-Option119Encoded $domains

    [pscustomobject] @{
        Mikrotik  = ConvertTo-Option119Mikrotik $encoded
        Cisco     = ConvertTo-Option119Cisco $encoded
        Hex       = ConvertTo-Option119Hex $encoded
        SpacedHex = ConvertTo-Option119Hex $encoded ' '
        Systemd   = ConvertTo-Option119CString $encoded
    }
}

function Read-Option119Segment {
    param([int[]] $Data, [int] $Index)

    $value = $Data[$Index]
    if ($value -eq 0) { return @{ Kind = 'End'; Next = $Index + 1 } }
    if (($value -band 0xC0) -eq 0xC0) {
        if ($Index + 1 -ge $Data.Count) { throw 'Pointer extends beyond end of input' }
        return @{ Kind = 'Pointer'; Next = $Index + 2; Pointer = ((($value -band 0x3F) -shl 8) -bor $Data[$Index + 1]) }
    }
    if (($value -band 0xC0) -ne 0) { throw 'Bad start byte' }
    if ($Index + $value -ge $Data.Count) { throw 'Segment extends beyond end of input' }

    $chars = for ($i = $Index + 1; $i -le $Index + $value; $i++) { [char] $Data[$i] }
    return @{ Kind = 'Text'; Next = $Index + $value + 1; Text = (-join $chars) }
}

function Read-Option119Name {
    param([int[]] $Data, [int] $Index)

    $labels = New-Object System.Collections.Generic.List[string]
    $i = $Index
    while ($i -lt $Data.Count) {
        $segment = Read-Option119Segment $Data $i
        if ($segment.Kind -eq 'End') { return @{ Name = ($labels -join '.'); Next = $segment.Next } }
        if ($segment.Kind -eq 'Text') {
            $labels.Add($segment.Text)
            $i = $segment.Next
            continue
        }
        if ($segment.Pointer -ge $Index) { throw 'Invalid forward or circular reference' }
        $labels.Add((Read-Option119Name $Data $segment.Pointer).Name)
        return @{ Name = ($labels -join '.'); Next = $segment.Next }
    }
    throw 'Missing END marker'
}

function ConvertFrom-Option119Bytes {
    param([int[]] $Data)

    $names = New-Object System.Collections.Generic.List[string]
    $i = 0
    while ($i -lt $Data.Count) {
        $name = Read-Option119Name $Data $i
        $names.Add($name.Name)
        $i = $name.Next
    }
    return ($names -join ' ')
}

function Test-Option119Hex {
    param([string] $Value)
    return $Value -match '^[0-9A-Fa-f]+$'
}

function ConvertFrom-Option119Hex {
    param([string] $Value)

    $result = New-Object System.Collections.Generic.List[int]
    $i = 0
    while ($i -lt $Value.Length) {
        if (" .;:`t`r`n".IndexOf($Value[$i]) -ge 0) { $i++; continue }
        if ($i -eq $Value.Length - 1) { throw 'Need an even number of hex digits' }
        $octet = $Value.Substring($i, 2)
        if (-not (Test-Option119Hex $octet)) { throw 'Unexpected hex character' }
        $result.Add([Convert]::ToInt32($octet, 16))
        $i += 2
    }
    return , $result.ToArray()
}

function ConvertFrom-Option119Mikrotik {
    param([string] $Value)

    $result = New-Object System.Collections.Generic.List[int]
    $i = 0
    while ($i -lt $Value.Length) {
        if ([char]::IsWhiteSpace($Value[$i])) { $i++; continue }

        $prefix = if ($i + 1 -lt $Value.Length) { $Value.Substring($i, 2).ToLowerInvariant() } else { '' }
        if ($prefix -eq "s'") {
            $end = $Value.IndexOf("'", $i + 2)
            if ($end -lt 0) { throw 'Unterminated string' }
            foreach ($char in $Value.Substring($i + 2, $end - $i - 2).ToCharArray()) { $result.Add([int] $char) }
            $i = $end + 1
        }
        elseif ($Value[$i] -eq "'") {
            $end = $Value.IndexOf("'", $i + 1)
            if ($end -lt 0) { throw 'Unterminated string' }
            $contents = $Value.Substring($i + 1, $end - $i - 1)
            if ($contents -match '^[0-9]+$') {
                $number = [int] $contents
                if ($number -gt 255) { throw 'Numeric literal must be between 0 and 255' }
                $result.Add($number)
            }
            elseif ($contents -match '^([0-9]{1,3}\.){3}[0-9]{1,3}$') {
                foreach ($part in $contents.Split('.')) {
                    $octet = [int] $part
                    if ($octet -gt 255) { throw 'Invalid IP address literal' }
                    $result.Add($octet)
                }
            }
            else {
                foreach ($char in $contents.ToCharArray()) { $result.Add([int] $char) }
            }
            $i = $end + 1
        }
        elseif ($prefix -eq '0x') {
            $i += 2
            $start = $i
            while ($i + 1 -lt $Value.Length -and (Test-Option119Hex $Value.Substring($i, 2))) {
                $result.Add([Convert]::ToInt32($Value.Substring($i, 2), 16))
                $i += 2
            }
            if ($i -eq $start -or ($i -lt $Value.Length -and (Test-Option119Hex ([string] $Value[$i])))) {
                throw 'Invalid hex sequence'
            }
        }
        else {
            throw 'Unexpected input'
        }
    }
    return , $result.ToArray()
}

function ConvertFrom-Option119CString {
    param([string] $Value)

    $result = New-Object System.Collections.Generic.List[int]
    $i = 0
    while ($i -lt $Value.Length) {
        if ($Value[$i] -ne '\') {
            $result.Add([int] $Value[$i])
            $i++
            continue
        }

        if ($i + 1 -lt $Value.Length -and $Value[$i + 1] -ceq 'x') {
            if ($i + 4 -gt $Value.Length -or -not (Test-Option119Hex $Value.Substring($i + 2, 2))) {
                throw 'Invalid hex escape in C string'
            }
            $result.Add([Convert]::ToInt32($Value.Substring($i + 2, 2), 16))
            $i += 4
            continue
        }

        $match = [regex]::Match($Value.Substring($i + 1), '^[0-7]{1,3}')
        if (-not $match.Success) { throw 'Unsupported escape code in C string' }
        $number = [Convert]::ToInt32($match.Value, 8)
        if ($number -gt 255) { throw 'Octal escape must be between 0 and 377' }
        $result.Add($number)
        $i += $match.Length + 1
    }
    return , $result.ToArray()
}

function ConvertFrom-Option119 {
    param([Parameter(Mandatory = $true)][string] $Value)

    $Value = $Value.Trim()
    if ($Value.Contains('\')) { $data = ConvertFrom-Option119CString $Value }
    elseif ($Value.ToLowerInvariant().Contains('0x') -or $Value.Contains("'")) { $data = ConvertFrom-Option119Mikrotik $Value }
    else { $data = ConvertFrom-Option119Hex $Value }

    return ConvertFrom-Option119Bytes $data
}

try {
    switch ($PSCmdlet.ParameterSetName) {
        'Encode' {
            $result = ConvertTo-Option119 -Domain $Domain
            if ($Format -eq 'All') { $result } else { $result.$Format }
        }
        'Decode' {
            ConvertFrom-Option119 -Value $Decode
        }
    }
}
catch {
    Write-Error $_.Exception.Message -ErrorAction Continue
    exit 1
}
