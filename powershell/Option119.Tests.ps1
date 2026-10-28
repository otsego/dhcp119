$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Option119.ps1')

$failures = 0

function Assert-Equal {
    param($Actual, $Expected, [string] $Message)

    if ($Actual -cne $Expected) {
        $script:failures++
        Write-Host "FAIL: $Message`n  expected: $Expected`n  actual:   $Actual" -ForegroundColor Red
    }
}

function Assert-Throws {
    param([scriptblock] $Script, [string] $Message)

    try {
        & $Script | Out-Null
        $script:failures++
        Write-Host "FAIL: $Message did not throw" -ForegroundColor Red
    }
    catch {}
}

$output = ConvertTo-Option119 -Domain 'google.com', 'yahoo.com'
Assert-Equal $output.Mikrotik "0x06'google'0x03'com'0x0005'yahoo'0xC007" 'Mikrotik encoding'
Assert-Equal $output.Hex '06676F6F676C6503636F6D00057961686F6FC007' 'hex encoding'
Assert-Equal $output.Systemd '\x06google\x03com\x00\x05yahoo\xC0\x07' 'systemd encoding'
Assert-Equal (ConvertTo-Option119 -Domain 'mydomain.home users.mydomain.home remote.users.mydomain.home').SpacedHex `
    '08 6D 79 64 6F 6D 61 69 6E 04 68 6F 6D 65 00 05 75 73 65 72 73 C0 00 06 72 65 6D 6F 74 65 C0 0F' 'back pointers'
Assert-Equal (ConvertTo-Option119 -Domain '555.google.com').Mikrotik "0x03s'555'0x06'google'0x03'com'0x00" 'numeric Mikrotik label'
Assert-Equal (ConvertTo-Option119 -Domain ' Google.com.  yahoo.com ').Hex '06676F6F676C6503636F6D00057961686F6FC007' 'input normalization'

$cases = @(
    'google.com telegraph.co.uk',
    'mydomain.home users.mydomain.home remote.users.mydomain.home',
    'remote.users.mydomain.home users.mydomain.home mydomain.home',
    'services.myhome.me devices.myhome.me myhome.me something-else.com',
    'google.com 0.google.com 555.yahoo.com'
)
foreach ($case in $cases) {
    $encoded = ConvertTo-Option119 -Domain $case
    foreach ($format in 'Mikrotik', 'Cisco', 'Hex', 'SpacedHex', 'Systemd') {
        Assert-Equal (ConvertFrom-Option119 $encoded.$format) $case "$format round trip: $case"
    }
}

Assert-Equal (ConvertFrom-Option119 "0x02s'65'0x06'google'0x03'com'0x00") '65.google.com' 'Mikrotik string literal'
Assert-Equal (ConvertFrom-Option119 "0x01'65'0x06'google'0x03'com'0x00") 'A.google.com' 'Mikrotik decimal literal'
Assert-Equal (ConvertFrom-Option119 "0x06'google'0x03'com'0x000579'97.104.111.111'0xC007") 'google.com yahoo.com' 'Mikrotik IP literal'
Assert-Equal (ConvertFrom-Option119 '\003com\000') 'com' 'C-string octal escapes'

Assert-Throws { ConvertTo-Option119 -Domain 'google.com..' } 'multiple trailing dots'
Assert-Throws { ConvertTo-Option119 -Domain 'bad..example' } 'empty segment'
Assert-Throws { ConvertTo-Option119 -Domain (('a' * 64) + '.com') } 'long label'
Assert-Throws { ConvertFrom-Option119Bytes @(3, 99, 111, 109, 192, 0, 0) } 'circular pointer'
Assert-Throws { ConvertFrom-Option119Bytes @(4, 116, 101, 115, 116, 192, 7, 3, 99, 111, 109, 0) } 'forward pointer'
Assert-Throws { ConvertFrom-Option119Bytes @(4, 116, 101, 115, 116, 3, 99, 111, 109) } 'missing end marker'
Assert-Throws { ConvertFrom-Option119Bytes @(3, 65, 66, 67, 4, 65, 66, 67) } 'read past end'
foreach ($bad in '0', '000', '   00 00 0 00', '.00.0.00') {
    Assert-Throws { ConvertFrom-Option119Hex $bad } "odd hex input '$bad'"
}

if ($failures -gt 0) {
    Write-Host "$failures test(s) failed." -ForegroundColor Red
    exit 1
}

Write-Host 'All PowerShell tests passed.' -ForegroundColor Green
