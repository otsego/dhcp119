# DHCP Domain Search List (Option 119) Encoder

[Use the tool here](https://jjjordan.github.io/dhcp119/)

Here's an encoder for DHCP Option 119, which sends domain search lists to
clients.  Many DHCP server implementations do not encode this option for
you, instead expecting the administrator to do it.  This repo provides a
quick, browser-based encoder so you don't need to roll your own script or
even fire up Powershell/Python.

## Command-line versions

### Python for Linux and macOS

Requires Python 3.7 or newer and has no third-party dependencies.

```sh
chmod +x python/option119.py
./python/option119.py encode example.com corp.example.com
./python/option119.py encode example.com --format mikrotik
./python/option119.py decode "0x07'example'0x03'com'0x00"
python3 -m unittest discover -s python
```

### PowerShell for Windows

Works with Windows PowerShell 5.1 and PowerShell 7.

```powershell
.\powershell\Option119.ps1 -Domain example.com, corp.example.com
.\powershell\Option119.ps1 -Domain example.com -Format Mikrotik
.\powershell\Option119.ps1 -Decode "0x07'example'0x03'com'0x00"
.\powershell\Option119.Tests.ps1
```

Both versions output Mikrotik RouterOS, Cisco IOS, hex, spaced hex, and
systemd-networkd values. Decoding auto-detects those formats.

## References

Here are some references that helped to build this:
* A [blog post](https://www.medo64.com/2017/04/adding-domain-search-option-to-mikrotik-dhcp/) describing the process to add this option to Mikrotik RouterOS.
* Another [blog post](https://blog.pessoft.com/2016/03/17/domain-search-list-as-dhcp-option-in-mikrotik-routeros/)
* A useful [post on the Mikrotik forums](https://forum.mikrotik.com/viewtopic.php?t=133801)
* A similar [python script](https://gist.github.com/SmartFinn/be417c7a7e0b3d9bee9c29e74d08ff78) (that lacks back-pointers)

The RFC's:
* 3397 [Dynamic Host Configuration Protocol (DHCP) Domain Search Option](https://tools.ietf.org/html/rfc3397)
* 1035 [DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION S 4.1.4 Message compression](https://tools.ietf.org/html/rfc1035#section-4.1.4)

The code here is licensed under GPL v3+.
