# Collabfiltrator
Exfiltrate blind remote code execution output over DNS via Burp Collaborator.

#### Version: 2.1

#### Authors:
- <a href="https://twitter.com/adam_logue">Adam Logue</a>
- <a href="https://twitter.com/jared_mclaren">Jared McLaren</a>
- <a href="https://twitter.com/ninjastyle82">Frank Scarpella</a>
- <a href="https://twitter.com/phurtim">Ryan Griffin</a>

#### Download Collabfiltrator from the <a href="https://portswigger.net/bappstore/fff2b36e392f49afbeb363403c07c6b8">Burp Suite BApp Store</a>

#### Requirements:
- Burp Suite Professional 1.7.x or Later
- <a href="https://www.jython.org/download.html">Jython 2.7.2</a>

#### Support:
[Installation in Burp Suite Professional](https://github.com/0xC01DF00D/Collabfiltrator/wiki/Installation-in-Burp-Suite-Professional)

[Blog Post](https://www.adamlogue.com/turning-blind-rce-into-good-rce-via-dns-exfiltration-using-collabfiltrator-burp-plugin/)

#### Supported Targets:

- Windows (powershell)
- Linux (sh + ping)

#### Usage:

Select a platform from the dropdown menu, enter the desired command, and press `Execute`. A payload will be generated for the platform you choose. Select `Copy Payload to Clipboard`, run the generated payload on your target, and wait for results to appear in the output window

<img src="https://i.imgur.com/iOAai5b.png">
<img src="https://i.imgur.com/3iGQpOS.png">

If you liked this plugin, please consider donating:
```
BTC: 1GvMN6AAQ9WgGZpAX4SFVTi2xU7LgCXAh2
ETH: 0x847487DBcC6eC9b681a736BE763aca3cB8Debe49
Paypal: paypal.me/logueadam
```

### Potential Ideas:
- Add Encryption?
- Add HTTP/HTTPS exfil support?
- More Choices of Exfil Bins (curl, wget, nslookup, dig, powershell, certutil, nc, ftp, etc.)

### Change Log:
2.1:
- Replaced the Linux exfil method with the enhanced Linux ping exfil command from [mr-mosi's fork](https://github.com/mr-mosi/Collabfiltrator). This payload been modified to work on systems running busybox and old sh shells.
- Added Dark Mode Compatibility.
- Fixed IDN 2008 error when hosts don't support punycode domains by setting "="" from "-"" to "EQLS".
- Added Burp 2021 GUI Compatibility so it doesn't look terrible.
- Added command output history to Extender tab.

2.0:
- Fixed dangling threads when unloading extension.
- Fixed dangling threads when execute button is pressed multiple times.
- Added "Stop Listener" button to manually stop listener instead of waiting for timeout.
- Removed 60 second timeout.
- Added printing of command executed to output box for better tracking.
- Added "Clear Output" Button for output box.
- Removed "E-F" suffix from subdomain string during exfiltration

1.0:
- Initial Release.
