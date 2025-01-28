
# Collabfiltrator
Exfiltrate Blind Remote Code Execution and SQL injection output over DNS via Burp Collaborator.

#### Version: 4.0.1

#### Authors:
- <a href="https://twitter.com/adam_logue">Adam Logue</a>
- <a href="https://twitter.com/jared_mclaren">Jared McLaren</a>
- <a href="https://twitter.com/ninjastyle82">Frank Scarpella</a>
- <a href="https://twitter.com/phurtim">Ryan Griffin</a>

#### AI Authors:
- Claude 3.5 Sonnet
- ChatGPT 4o

#### Requirements:
- Burp Suite Professional 2024.12.1 or Later

#### Support:
[Building from Source](https://github.com/0xC01DF00D/Collabfiltrator/wiki/Building-from-Source)

[Installation in Burp Suite Professional](https://github.com/0xC01DF00D/Collabfiltrator/wiki/Installation-in-Burp-Suite-Professional)

[Original Blog Post](https://www.adamlogue.com/turning-blind-rce-into-good-rce-via-dns-exfiltration-using-collabfiltrator-burp-plugin/)

#### Supported RCE Targets:

- Windows (Powershell)
- Linux (sh + ping)
- Linux (sh + nslookup)
- Linux (bash + ping)
- Linux (bash + nslookup)

#### Supported SQLi Targets:
- Microsoft SQL Server (Stacked Queries)
- MySQL (Windows)
- PostgreSQL (Elevated Privileges)
- Oracle (Elevated Privileges)
- Oracle (XML External Entities)

#### RCE Exfiltration Usage:

Select a platform from the dropdown menu, enter the desired command, and press `Execute`. A payload will be generated for the chosen platform. Select `Copy Payload to Clipboard`, execute the generated payload on your target, and wait for results to appear in the output window.

<img src="https://i.imgur.com/CimnIGx.png">
<img src="https://i.imgur.com/jRX1jCI.png">

#### SQLi Exfiltration Usage:

Select a DBMS and extraction query type from the dropdown menu. Toggle between hex encoding output during DNS exfiltration (to preserve special characters, spaces, etc) or plaintext exfiltration, and press `Dump`. A payload will be generated for the chosen DBMS. Select `Copy Payload to Clipboard`, run the generated SQL query on your target, and wait for results to appear in the output window. Extracted "table" and "column" data will populate in subsequent "column" and "row" payloads.

<img src="https://i.imgur.com/55ptOSm.png">
<img src="https://i.imgur.com/qUVN7Mb.png">

If you liked this plugin, please consider donating:
```
BTC: 1GvMN6AAQ9WgGZpAX4SFVTi2xU7LgCXAh2
ETH: 0x847487DBcC6eC9b681a736BE763aca3cB8Debe49
Paypal: paypal.me/logueadam
```

### Change Log:
4.0.1:
- Merged the RCEMonitoringManager and SQLiMonitoringManager into a unified MonitoringManager that uses a single monitoring thread.
- Stop buttons no longer stop both RCE and SQLi monitoring threads simultaneously allowing simultaneous usage of RCE and SQLi exfiltration.
- Logging is now entirely performed through the Burp Montoya logging interface.
- Microsoft SQL Server Queries have been optimized for speed across large databases and no longer default to the 'master' table.
- Logging through the Burp Montoya logging interface in the "Extensions" tab now show raw DNS queries in a pretty "xxd" hex format.
- Monitoring Manager logic has been improved to filter out additional garbage DNS queries sent by databases, such as DNS queries containing only underscores.
- Improved logging in Burp Montoya logging interface.
- Improved README.md and pom.xml

4.0:
- Complete rewrite in native Java using Portswigger's Montoya API.
- Faster than the Legacy Jython Version.
- Introducing SQLi DNS exfiltration with payload support for Microsoft SQL Server (Stacked Queries), MySQL (Windows), PostgreSQL (Elevated Privileges), Oracle (Elevated Privileges), and Oracle (XXE).
- New info icon includes a mouseover modal that explains constraints of each payload.
- Exfiltrated SQLi table and column data automatically populates in subsequent column and row payloads.
- SQL injection payloads can be modified in the payload box before copying them to the clipboard.
- Ditched base64 encoding in favor of hex encoding.

3.0:
- This version was originally going to contain the SQLi DNS exfiltration functionality. However, it was never released because I decided halfway through the implementation to just rewrite the entire thing in native Java using Portswigger's Montoya API.

2.2:
- Fixed Burp 2024 issues with output not displaying.

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