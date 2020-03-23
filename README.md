# Collabfiltrator
Exfiltrate blind remote code execution output over DNS via Burp Collaborator.

#### Authors:
- <a href="https://twitter.com/adam_logue">Adam Logue</a>
- <a href="https://twitter.com/jared_mclaren">Jared McLaren</a>
- <a href="https://twitter.com/ninjastyle82">Frank Scarpella</a>

#### Requirements:
- Burp Suite Professional 1.7.x or Later
- <a href="https://www.jython.org/download.html">Jython 2.7.1</a>

#### Support:
[Installation in Burp Suite Professional](https://github.com/0xC01DF00D/Collabfiltrator/wiki/Installation-in-Burp-Suite-Professional)

[Blog Post](https://www.adamlogue.com/turning-blind-rce-into-good-rce-via-dns-exfiltration-using-collabfiltrator-burp-plugin/)

#### Currently Supported Platforms:

- Windows
- Linux

#### Usage:

Select a platform from the dropdown menu, enter the desired command, and press `Execute`. A payload will be generated for the platform you choose. Select `Copy Payload to Clipboard`, run the generated payload on your target, and wait for results to appear in the output window.

In case you get some garbage, sending a request to read that particular line(s) should get your job done. For example, if you get garbage on line 3-5 of /etc/passwd, you could then do;
```bash
tail -n+3 /etc/passwd|head -n3
```
and replace the garbage with newly received data.

<img src="https://i.imgur.com/tmRqfiY.png">
<img src="https://i.imgur.com/x1Rin8w.png">

If you liked this plugin, please consider donating:
```
BTC: 1GvMN6AAQ9WgGZpAX4SFVTi2xU7LgCXAh2
ETH: 0x847487DBcC6eC9b681a736BE763aca3cB8Debe49
Paypal: paypal.me/logueadam
```

