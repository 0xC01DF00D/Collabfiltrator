package burp;

import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.collaborator.InteractionFilter;
import burp.api.montoya.logging.Logging;
import com.google.common.io.BaseEncoding;

import javax.swing.*;
import java.util.*;
import java.util.stream.Collectors;

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
                        
                        logging.logToOutput("Raw DNS query: " + interaction.dnsDetails().get().query());
                        
                        byte[] queryBytes = interaction.dnsDetails().get().query().getBytes();
                        logging.logToOutput("Processing query with length: " + queryBytes.length);
                        
                        int currentIndex = 12;
                        if (currentIndex >= queryBytes.length) {
                            continue;
                        }

                        StringBuilder preamble = new StringBuilder();
                        int preambleLength = queryBytes[currentIndex] & 0xFF;
                        currentIndex++;
                        
                        if (currentIndex + preambleLength > queryBytes.length) {
                            continue;
                        }
                        
                        for (int i = 0; i < preambleLength; i++) {
                            preamble.append((char)queryBytes[currentIndex + i]);
                        }
                        currentIndex += preambleLength;

                        StringBuilder dataChunk = new StringBuilder();
                        if (currentIndex >= queryBytes.length) {
                            continue;
                        }
                        
                        int dataLength = queryBytes[currentIndex] & 0xFF;
                        currentIndex++;
                        
                        if (currentIndex + dataLength > queryBytes.length) {
                            continue;
                        }
                        
                        for (int i = 0; i < dataLength; i++) {
                            dataChunk.append((char)queryBytes[currentIndex + i]);
                        }
                        
                        logging.logToOutput(String.format("Extracted - Preamble: %s, Data: %s", 
                            preamble.toString(), dataChunk.toString()));
                        
                        String cleanPreamble = preamble.toString().trim();
                        String cleanData = dataChunk.toString().trim();
                        
                        if (!cleanPreamble.isEmpty() && !cleanData.isEmpty()) {
                            dnsRecordDict.put(cleanPreamble, cleanData);
                        }
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
        
        // Filter and sort only numeric keys
        List<Map.Entry<String, String>> sortedEntries = dnsRecordDict.entrySet().stream()
            .filter(entry -> entry.getKey().matches("\\d+"))
            .sorted((a, b) -> Integer.parseInt(a.getKey()) - Integer.parseInt(b.getKey()))
            .collect(Collectors.toList());
        
        // Clean and concatenate hex data
        for (Map.Entry<String, String> entry : sortedEntries) {
            String hexValue = entry.getValue()
                .replaceAll("[^0-9A-Fa-f]", "") // Remove non-hex characters
                .replaceAll("k.*$", "") // Remove any trailing non-hex data
                .trim();
            if (!hexValue.isEmpty()) {
                output.append(hexValue);
            }
        }
        
        try {
            String hexString = output.toString();
            logging.logToOutput("Attempting to decode hex string: " + hexString);
            
            byte[] decoded = BaseEncoding.base16().decode(hexString.toUpperCase());
            String result = new String(decoded);
            
            rcePanel.getRceOutputTxt().append("Command: " + rcePanel.getCommandTxt().getText() + "\n");
            rcePanel.getRceOutputTxt().append("Exfiltrated Data:\n" + result + "\n\n");
            rcePanel.getRceOutputTxt().setCaretPosition(rcePanel.getRceOutputTxt().getDocument().getLength());
            
            logging.logToOutput("Collaborator Domain: " + collaboratorPayload);
            logging.logToOutput("Command: " + rcePanel.getCommandTxt().getText());
            logging.logToOutput("Output:\n" + result + "\n");
            
        } catch (IllegalArgumentException e) {
            logging.logToError("Error decoding hex output: " + e.getMessage());
            logging.logToError("Problematic hex string: " + output.toString());
            SwingUtilities.invokeLater(() -> {
                rcePanel.getRceOutputTxt().append("Error: Failed to decode output. See extension logs for details.\n");
            });
        }
    }
}