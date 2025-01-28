package burp;

import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.collaborator.InteractionFilter;
import burp.api.montoya.logging.Logging;
import com.google.common.io.BaseEncoding;

import javax.swing.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

public class MonitoringManager {
    private final CollaboratorClient collaboratorClient;
    private final Logging logging;
    private Thread monitoringThread;
    private volatile boolean stopMonitoring;
    private final Map<String, MonitoringSession> activeSessions;
    
    public MonitoringManager(CollaboratorClient collaboratorClient, Logging logging) {
        this.collaboratorClient = collaboratorClient;
        this.logging = logging;
        this.activeSessions = new ConcurrentHashMap<>();
        startMonitoringThread();
    }
    
    private void startMonitoringThread() {
        stopMonitoring = false;
        monitoringThread = new Thread(() -> {
            try {
                while (!stopMonitoring && !Thread.currentThread().isInterrupted()) {
                    try {
                        Thread.sleep(1000);
                        
                        // Get all active collaborator payloads
                        Set<String> payloads = new HashSet<>(activeSessions.keySet());
                        
                        for (String payload : payloads) {
                            if (Thread.currentThread().isInterrupted()) {
                                break;
                            }
                            
                            MonitoringSession session = activeSessions.get(payload);
                            if (session != null && !session.isComplete()) {
                                try {
                                    List<Interaction> interactions = collaboratorClient.getInteractions(
                                        InteractionFilter.interactionPayloadFilter(payload)
                                    );
                                    
                                    if (!interactions.isEmpty()) {
                                        logging.logToOutput("Found " + interactions.size() + 
                                            " interactions for payload: " + payload);
                                    }
                                    
                                    // Process interactions for this session
                                    session.processInteractions(interactions);
                                    
                                    // Check if session is complete
                                    if (session.isComplete()) {
                                        logging.logToOutput("Session completed for payload: " + payload);
                                        cleanupSession(payload);
                                    }
                                } catch (Exception e) {
                                    logging.logToError("Error processing interactions for payload: " + 
                                        payload, e);
                                }
                            }
                        }
                        
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        logging.logToOutput("Monitoring thread stopping due to interrupt");
                        break;
                    } catch (Exception e) {
                        logging.logToError("Error in monitoring loop", e);
                    }
                }
            } finally {
                // Cleanup all sessions on thread termination
                logging.logToOutput("Monitoring thread shutting down - cleaning up sessions");
                Set<String> remainingSessions = new HashSet<>(activeSessions.keySet());
                for (String payload : remainingSessions) {
                    try {
                        MonitoringSession session = activeSessions.get(payload);
                        if (session != null) {
                            session.stop();
                            cleanupSession(payload);
                        }
                    } catch (Exception e) {
                        logging.logToError("Error cleaning up session during shutdown: " + payload, e);
                    }
                }
                logging.logToOutput("Monitoring thread shutdown complete");
            }
        });
        monitoringThread.setName("Collabfiltrator-Monitor");
        monitoringThread.start();
    }
    
    public void registerSession(String payload, MonitoringSession session) {
        if (payload == null || payload.trim().isEmpty()) {
            logging.logToError("Attempted to register session with null or empty payload");
            return;
        }
        
        activeSessions.put(payload, session);
        logging.logToOutput("Started monitoring session for payload: " + payload + 
            " (Active sessions: " + activeSessions.size() + ")");
    }
    
    public void stopSession(String payload) {
        MonitoringSession session = activeSessions.get(payload);
        if (session != null) {
            session.stop();
            cleanupSession(payload);
        }
    }
    
    private void cleanupSession(String payload) {
        MonitoringSession removed = activeSessions.remove(payload);
        if (removed != null) {
            logging.logToOutput("Stopped monitoring session for payload: " + payload + 
                " (Active sessions: " + activeSessions.size() + ")");
        }
    }
    
    public void shutdown() {
        logging.logToOutput("Initiating monitoring shutdown...");
        stopMonitoring = true;
        if (monitoringThread != null) {
            monitoringThread.interrupt();
            try {
                monitoringThread.join(5000); // Wait up to 5 seconds for clean shutdown
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                logging.logToOutput("Shutdown interrupted, continuing with cleanup");
            }
        }
        activeSessions.clear();
        logging.logToOutput("Monitoring shutdown complete");
    }
}

// Interface defining the monitoring session contract
interface MonitoringSession {
    void processInteractions(List<Interaction> interactions);
    boolean isComplete();
    void stop();
}

// Implementation for RCE monitoring
class RCEMonitoringSession implements MonitoringSession {
    private final RCEPanel rcePanel;
    private final Map<String, String> dnsRecordDict;
    private int sameCounter;
    private volatile boolean stopped;
    private final Logging logging;
    
    public RCEMonitoringSession(RCEPanel rcePanel, Logging logging) {
        this.rcePanel = rcePanel;
        this.logging = logging;
        this.dnsRecordDict = new HashMap<>();
        this.sameCounter = 0;
        this.stopped = false;
    }
    
    @Override
    public void processInteractions(List<Interaction> interactions) {
        Set<String> oldKeys = new HashSet<>(dnsRecordDict.keySet());
        logging.logToOutput("Old keys before processing: " + oldKeys);
        
        for (Interaction interaction : interactions) {
            if (!interaction.dnsDetails().isPresent()) {
                continue;
            }
            
            byte[] queryBytes = interaction.dnsDetails().get().query().getBytes();
            logging.logToOutput("Raw DNS query:\n" + HexDumpUtil.xxdStyle(queryBytes));
            logging.logToOutput("Processing query with length: " + queryBytes.length);
            
            if (queryBytes.length <= 12) {
                continue;
            }
            
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
        
        // Check completion conditions
        if (sameCounter >= 5 && !dnsRecordDict.isEmpty()) {
            stop();
        }
    }
    
    @Override
    public boolean isComplete() {
        return stopped || (sameCounter >= 5 && !dnsRecordDict.isEmpty());
    }
    
    @Override
    public void stop() {
        stopped = true;
        SwingUtilities.invokeLater(() -> {
            if (!dnsRecordDict.isEmpty()) {
                displayRCEOutput();
            }
            rcePanel.getRceProgressBar().setIndeterminate(false);
            rcePanel.getRceStopButton().setVisible(false);
            rcePanel.getExecuteButton().setVisible(true);
        });
    }
    
    private void displayRCEOutput() {
        StringBuilder output = new StringBuilder();
        
        List<Map.Entry<String, String>> sortedEntries = dnsRecordDict.entrySet().stream()
            .filter(entry -> entry.getKey().matches("\\d+"))
            .sorted((a, b) -> Integer.parseInt(a.getKey()) - Integer.parseInt(b.getKey()))
            .collect(Collectors.toList());
        
        for (Map.Entry<String, String> entry : sortedEntries) {
            String hexValue = entry.getValue()
                .replaceAll("[^0-9A-Fa-f]", "")
                .replaceAll("k.*$", "")
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
            
            logging.logToOutput("Command: " + rcePanel.getCommandTxt().getText());
            logging.logToOutput("Output:\n" + result + "\n");
            
        } catch (IllegalArgumentException e) {
            logging.logToError("Error decoding hex output", e);
            logging.logToError("Problematic hex string: " + output.toString());
            rcePanel.getRceOutputTxt().append("Error: Failed to decode output. See extension logs for details.\n");
        }
    }
}

// Implementation for SQLi monitoring 
class SQLiMonitoringSession implements MonitoringSession {
    private final SQLiPanel sqliPanel;
    private final Set<String> processedQueries;
    private final Map<String, String> lastExfiltratedTableByDBMS;
    private final Map<String, String> lastExfiltratedColumnByDBMS;
    private int sameCounter;
    private volatile boolean stopped;
    private boolean foundValidQuery;
    private final Logging logging;
    private final String collaboratorPayload;
    
    public SQLiMonitoringSession(SQLiPanel sqliPanel, 
                               Logging logging,
                               Map<String, String> lastExfiltratedTableByDBMS,
                               Map<String, String> lastExfiltratedColumnByDBMS,
                               String collaboratorPayload) {
        this.sqliPanel = sqliPanel;
        this.logging = logging;
        this.lastExfiltratedTableByDBMS = lastExfiltratedTableByDBMS;
        this.lastExfiltratedColumnByDBMS = lastExfiltratedColumnByDBMS;
        this.collaboratorPayload = collaboratorPayload;
        this.processedQueries = new HashSet<>();
        this.sameCounter = 0;
        this.stopped = false;
        this.foundValidQuery = false;
    }
    
    @Override
    public void processInteractions(List<Interaction> interactions) {
        Set<String> oldQueries = new HashSet<>(processedQueries);
        logging.logToOutput("Old queries before processing: " + oldQueries);
        
        for (Interaction interaction : interactions) {
            if (!interaction.dnsDetails().isPresent()) {
                continue;
            }

            byte[] fullQueryBytes = interaction.dnsDetails().get().query().getBytes();
            logging.logToOutput("Raw DNS query:\n" + HexDumpUtil.xxdStyle(fullQueryBytes));
            
            if (fullQueryBytes.length <= 13) {
                continue;
            }
            byte[] queryBytes = Arrays.copyOfRange(fullQueryBytes, 13, fullQueryBytes.length);
            String queryString = new String(queryBytes, StandardCharsets.UTF_8);
            logging.logToOutput("Processing DNS query (after header strip): " + queryString);
            
            String dbmsType = (String) sqliPanel.getDbmsComboBox().getSelectedItem();
            String cleanedQuery = cleanQuery(queryString);
            
            // Only filter out single underscore queries, allow other single characters
            if (!cleanedQuery.equals("_")) {
                if (sqliPanel.getHexEncodingToggle().isSelected()) {
                    String bestResult = decodeHexQuery(cleanedQuery);
                    
                    if (!bestResult.isEmpty() && !bestResult.equals("_")) {
                        // Allow any alphanumeric character, including single characters
                        if (bestResult.matches(".*[a-zA-Z0-9].*")) {
                            processedQueries.add(bestResult);
                            foundValidQuery = true;
                            logging.logToOutput("Successfully decoded hex: " + bestResult);
                        }
                    }
                } else {
                    if (isValidDBMS(dbmsType)) {
                        // Allow any alphanumeric character, including single characters
                        if (cleanedQuery.matches(".*[a-zA-Z0-9].*")) {
                            processedQueries.add(cleanedQuery);
                            foundValidQuery = true;
                            logging.logToOutput("Processed " + dbmsType + " query: " + cleanedQuery);
                        }
                    }
                }
            }
        }

        Set<String> newQueries = new HashSet<>(processedQueries);
        logging.logToOutput("New queries after processing: " + newQueries);
        
        if (newQueries.equals(oldQueries) && !newQueries.isEmpty()) {
            sameCounter++;
            logging.logToOutput("No new queries found. Same counter: " + sameCounter);
        } else if (!newQueries.equals(oldQueries) && !newQueries.isEmpty()) {
            sameCounter = 0;
            logging.logToOutput("New queries detected, resetting counter");
        }

        // Check completion conditions and trigger output display
        if (sameCounter >= 5 && foundValidQuery && !processedQueries.isEmpty()) {
            logging.logToOutput("Processing complete, stopping monitoring");
            if (!stopped) {
                stop();
            }
        }
    }

    private boolean isValidDBMS(String dbmsType) {
        return dbmsType.equals("PostgreSQL (Elevated Privileges)") || 
               dbmsType.equals("Oracle (Elevated Privileges)") || 
               dbmsType.equals("Oracle (XXE)") || 
               dbmsType.equals("MySQL (Windows)") || 
               dbmsType.equals("Microsoft SQL Server (Stacked)");
    }

    private String cleanQuery(String query) {
        // First strip out the collaborator payload and any trailing characters
        String cleanedQuery = query;
        
        // Break the collaborator payload into parts
        String[] domainParts = collaboratorPayload.split("\\.");
        if (domainParts.length >= 1) {
            // Use the first part of the collaborator domain (the unique identifier)
            // This avoids assumptions about the domain extension
            String uniqueId = domainParts[0];
            int domainIndex = query.toLowerCase().indexOf(uniqueId.toLowerCase());
            if (domainIndex > -1) {
                cleanedQuery = query.substring(0, domainIndex);
            }
        }
        
        // Remove any trailing non-alphanumeric characters
        cleanedQuery = cleanedQuery.replaceAll("[^a-zA-Z0-9]+$", "");
        
        return cleanedQuery.trim();
    }

    private String decodeHexQuery(String cleanedQuery) {
        // First check - if query starts with underscore, return empty string
        if (cleanedQuery.startsWith("_")) {
            return "";
        }
        
        String hexPattern = "([0-9a-fA-F]{2,})";
        java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(hexPattern);
        java.util.regex.Matcher matcher = pattern.matcher(cleanedQuery);
        
        String bestResult = "";
        int maxValidLength = 0;
        
        while (matcher.find()) {
            String match = matcher.group(1);
            try {
                String decoded = new String(BaseEncoding.base16().decode(match.toUpperCase()));
                
                // Accept the result if:
                // 1. It contains printable chars, AND
                // 2. Either it's a single alphanumeric character OR it's longer than the previous best result
                if (decoded.matches(".*\\p{Print}.*") && 
                    (decoded.matches("[a-zA-Z0-9]") || decoded.length() > maxValidLength)) {
                    bestResult = decoded;
                    maxValidLength = decoded.length();
                }
            } catch (IllegalArgumentException e) {
                continue;
            }
        }
        
        return bestResult;
    }
    
    @Override
    public boolean isComplete() {
        return stopped || (sameCounter >= 5 && foundValidQuery && !processedQueries.isEmpty());
    }
    
    @Override
    public void stop() {
        stopped = true;
        SwingUtilities.invokeLater(() -> {
            if (!processedQueries.isEmpty()) {
                displaySQLiOutput(processedQueries, collaboratorPayload);
            }
            sqliPanel.getSqliProgressBar().setIndeterminate(false);
            sqliPanel.getSqliStopButton().setVisible(false);
            sqliPanel.getGenerateSQLiButton().setVisible(true);
        });
    }

    private void displaySQLiOutput(Set<String> processedQueries, String collaboratorPayload) {
        if (processedQueries.isEmpty()) {
            return;
        }

        // Get all meaningful queries, removing the collaborator domain and filtering garbage data
        List<String> finalResults = processedQueries.stream()
            .map(this::cleanQuery)                          // Clean each query
            .filter(q -> !q.matches("^[_\\s]*$"))          // Filter out underscore-only queries
            .filter(q -> !q.startsWith("_"))               // Filter queries starting with underscore
            .filter(q -> q.matches(".*[a-zA-Z0-9].*"))     // Must contain alphanumeric
            .filter(q -> !q.matches("^[^a-zA-Z0-9]*$"))    // Must not be only special characters
            .filter(q -> q.length() > 0)                   // Ensure we have content after cleaning
            .distinct()   // Remove any duplicates
            .sorted()     // Sort for consistent display
            .collect(Collectors.toList());
                
        // Save extracted values based on extraction type if results exist
        if (!finalResults.isEmpty()) {
            String dbmsType = (String) sqliPanel.getDbmsComboBox().getSelectedItem();
            String extractType = (String) sqliPanel.getExtractComboBox().getSelectedItem();
            String extractedValue = finalResults.get(0); // Get first result
            
            switch (extractType) {
                case "Table":
                    lastExfiltratedTableByDBMS.put(dbmsType, extractedValue);
                    logging.logToOutput("Saved extracted table name for " + dbmsType + ": " + 
                                      lastExfiltratedTableByDBMS.get(dbmsType));
                    break;
                case "Column":
                    lastExfiltratedColumnByDBMS.put(dbmsType, extractedValue);
                    logging.logToOutput("Saved extracted column name for " + dbmsType + ": " + 
                                      lastExfiltratedColumnByDBMS.get(dbmsType));
                    break;
            }

            sqliPanel.getSqliOutputTxt().append("Extract Type: " + extractType + "\n");
            sqliPanel.getSqliOutputTxt().append("Exfiltrated Data:\n");
            sqliPanel.getSqliOutputTxt().append(String.join("\n", finalResults) + "\n\n");
            sqliPanel.getSqliOutputTxt().setCaretPosition(sqliPanel.getSqliOutputTxt().getDocument().getLength());
        }

        // Log the results
        logging.logToOutput("Collaborator Domain: " + collaboratorPayload);
        logging.logToOutput("Extract Type: " + sqliPanel.getExtractComboBox().getSelectedItem());
        logging.logToOutput("Output:\n" + String.join("\n", finalResults));
        
        String currentDBMS = (String) sqliPanel.getDbmsComboBox().getSelectedItem();
        String savedTable = lastExfiltratedTableByDBMS.getOrDefault(currentDBMS, "");
        String savedColumn = lastExfiltratedColumnByDBMS.getOrDefault(currentDBMS, "");
        
        logging.logToOutput("Current saved table for " + currentDBMS + ": " + savedTable);
        logging.logToOutput("Current saved column for " + currentDBMS + ": " + savedColumn + "\n");
    }
}