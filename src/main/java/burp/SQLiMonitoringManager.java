package burp;

import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.collaborator.InteractionFilter;
import burp.api.montoya.logging.Logging;
import com.google.common.io.BaseEncoding;

import javax.swing.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

public class SQLiMonitoringManager {
private final CollaboratorClient collaboratorClient;
private final Logging logging;
private final SQLiPanel sqliPanel;
private final Map<String, String> lastExfiltratedTableByDBMS;
private final Map<String, String> lastExfiltratedColumnByDBMS;
private Thread monitoringThread;
private boolean stopMonitoring = false;

public SQLiMonitoringManager(CollaboratorClient collaboratorClient, 
                               Logging logging, 
                               SQLiPanel sqliPanel,
                               Map<String, String> lastExfiltratedTableByDBMS,
                               Map<String, String> lastExfiltratedColumnByDBMS) {
        this.collaboratorClient = collaboratorClient;
        this.logging = logging;
        this.sqliPanel = sqliPanel;
        this.lastExfiltratedTableByDBMS = lastExfiltratedTableByDBMS;
        this.lastExfiltratedColumnByDBMS = lastExfiltratedColumnByDBMS;
    }

    public void startMonitoring(String collaboratorPayload) {
        logging.logToOutput("Starting monitoring for SQLi collaborator domain: " + collaboratorPayload);
        stopMonitoring = false;

        Thread thread = new Thread(() -> {
            Set<String> processedQueries = new HashSet<>();
            int sameCounter = 0;
            boolean foundValidQuery = false;
            
            while (!stopMonitoring) {
                try {
                    Thread.sleep(1000);
                    
                    Set<String> oldQueries = new HashSet<>(processedQueries);
                    logging.logToOutput("Old queries before processing: " + oldQueries);
                    
                    List<Interaction> interactions = collaboratorClient.getInteractions(
                        InteractionFilter.interactionPayloadFilter(collaboratorPayload)
                    );

                    for (Interaction interaction : interactions) {
                        if (!interaction.dnsDetails().isPresent()) {
                            continue;
                        }

                        byte[] fullQueryBytes = interaction.dnsDetails().get().query().getBytes();
                        if (fullQueryBytes.length <= 13) {
                            continue;
                        }
                        byte[] queryBytes = Arrays.copyOfRange(fullQueryBytes, 13, fullQueryBytes.length);
                        String queryString = new String(queryBytes, StandardCharsets.UTF_8);
                        logging.logToOutput("Processing DNS query (after header strip): " + queryString);
                        
                        String dbmsType = (String) sqliPanel.getDbmsComboBox().getSelectedItem();
                        
                        if (sqliPanel.getHexEncodingToggle().isSelected()) {
                            String cleanedQuery = queryString;
                            String collaboratorDomain = collaboratorPayload;
                            int domainIndex = cleanedQuery.toLowerCase().indexOf(collaboratorDomain.toLowerCase());
                            if (domainIndex > -1) {
                                cleanedQuery = cleanedQuery.substring(0, domainIndex);
                            }
                            
                            String hexPattern = "([0-9a-fA-F]{2,})";
                            java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(hexPattern);
                            java.util.regex.Matcher matcher = pattern.matcher(cleanedQuery);
                            
                            String bestResult = "";
                            while (matcher.find()) {
                                String match = matcher.group(1);
                                try {
                                    String decoded = new String(BaseEncoding.base16().decode(match.toUpperCase()));
                                    if (decoded.matches(".*\\p{Print}.*") && decoded.length() > bestResult.length()) {
                                        bestResult = decoded;
                                    }
                                } catch (IllegalArgumentException e) {
                                    continue;
                                }
                            }
                            
                            if (!bestResult.isEmpty()) {
                                processedQueries.add(bestResult);
                                foundValidQuery = true;
                                logging.logToOutput("Successfully decoded hex: " + bestResult);
                            }
                        } else {
                            if (dbmsType.equals("PostgreSQL (Elevated Privileges)") || 
                                dbmsType.equals("Oracle (Elevated Privileges)")|| 
                                dbmsType.equals("Oracle (XXE)")|| 
                                dbmsType.equals("MySQL (Windows)")|| 
                                dbmsType.equals("Microsoft SQL Server (Stacked)")) {
                                
                                // Strip out only the collaborator domain
                                String collaboratorDomain = collaboratorPayload;
                                int domainIndex = queryString.toLowerCase().indexOf(collaboratorDomain.toLowerCase());
                                if (domainIndex > -1) {
                                    queryString = queryString.substring(0, domainIndex);
                                }
                                
                                if (!queryString.isEmpty()) {
                                    processedQueries.add(queryString);
                                    foundValidQuery = true;
                                    logging.logToOutput("Processed " + dbmsType + " query: " + queryString);
                                }
                            }
                        }
                    }

                    Set<String> newQueries = new HashSet<>(processedQueries);
                    logging.logToOutput("New queries after processing: " + newQueries);
                    
                    if (foundValidQuery) {
                        sameCounter++;
                        logging.logToOutput("Valid query found. Same counter: " + sameCounter);
                    }
                    
                    if (sameCounter >= 5 || (foundValidQuery && !processedQueries.isEmpty())) {
                        logging.logToOutput("Processing complete, stopping monitoring");
                        stopMonitoring = true;
                        displayOutput(processedQueries, collaboratorPayload);
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
                sqliPanel.getSqliProgressBar().setIndeterminate(false);
                sqliPanel.getSqliStopButton().setVisible(false);
                sqliPanel.getGenerateSQLiButton().setVisible(true);
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

    private void displayOutput(Set<String> processedQueries, String collaboratorPayload) {
        if (processedQueries.isEmpty()) {
            return;
        }

        // Get all meaningful queries, removing the collaborator domain
        List<String> finalResults = processedQueries.stream()
            .filter(q -> !q.matches("^[_\\s]*$"))         // Filter out underscore-only queries
            .filter(q -> q.matches(".*[a-zA-Z0-9].*"))    // Must contain alphanumeric
            .map(q -> {
                // Remove collaborator domain from final display
                String collaboratorDomain = collaboratorPayload;
                return q.replaceAll("(?i)" + collaboratorDomain + ".*$", "").trim();
            })
            .distinct()  // Remove any duplicates
            .sorted()    // Sort for consistent display
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

            // Update the UI
            SwingUtilities.invokeLater(() -> {
                sqliPanel.getSqliOutputTxt().append("Extract Type: " + extractType + "\n");
                sqliPanel.getSqliOutputTxt().append("Exfiltrated Data:\n");
                sqliPanel.getSqliOutputTxt().append(String.join("\n", finalResults) + "\n\n");
                sqliPanel.getSqliOutputTxt().setCaretPosition(sqliPanel.getSqliOutputTxt().getDocument().getLength());
            });
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