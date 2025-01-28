package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.UserInterface;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.util.*;

public class Collabfiltrator implements BurpExtension {
    private MontoyaApi api;
    private Logging logging;
    private UserInterface userInterface;
    private CollaboratorClient collaboratorClient;
    private Map<String, String> lastExfiltratedTableByDBMS = new HashMap<>();
    private Map<String, String> lastExfiltratedColumnByDBMS = new HashMap<>();
    private RCEPayloadManager rcePayloadManager;
    private SQLiPayloadManager sqliPayloadManager;
    private MonitoringManager monitoringManager;
    private String currentRCEPayload;
    private String currentSQLiPayload;

    // GUI Components
    private JPanel mainPanel;
    private RCEPanel rcePanel;
    private SQLiPanel sqliPanel;

    public Collabfiltrator() {
        this.collaboratorClient = null; // Will be initialized in initialize()
    }

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.logging = api.logging();
        this.userInterface = api.userInterface();
        this.collaboratorClient = api.collaborator().createClient();
        this.rcePayloadManager = new RCEPayloadManager(collaboratorClient, logging);
        this.sqliPayloadManager = new SQLiPayloadManager(lastExfiltratedTableByDBMS, lastExfiltratedColumnByDBMS, logging);
        this.monitoringManager = new MonitoringManager(collaboratorClient, logging);

        // Register unloading handler
        api.extension().registerUnloadingHandler(() -> {
            logging.logToOutput("Collabfiltrator extension unloading - cleaning up resources...");
            stopRCEMonitoring();
            stopSQLiMonitoring();
            monitoringManager.shutdown();
            logging.logToOutput("Collabfiltrator extension cleanup completed.");
        });

        logging.logToOutput("Extension Name: Collabfiltrator");
        logging.logToOutput("Description:    Exfiltrate Blind RCE and SQLi output over DNS via Burp Collaborator.");
        logging.logToOutput("Human Authors:  Adam Logue, Frank Scarpella, Jared McLaren, Ryan Griffin");
        logging.logToOutput("AI Authors:     ChatGPT 4o, Claude 3.5 Sonnet");
        logging.logToOutput("Version:        4.0.1\n\n");

        setupGui();
        addTabToBurpSuite();
    }

    private void setupGui() {
        mainPanel = new JPanel();
        mainPanel.setLayout(new BorderLayout());
        
        // Create the tabbed pane
        JTabbedPane tabbedPane = new JTabbedPane();

        // Create panels
        rcePanel = new RCEPanel(this);
        sqliPanel = new SQLiPanel(this);

        // Add tabs to the tabbed pane
        tabbedPane.addTab("RCE", rcePanel);
        tabbedPane.addTab("SQLi", sqliPanel);

        // Add the tabbed pane to the main panel
        mainPanel.add(tabbedPane, BorderLayout.CENTER);
    }

    private void addTabToBurpSuite() {
        api.extension().setName("Collabfiltrator");
        userInterface.registerSuiteTab("Collabfiltrator", mainPanel);
    }

    public void copyToClipboard(String payload) {
        StringSelection selection = new StringSelection(payload);
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, selection);
    }

    public void stopRCEMonitoring() {
        if (currentRCEPayload != null) {
            monitoringManager.stopSession(currentRCEPayload);
            currentRCEPayload = null;
        }
        rcePanel.getRceProgressBar().setIndeterminate(false);
        rcePanel.getRceStopButton().setVisible(false);
        rcePanel.getExecuteButton().setVisible(true);
    }

    public void stopSQLiMonitoring() {
        if (currentSQLiPayload != null) {
            monitoringManager.stopSession(currentSQLiPayload);
            currentSQLiPayload = null;
        }
        sqliPanel.getSqliProgressBar().setIndeterminate(false);
        sqliPanel.getSqliStopButton().setVisible(false);
        sqliPanel.getGenerateSQLiButton().setVisible(true);
    }

    public void executeRCEPayload(String command) {
        // Generate new collaborator payload
        CollaboratorPayload payload = collaboratorClient.generatePayload();
        currentRCEPayload = payload.toString();
        rcePanel.getRceBurpCollaboratorDomainTxt().setText(currentRCEPayload);
        
        rcePanel.getRceProgressBar().setIndeterminate(true);
        rcePanel.getRceStopButton().setVisible(true);
        rcePanel.getExecuteButton().setVisible(false);
                
        String osType = (String) rcePanel.getOsComboBox().getSelectedItem();
        String generatedPayload = rcePayloadManager.createPayload(osType, command, currentRCEPayload);
        
        rcePanel.getRcePayloadTxt().setText(generatedPayload);
        
        // Create and register RCE monitoring session
        RCEMonitoringSession session = new RCEMonitoringSession(rcePanel, logging);
        monitoringManager.registerSession(currentRCEPayload, session);
    }

    public void generateSQLiPayload() {
        // Generate new collaborator payload
        CollaboratorPayload payload = collaboratorClient.generatePayload();
        currentSQLiPayload = payload.toString();
        sqliPanel.getSqliBurpCollaboratorDomainTxt().setText(currentSQLiPayload);
        
        String dbms = (String) sqliPanel.getDbmsComboBox().getSelectedItem();
        String extractType = (String) sqliPanel.getExtractComboBox().getSelectedItem();
        boolean hexEncoded = sqliPanel.getHexEncodingToggle().isSelected();
        
        String generatedPayload = sqliPayloadManager.generatePayload(dbms, extractType, hexEncoded, 
                                                   currentSQLiPayload);

        sqliPanel.getSqlipayloadTxt().setText(generatedPayload);
        sqliPanel.getSqliProgressBar().setIndeterminate(true);
        sqliPanel.getSqliStopButton().setVisible(true);
        sqliPanel.getGenerateSQLiButton().setVisible(false);
        
        // Create and register SQLi monitoring session
        SQLiMonitoringSession session = new SQLiMonitoringSession(
            sqliPanel, 
            logging, 
            lastExfiltratedTableByDBMS, 
            lastExfiltratedColumnByDBMS,
            currentSQLiPayload
        );
        monitoringManager.registerSession(currentSQLiPayload, session);
    }
}