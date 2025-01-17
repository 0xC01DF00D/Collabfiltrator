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
    private CollaboratorPayload collaboratorPayload;
    private Map<String, String> lastExfiltratedTableByDBMS = new HashMap<>();
    private Map<String, String> lastExfiltratedColumnByDBMS = new HashMap<>();
    private RCEPayloadManager rcePayloadManager;
    private SQLiPayloadManager sqliPayloadManager;
    private RCEMonitoringManager rceMonitoringManager;
    private SQLiMonitoringManager sqliMonitoringManager;

    // GUI Components
    private JPanel mainPanel;
    private RCEPanel rcePanel;
    private SQLiPanel sqliPanel;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.logging = api.logging();
        this.userInterface = api.userInterface();
        this.collaboratorClient = api.collaborator().createClient();
        this.rcePayloadManager = new RCEPayloadManager(collaboratorClient, logging);
        this.sqliPayloadManager = new SQLiPayloadManager(lastExfiltratedTableByDBMS, lastExfiltratedColumnByDBMS, logging);

        // Register unloading handler
        api.extension().registerUnloadingHandler(() -> {
            logging.logToOutput("Collabfiltrator extension unloading - cleaning up resources...");
            // Force stop monitoring
            rceMonitoringManager.stopMonitoring();
            sqliMonitoringManager.stopMonitoring();
            logging.logToOutput("Collabfiltrator extension cleanup completed.");
        });

        logging.logToOutput("Extension Name: Collabfiltrator");
        logging.logToOutput("Description:    Exfiltrate Blind RCE and SQLi output over DNS via Burp Collaborator.");
        logging.logToOutput("Human Authors:  Adam Logue, Frank Scarpella, Jared McLaren, Ryan Griffin");
        logging.logToOutput("AI Authors:     ChatGPT 4o, Claude 3.5 Sonnet");
        logging.logToOutput("Version:        4.0");

        setupGui();
        addTabToBurpSuite();
        
        // Initialize monitoring managers after GUI setup
        this.rceMonitoringManager = new RCEMonitoringManager(collaboratorClient, logging, rcePanel);
        this.sqliMonitoringManager = new SQLiMonitoringManager(collaboratorClient, logging, sqliPanel, 
                                                             lastExfiltratedTableByDBMS, 
                                                             lastExfiltratedColumnByDBMS);
        
        generateNewRCECollaboratorPayload();
        generateNewSQLiCollaboratorPayload();
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
        userInterface.registerSuiteTab("Collabfiltrator", mainPanel);
    }

    private void generateNewRCECollaboratorPayload() {
        this.collaboratorPayload = collaboratorClient.generatePayload();
        rcePanel.getRceBurpCollaboratorDomainTxt().setText(collaboratorPayload.toString());
    }

    private void generateNewSQLiCollaboratorPayload() {
        this.collaboratorPayload = collaboratorClient.generatePayload();
        sqliPanel.getSqliBurpCollaboratorDomainTxt().setText(collaboratorPayload.toString());
    }

    public void copyToClipboard(String payload) {
        StringSelection selection = new StringSelection(payload);
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, selection);
    }

    public void stopMonitoringAction() {
        rceMonitoringManager.stopMonitoring();
        sqliMonitoringManager.stopMonitoring();
        rcePanel.getRceProgressBar().setIndeterminate(false);
        sqliPanel.getSqliProgressBar().setIndeterminate(false);
    }

    public void executeRCEPayload(String command) {
        generateNewRCECollaboratorPayload();
                
        rcePanel.getRceProgressBar().setIndeterminate(true);
        rcePanel.getRceStopButton().setVisible(true);
                
        String osType = (String) rcePanel.getOsComboBox().getSelectedItem();
        String payload = rcePayloadManager.createPayload(osType, command, collaboratorPayload.toString());
        
        rcePanel.getRcePayloadTxt().setText(payload);
        rceMonitoringManager.startMonitoring(collaboratorPayload.toString());
    }

    public void generateSQLiPayload() {
        String dbms = (String) sqliPanel.getDbmsComboBox().getSelectedItem();
        String extractType = (String) sqliPanel.getExtractComboBox().getSelectedItem();
        boolean hexEncoded = sqliPanel.getHexEncodingToggle().isSelected();
        String payload;

        // Generate new Collaborator payload
        generateNewSQLiCollaboratorPayload();

        // Get payload from manager
        payload = sqliPayloadManager.generatePayload(dbms, extractType, hexEncoded, 
                                                   collaboratorPayload.toString());

        sqliPanel.getSqlipayloadTxt().setText(payload);
        sqliMonitoringManager.startMonitoring(collaboratorPayload.toString());
    }
}