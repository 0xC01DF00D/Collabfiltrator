package burp;

import javax.swing.*;
import javax.swing.text.*;
import java.awt.*;
import java.awt.event.*;
import javax.swing.Timer;
import java.util.Map;

public class SQLiPanel extends JPanel {
    private final Collabfiltrator mainExtension;
    private JTextArea sqlipayloadTxt;
    private JTextArea sqliOutputTxt;
    private JTextPane sqliBurpCollaboratorDomainTxt;
    private JProgressBar sqliProgressBar;
    private JButton sqliStopButton;
    private JButton generateSQLiButton;
    private JComboBox<String> dbmsComboBox;
    private JComboBox<String> extractComboBox;
    private ToggleSwitch hexEncodingToggle;

    public SQLiPanel(Collabfiltrator mainExtension) {
        this.mainExtension = mainExtension;
        setupPanel();
    }

    private void setupPanel() {
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        setAlignmentX(Component.CENTER_ALIGNMENT);

        // Title with subtitle
        JLabel sqliTitleLabel = new JLabel("Collabfiltrator: SQLi Exfil", SwingConstants.CENTER);
        sqliTitleLabel.setFont(new Font("Arial", Font.BOLD, 18));
        sqliTitleLabel.setAlignmentX(Component.CENTER_ALIGNMENT);

        JLabel sqliSubtitleLabel = new JLabel("Exfiltrate Blind SQL injection output over DNS via Burp Collaborator.", SwingConstants.CENTER);
        sqliSubtitleLabel.setFont(new Font("Arial", Font.PLAIN, 13));
        sqliSubtitleLabel.setAlignmentX(Component.CENTER_ALIGNMENT);

        add(sqliTitleLabel);
        add(Box.createRigidArea(new Dimension(0, 5)));
        add(sqliSubtitleLabel);
        add(Box.createRigidArea(new Dimension(0, 15)));

        // Input Panel
        JPanel sqliInputPanel = createInputPanel();
        add(sqliInputPanel);
        add(Box.createRigidArea(new Dimension(0, 15)));

        // Payload Panel
        JPanel sqliPayloadPanel = createPayloadPanel();
        add(sqliPayloadPanel);
        add(Box.createRigidArea(new Dimension(0, 10)));

        // Note Label
        JLabel sqliNoteLabel = new JLabel("Note: SQLi Payloads are generic and may require minor modification.");
        sqliNoteLabel.setFont(new Font("Arial", Font.ITALIC, 12));
        sqliNoteLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        add(sqliNoteLabel);
        add(Box.createRigidArea(new Dimension(0, 5)));

        // Copy Button
        JButton sqliCopyButton = new JButton("Copy Payload to Clipboard");
        sqliCopyButton.addActionListener(e -> mainExtension.copyToClipboard(sqlipayloadTxt.getText()));
        sqliCopyButton.setAlignmentX(Component.CENTER_ALIGNMENT);
        add(sqliCopyButton);
        add(Box.createRigidArea(new Dimension(0, 10)));

        // Progress Bar
        sqliProgressBar = new JProgressBar(0, 100);
        sqliProgressBar.setMaximumSize(new Dimension(200, 20));
        add(sqliProgressBar);
        add(Box.createRigidArea(new Dimension(0, 15)));

        // SQLi Collaborator Domain
        sqliBurpCollaboratorDomainTxt = new JTextPane();
        sqliBurpCollaboratorDomainTxt.setAlignmentX(Component.CENTER_ALIGNMENT);
        sqliBurpCollaboratorDomainTxt.setFont(new Font("Arial", Font.ITALIC, 12));
        sqliBurpCollaboratorDomainTxt.setEditable(false);
        sqliBurpCollaboratorDomainTxt.setOpaque(false);
        sqliBurpCollaboratorDomainTxt.setMaximumSize(new Dimension(300, 30));
        add(sqliBurpCollaboratorDomainTxt);
        add(Box.createRigidArea(new Dimension(0, 10)));

        // Output Panel
        JPanel sqliOutputPanel = createOutputPanel();
        add(sqliOutputPanel);
        add(Box.createRigidArea(new Dimension(0, 10)));

        // Clear Output Button
        JButton sqliClearOutputButton = new JButton("Clear Output");
        sqliClearOutputButton.addActionListener(e -> sqliOutputTxt.setText(""));
        sqliClearOutputButton.setAlignmentX(Component.CENTER_ALIGNMENT);
        add(sqliClearOutputButton);
    }

    private JPanel createInputPanel() {
        JPanel sqliInputPanel = new JPanel();
        sqliInputPanel.setLayout(new BoxLayout(sqliInputPanel, BoxLayout.X_AXIS));
        sqliInputPanel.setAlignmentX(Component.CENTER_ALIGNMENT);

        // Create DBMS Combo Box
        JLabel dbmsLabel = new JLabel("DBMS ");
        dbmsComboBox = new JComboBox<>(new String[]{
            "Microsoft SQL Server (Stacked)", 
            "MySQL (Windows)", 
            "PostgreSQL (Elevated Privileges)", 
            "Oracle (Elevated Privileges)", 
            "Oracle (XXE)"
        });
        dbmsComboBox.setMaximumSize(new Dimension(170, 25));

        // Info icon setup
        Icon infoIcon = UIManager.getIcon("OptionPane.informationIcon");
        JLabel infoIconLabel = new JLabel("", infoIcon, JLabel.CENTER);
        infoIconLabel.setMaximumSize(new Dimension(30, 30));

        setupHoverDialog(infoIconLabel);

        JLabel extractLabel = new JLabel("Extract ");
        extractComboBox = new JComboBox<>(new String[]{"Version", "Database", "Table", "Column", "Row"});
        extractComboBox.setMaximumSize(new Dimension(100, 25));

        hexEncodingToggle = new ToggleSwitch();
        hexEncodingToggle.setMaximumSize(new Dimension(40, 20));
        hexEncodingToggle.setSelected(true);

        generateSQLiButton = new JButton("Dump");
        generateSQLiButton.setMaximumSize(new Dimension(100, 25));
        generateSQLiButton.setVisible(true);

        sqliStopButton = new JButton("Stop");
        sqliStopButton.setMaximumSize(new Dimension(100, 25));
        sqliStopButton.setVisible(false);

        // Add action listeners
        generateSQLiButton.addActionListener(e -> {
            mainExtension.generateSQLiPayload();
            sqliStopButton.setVisible(true);
            generateSQLiButton.setVisible(false);
            sqliProgressBar.setIndeterminate(true);
        });

        sqliStopButton.addActionListener(e -> {
            mainExtension.stopMonitoringAction();
            sqliStopButton.setVisible(false);
            generateSQLiButton.setVisible(true);
            sqliProgressBar.setIndeterminate(false);
        });

        // Add components to panel
        sqliInputPanel.add(infoIconLabel);
        sqliInputPanel.add(Box.createRigidArea(new Dimension(5, 0)));
        sqliInputPanel.add(dbmsLabel);
        sqliInputPanel.add(Box.createRigidArea(new Dimension(5, 0)));
        sqliInputPanel.add(dbmsComboBox);
        sqliInputPanel.add(Box.createRigidArea(new Dimension(5, 0)));
        sqliInputPanel.add(extractLabel);
        sqliInputPanel.add(Box.createRigidArea(new Dimension(5, 0)));
        sqliInputPanel.add(extractComboBox);
        sqliInputPanel.add(Box.createRigidArea(new Dimension(10, 0)));
        sqliInputPanel.add(new JLabel("Plaintext "));
        sqliInputPanel.add(hexEncodingToggle);
        sqliInputPanel.add(Box.createRigidArea(new Dimension(5, 0)));
        sqliInputPanel.add(new JLabel("Hex Encoded "));
        sqliInputPanel.add(Box.createRigidArea(new Dimension(5, 0)));
        sqliInputPanel.add(generateSQLiButton);
        sqliInputPanel.add(sqliStopButton);
        sqliInputPanel.add(Box.createRigidArea(new Dimension(5, 0)));

        return sqliInputPanel;
    }

    private JPanel createPayloadPanel() {
        JPanel sqliPayloadPanel = new JPanel();
        sqliPayloadPanel.setLayout(new BoxLayout(sqliPayloadPanel, BoxLayout.X_AXIS));
        sqliPayloadPanel.setAlignmentX(Component.CENTER_ALIGNMENT);

        JLabel sqliPayloadLabel = new JLabel("Payload ");
        sqlipayloadTxt = new JTextArea(8, 55);
        sqlipayloadTxt.setEditable(true);
        sqlipayloadTxt.setLineWrap(true);
        sqlipayloadTxt.setWrapStyleWord(true);
        sqlipayloadTxt.setBackground(new Color(245, 245, 245));
        JScrollPane sqliPayloadScrollPane = new JScrollPane(sqlipayloadTxt);
        sqliPayloadScrollPane.setMaximumSize(new Dimension(600, 200));

        sqliPayloadPanel.add(sqliPayloadLabel);
        sqliPayloadPanel.add(Box.createRigidArea(new Dimension(5, 0)));
        sqliPayloadPanel.add(sqliPayloadScrollPane);

        return sqliPayloadPanel;
    }

    private JPanel createOutputPanel() {
        JPanel sqliOutputPanel = new JPanel();
        sqliOutputPanel.setLayout(new BoxLayout(sqliOutputPanel, BoxLayout.X_AXIS));
        sqliOutputPanel.setAlignmentX(Component.CENTER_ALIGNMENT);

        JLabel sqliOutputLabel = new JLabel("Output ");
        sqliOutputTxt = new JTextArea(8, 55);
        sqliOutputTxt.setEditable(false);
        sqliOutputTxt.setLineWrap(true);
        sqliOutputTxt.setWrapStyleWord(true);
        sqliOutputTxt.setBackground(new Color(245, 245, 245));
        JScrollPane sqliOutputScrollPane = new JScrollPane(sqliOutputTxt);
        sqliOutputScrollPane.setMaximumSize(new Dimension(600, 200));

        sqliOutputPanel.add(sqliOutputLabel);
        sqliOutputPanel.add(Box.createRigidArea(new Dimension(5, 0)));
        sqliOutputPanel.add(sqliOutputScrollPane);

        return sqliOutputPanel;
    }

    private void setupHoverDialog(JLabel infoIconLabel) {
        JDialog hoverDialog = new JDialog(SwingUtilities.getWindowAncestor(this), "Info", Dialog.ModalityType.MODELESS);
        hoverDialog.setUndecorated(true);
        hoverDialog.setSize(300, 615);

        JPanel dialogContent = new JPanel();
        dialogContent.setBorder(BorderFactory.createLineBorder(Color.BLACK));
        dialogContent.setLayout(new BorderLayout());

        JLabel sqliDialogTitleLabel = new JLabel("Constraints", SwingConstants.CENTER);
        sqliDialogTitleLabel.setFont(new Font("Arial", Font.BOLD, 14));
        sqliDialogTitleLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        dialogContent.add(sqliDialogTitleLabel, BorderLayout.NORTH);

        // Create DBMS-specific context panes
        setupDBMSContextPanes(dialogContent);

        hoverDialog.add(dialogContent);
        setupHoverDialogListeners(infoIconLabel, hoverDialog, dialogContent);
    }

    private void setupDBMSContextPanes(JPanel dialogContent) {
        JTextPane[] contextPanes = {
            createContextPane("Microsoft SQL Server (Stacked Query) SQLi", createMSSQLContent()),
            createContextPane("MySQL (Windows) SQLi", createMySQLContent()),
            createContextPane("PostgreSQL (Elevated Privileges) SQLi", createPostgreSQLContent()),
            createContextPane("Oracle (Elevated Privileges) SQLi", createOraclePrivContent()),
            createContextPane("Oracle (XXE) SQLi", createOracleXXEContent())
        };

        // Add change listener to DBMS combo box
        dbmsComboBox.addActionListener(e -> {
            String selectedDBMS = (String) dbmsComboBox.getSelectedItem();
            dialogContent.remove(1); // Remove current context
            
            switch (selectedDBMS) {
                case "Microsoft SQL Server (Stacked)":
                    dialogContent.add(contextPanes[0], BorderLayout.CENTER);
                    break;
                case "MySQL (Windows)":
                    dialogContent.add(contextPanes[1], BorderLayout.CENTER);
                    break;
                case "PostgreSQL (Elevated Privileges)":
                    dialogContent.add(contextPanes[2], BorderLayout.CENTER);
                    break;
                case "Oracle (Elevated Privileges)":
                    dialogContent.add(contextPanes[3], BorderLayout.CENTER);
                    break;
                case "Oracle (XXE)":
                    dialogContent.add(contextPanes[4], BorderLayout.CENTER);
                    break;
            }
            
            dialogContent.revalidate();
            dialogContent.repaint();
        });

        // Set initial context
        dialogContent.add(contextPanes[0], BorderLayout.CENTER);
    }

    private void setupHoverDialogListeners(JLabel infoIconLabel, JDialog hoverDialog, JPanel dialogContent) {
        infoIconLabel.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent e) {
                Point p = infoIconLabel.getLocationOnScreen();
                hoverDialog.setLocation(p.x - hoverDialog.getWidth() - 5, p.y);
                hoverDialog.setVisible(true);
            }
            
            @Override
            public void mouseExited(MouseEvent e) {
                Timer timer = new Timer(100, event -> {
                    Point mouse = MouseInfo.getPointerInfo().getLocation();
                    Point dialog = hoverDialog.getLocationOnScreen();
                    Rectangle bounds = new Rectangle(dialog, hoverDialog.getSize());
                    if (!bounds.contains(mouse)) {
                        hoverDialog.setVisible(false);
                    }
                });
                timer.setRepeats(false);
                timer.start();
            }
        });

        dialogContent.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseExited(MouseEvent e) {
                Point mouse = MouseInfo.getPointerInfo().getLocation();
                Point dialog = hoverDialog.getLocationOnScreen();
                Rectangle bounds = new Rectangle(dialog, hoverDialog.getSize());
                if (!bounds.contains(mouse)) {
                    hoverDialog.setVisible(false);
                }
            }
        });
    }

    private JTextPane createContextPane(String title, String content) {
        JTextPane pane = new JTextPane();
        pane.setEditable(false);
        pane.setOpaque(false);
        pane.setMargin(new Insets(10, 10, 10, 10));
        
        SimpleAttributeSet normalStyle = new SimpleAttributeSet();
        StyleConstants.setFontFamily(normalStyle, "Arial");
        StyleConstants.setFontSize(normalStyle, 13);
        pane.setCharacterAttributes(normalStyle, true);
        
        pane.setText(title + "\n\n" + content);
        
        // Make title bold
        StyledDocument doc = pane.getStyledDocument();
        SimpleAttributeSet bold = new SimpleAttributeSet();
        StyleConstants.setBold(bold, true);
        StyleConstants.setFontSize(bold, 14);
        doc.setParagraphAttributes(0, title.length(), bold, false);
        
        return pane;
    }

    private String createMSSQLContent() {
        return "⦿  Uses xp_dirtree for DNS exfiltration\n\n" +
            "⦿  Does not work with Azure SQL databases\n\n" +
            "⦿  Requires stacked query injection\n\n" +
            "⦿  Works with hex-encoded and plaintext data\n\n" +
            "⦿  Extracts data using master..xp_dirtree\n\n" +
            "⦿  Hex encoding data preserves case sensitivity\n\n" +
            "⦿  Hex encoding data preserves special characters\n\n" +
            "⦿  Hex encoding data may truncate output\n\n" +
            "⦿  Limited to 62 chars per request";
    }

    private String createMySQLContent() {
        return "⦿  Does NOT work for Linux/XAMPP MySQL\n\n" +
            "⦿  Uses LOAD_FILE for DNS exfiltration\n\n" +
            "⦿  LOAD_FILE queries sometimes take >= 30 seconds to complete\n\n" +
            "⦿  Requires secure_file_priv to be disabled\n\n" +
            "⦿  Works with hex-encoded and plaintext data\n\n" +
            "⦿  Utilizes Windows UNC path for exfil\n\n" +
            "⦿  Hex encoding data preserves case sensitivity\n\n" +
            "⦿  Hex encoding data preserves special characters\n\n" +
            "⦿  Hex encoding data may truncate output\n\n" +
            "⦿  Limited to 62 chars per request";
    }

    private String createPostgreSQLContent() {
        return "⦿  Uses COPY TO PROGRAM for DNS exfiltration\n\n" +
            "⦿  Requires superuser privileges\n\n" +
            "⦿  Works with hex-encoded and plaintext data\n\n" +
            "⦿  Executes system commands via nslookup\n\n" +
            "⦿  Hex encoding data preserves case sensitivity\n\n" +
            "⦿  Hex encoding data preserves special characters\n\n" +
            "⦿  Hex encoding data may truncate output\n\n" +
            "⦿  Limited to 62 chars per request";
    }

    private String createOraclePrivContent() {
        return "⦿  Uses UTL_INADDR for DNS exfiltration\n\n" +
            "⦿  Requires network privileges\n\n" +
            "⦿  Works with hex-encoded and plaintext data\n\n" +
            "⦿  Default package for network operations\n\n" +
            "⦿  Hex encoding data preserves case sensitivity\n\n" +
            "⦿  Hex encoding data preserves special characters\n\n" +
            "⦿  Hex encoding data may truncate output\n\n" +
            "⦿  Limited to 62 chars per request";
    }

    private String createOracleXXEContent() {
        return "⦿  CVE-2014-6577\n\n" +
            "⦿  Uses XML External Entity for DNS exfiltration\n\n" +
            "⦿  No special privileges required\n\n" +
            "⦿  Works with hex-encoded and plaintext data\n\n" +
            "⦿  Exploits XML parser functionality\n\n" +
            "⦿  Hex encoding data preserves case sensitivity\n\n" +
            "⦿  Hex encoding data preserves special characters\n\n" +
            "⦿  Hex encoding data may truncate output\n\n" +
            "⦿  Limited to 62 chars per request";
    }

    // Getters for components that need to be accessed from main extension
    public JTextArea getSqlipayloadTxt() {
        return sqlipayloadTxt;
    }

    public JTextArea getSqliOutputTxt() {
        return sqliOutputTxt;
    }

    public JTextPane getSqliBurpCollaboratorDomainTxt() {
        return sqliBurpCollaboratorDomainTxt;
    }

    public JProgressBar getSqliProgressBar() {
        return sqliProgressBar;
    }

    public JButton getSqliStopButton() {
        return sqliStopButton;
    }

    public JButton getGenerateSQLiButton() {
        return generateSQLiButton;
    }

    public JComboBox<String> getDbmsComboBox() {
        return dbmsComboBox;
    }

    public JComboBox<String> getExtractComboBox() {
        return extractComboBox;
    }

    public ToggleSwitch getHexEncodingToggle() {
        return hexEncodingToggle;
    }
}