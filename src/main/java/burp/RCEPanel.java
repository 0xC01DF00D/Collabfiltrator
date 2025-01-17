package burp;

import javax.swing.*;
import javax.swing.text.*;
import java.awt.*;
import java.awt.event.*;
import javax.swing.Timer;

public class RCEPanel extends JPanel {
    private final Collabfiltrator mainExtension;
    private JTextArea rcePayloadTxt;
    private JTextArea rceOutputTxt;
    private JTextPane rceBurpCollaboratorDomainTxt;
    private JProgressBar rceProgressBar;
    private JButton rceStopButton;
    private JButton executeButton;
    private JComboBox<String> osComboBox;
    private JTextField commandTxt;

    public RCEPanel(Collabfiltrator mainExtension) {
        this.mainExtension = mainExtension;
        setupPanel();
    }

    private void setupPanel() {
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        setAlignmentX(Component.CENTER_ALIGNMENT);

        // Title with subtitle
        JLabel rceTitleLabel = new JLabel("Collabfiltrator: RCE Exfil", SwingConstants.CENTER);
        rceTitleLabel.setFont(new Font("Arial", Font.BOLD, 18));
        rceTitleLabel.setAlignmentX(Component.CENTER_ALIGNMENT);

        JLabel rceSubtitleLabel = new JLabel("Exfiltrate Blind Remote Code Execution output over DNS via Burp Collaborator.", SwingConstants.CENTER);
        rceSubtitleLabel.setFont(new Font("Arial", Font.PLAIN, 13));
        rceSubtitleLabel.setAlignmentX(Component.CENTER_ALIGNMENT);

        add(rceTitleLabel);
        add(Box.createRigidArea(new Dimension(0, 5)));
        add(rceSubtitleLabel);
        add(Box.createRigidArea(new Dimension(0, 15)));

        // Input Panel
        JPanel rceInputPanel = createInputPanel();
        add(rceInputPanel);
        add(Box.createRigidArea(new Dimension(0, 15)));

        // Payload Panel
        JPanel rcePayloadPanel = createPayloadPanel();
        add(rcePayloadPanel);
        add(Box.createRigidArea(new Dimension(0, 10)));

        // Copy Button
        JButton rceCopyButton = new JButton("Copy Payload to Clipboard");
        rceCopyButton.setAlignmentX(Component.CENTER_ALIGNMENT);
        rceCopyButton.addActionListener(e -> mainExtension.copyToClipboard(rcePayloadTxt.getText()));
        add(rceCopyButton);
        add(Box.createRigidArea(new Dimension(0, 15)));

        // Progress Bar Section
        rceProgressBar = new JProgressBar(0, 100);
        rceProgressBar.setMaximumSize(new Dimension(200, 20));
        add(rceProgressBar);
        add(Box.createRigidArea(new Dimension(0, 15)));

        // RCE Collaborator Domain
        rceBurpCollaboratorDomainTxt = new JTextPane();
        rceBurpCollaboratorDomainTxt.setAlignmentX(Component.CENTER_ALIGNMENT);
        rceBurpCollaboratorDomainTxt.setFont(new Font("Arial", Font.ITALIC, 12));
        rceBurpCollaboratorDomainTxt.setEditable(false);
        rceBurpCollaboratorDomainTxt.setOpaque(false);
        rceBurpCollaboratorDomainTxt.setMaximumSize(new Dimension(300, 30));
        add(rceBurpCollaboratorDomainTxt);
        add(Box.createRigidArea(new Dimension(0, 10)));

        // Output Section
        JPanel rceOutputPanel = createOutputPanel();
        add(rceOutputPanel);
        add(Box.createRigidArea(new Dimension(0, 10)));

        // Clear Output Button
        JButton rceClearOutputButton = new JButton("Clear Output");
        rceClearOutputButton.addActionListener(e -> rceOutputTxt.setText(""));
        rceClearOutputButton.setAlignmentX(Component.CENTER_ALIGNMENT);
        add(rceClearOutputButton);
    }

    private JPanel createInputPanel() {
        JPanel rceInputPanel = new JPanel();
        rceInputPanel.setLayout(new BoxLayout(rceInputPanel, BoxLayout.X_AXIS));

        JLabel platformLabel = new JLabel("Platform ");
        osComboBox = new JComboBox<>(new String[]{
            "Windows PowerShell", "Linux (sh + ping)", "Linux (sh + nslookup)",
            "Linux (bash + ping)", "Linux (bash + nslookup)"
        });
        osComboBox.setMaximumSize(new Dimension(175, 25));

        // Info icon setup
        Icon infoIcon = UIManager.getIcon("OptionPane.informationIcon");
        JLabel rceInfoIconLabel = new JLabel("", infoIcon, JLabel.CENTER);
        rceInfoIconLabel.setMaximumSize(new Dimension(30, 30));

        setupHoverDialog(rceInfoIconLabel);

        JLabel commandLabel = new JLabel("Command ");
        commandTxt = new JTextField("hostname", 25);
        commandTxt.setMaximumSize(new Dimension(350, 25));

        // Create Buttons
        executeButton = new JButton("Execute");
        executeButton.setMaximumSize(new Dimension(90, 25));
        executeButton.setVisible(true);

        rceStopButton = new JButton("Stop");
        rceStopButton.setMaximumSize(new Dimension(90, 25));
        rceStopButton.setVisible(false);

        // Add action listeners
        executeButton.addActionListener(e -> {
            mainExtension.executeRCEPayload(commandTxt.getText());
            rceStopButton.setVisible(true);
            executeButton.setVisible(false);
        });

        rceStopButton.addActionListener(e -> {
            mainExtension.stopMonitoringAction();
            rceStopButton.setVisible(false);
            executeButton.setVisible(true);
        });

        // Add components to panel
        rceInputPanel.add(Box.createRigidArea(new Dimension(5, 0)));
        rceInputPanel.add(rceInfoIconLabel);
        rceInputPanel.add(Box.createRigidArea(new Dimension(5, 0)));
        rceInputPanel.add(platformLabel);
        rceInputPanel.add(Box.createRigidArea(new Dimension(5, 0)));
        rceInputPanel.add(platformLabel);
        rceInputPanel.add(Box.createRigidArea(new Dimension(5, 0)));
        rceInputPanel.add(osComboBox);
        rceInputPanel.add(Box.createRigidArea(new Dimension(5, 0)));
        rceInputPanel.add(commandLabel);
        rceInputPanel.add(Box.createRigidArea(new Dimension(5, 0)));
        rceInputPanel.add(commandTxt);
        rceInputPanel.add(Box.createRigidArea(new Dimension(5, 0)));
        rceInputPanel.add(executeButton);
        rceInputPanel.add(rceStopButton);

        return rceInputPanel;
    }

    private JPanel createPayloadPanel() {
        JPanel rcePayloadPanel = new JPanel();
        rcePayloadPanel.setLayout(new BoxLayout(rcePayloadPanel, BoxLayout.X_AXIS));
        rcePayloadPanel.setAlignmentX(Component.CENTER_ALIGNMENT);

        JLabel rcePayloadLabel = new JLabel("Payload ");
        rcePayloadTxt = new JTextArea(8, 55);
        rcePayloadTxt.setEditable(false);
        rcePayloadTxt.setLineWrap(true);
        rcePayloadTxt.setWrapStyleWord(true);
        rcePayloadTxt.setBackground(new Color(245, 245, 245));
        JScrollPane rcePayloadScrollPane = new JScrollPane(rcePayloadTxt);
        rcePayloadScrollPane.setMaximumSize(new Dimension(600, 200));

        rcePayloadPanel.add(rcePayloadLabel);
        rcePayloadPanel.add(Box.createRigidArea(new Dimension(5, 0)));
        rcePayloadPanel.add(rcePayloadScrollPane);

        return rcePayloadPanel;
    }

    private JPanel createOutputPanel() {
        JPanel rceOutputPanel = new JPanel();
        rceOutputPanel.setLayout(new BoxLayout(rceOutputPanel, BoxLayout.X_AXIS));

        JLabel rceOutputLabel = new JLabel("Output ");
        rceOutputLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

        rceOutputTxt = new JTextArea(8, 55);
        rceOutputTxt.setEditable(false);
        rceOutputTxt.setLineWrap(true);
        rceOutputTxt.setWrapStyleWord(true);
        rceOutputTxt.setBackground(new Color(245, 245, 245));
        JScrollPane rceOutputScrollPane = new JScrollPane(rceOutputTxt);
        rceOutputScrollPane.setMaximumSize(new Dimension(600, 200));

        rceOutputPanel.add(rceOutputLabel);
        rceOutputPanel.add(Box.createRigidArea(new Dimension(5, 0)));
        rceOutputPanel.add(rceOutputScrollPane);

        return rceOutputPanel;
    }

    private void setupHoverDialog(JLabel infoIconLabel) {
        JDialog rceHoverDialog = new JDialog(SwingUtilities.getWindowAncestor(this), "Info", Dialog.ModalityType.MODELESS);
        rceHoverDialog.setUndecorated(true);
        rceHoverDialog.setSize(300, 615);

        JPanel rceDialogContent = new JPanel();
        rceDialogContent.setBorder(BorderFactory.createLineBorder(Color.BLACK));
        rceDialogContent.setLayout(new BorderLayout());

        JLabel rceDialogTitleLabel = new JLabel("Constraints", SwingConstants.CENTER);
        rceDialogTitleLabel.setFont(new Font("Arial", Font.BOLD, 14));
        rceDialogTitleLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        rceDialogContent.add(rceDialogTitleLabel, BorderLayout.NORTH);

        // Create platform-specific context panes
        setupPlatformContextPanes(rceDialogContent);

        rceHoverDialog.add(rceDialogContent);
        setupHoverDialogListeners(infoIconLabel, rceHoverDialog, rceDialogContent);
    }

    private void setupPlatformContextPanes(JPanel dialogContent) {
        JTextPane[] contextPanes = {
            createContextPane("Windows PowerShell", createPowerShellContent()),
            createContextPane("Linux Shell + Ping", createLinuxShPingContent()),
            createContextPane("Linux Shell + Nslookup", createLinuxShNsContent()),
            createContextPane("Linux Bash + Ping", createLinuxBashPingContent()),
            createContextPane("Linux Bash + Nslookup", createLinuxBashNsContent())
        };

        // Add change listener to platform combo box
        osComboBox.addActionListener(e -> {
            String selectedPlatform = (String) osComboBox.getSelectedItem();
            dialogContent.remove(1); // Remove current context
            
            switch (selectedPlatform) {
                case "Windows PowerShell":
                    dialogContent.add(contextPanes[0], BorderLayout.CENTER);
                    break;
                case "Linux (sh + ping)":
                    dialogContent.add(contextPanes[1], BorderLayout.CENTER);
                    break;
                case "Linux (sh + nslookup)":
                    dialogContent.add(contextPanes[2], BorderLayout.CENTER);
                    break;
                case "Linux (bash + ping)":
                    dialogContent.add(contextPanes[3], BorderLayout.CENTER);
                    break;
                case "Linux (bash + nslookup)":
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

    private String createPowerShellContent() {
        return "⦿  Uses PowerShell for command execution\n\n" +
            "⦿  Requires PowerShell execution rights\n\n" +
            "⦿  Uses nslookup for DNS exfiltration\n\n" +
            "⦿  Output is hex encoded automatically\n\n" +
            "⦿  Case sensitivity is preserved\n\n" +
            "⦿  Special characters are preserved";
    }

    private String createLinuxShPingContent() {
        return "⦿  Uses Linux sh shell for command execution\n\n" +
            "⦿  Requires base64 command access\n\n" +
            "⦿  Requires ping command access\n\n" +
            "⦿  Uses ping for DNS exfiltration\n\n" +
            "⦿  Output is hex encoded automatically\n\n" +
            "⦿  Case sensitivity is preserved\n\n" +
            "⦿  Special characters are preserved";
    }

    private String createLinuxShNsContent() {
        return "⦿  Uses Linux sh shell for command execution\n\n" +
            "⦿  Requires base64 command access\n\n" +
            "⦿  Requires nslookup command access\n\n" +
            "⦿  Uses nslookup for DNS exfiltration\n\n" +
            "⦿  Output is hex encoded automatically\n\n" +
            "⦿  Case sensitivity is preserved\n\n" +
            "⦿  Special characters are preserved";
    }

    private String createLinuxBashPingContent() {
        return "⦿  Uses Linux bash shell for command execution\n\n" +
            "⦿  Requires base64 command access\n\n" +
            "⦿  Requires ping command access\n\n" +
            "⦿  Uses ping for DNS exfiltration\n\n" +
            "⦿  Output is hex encoded automatically\n\n" +
            "⦿  Case sensitivity is preserved\n\n" +
            "⦿  Special characters are preserved";
    }

    private String createLinuxBashNsContent() {
        return "⦿  Uses Linux bash shell for command execution\n\n" +
            "⦿  Requires base64 command access\n\n" +
            "⦿  Requires nslookup command access\n\n" +
            "⦿  Uses nslookup for DNS exfiltration\n\n" +
            "⦿  Output is hex encoded automatically\n\n" +
            "⦿  Case sensitivity is preserved\n\n" +
            "⦿  Special characters are preserved";
    }

    // Getters for components that need to be accessed from main extension
    public JTextArea getRcePayloadTxt() {
        return rcePayloadTxt;
    }

    public JTextArea getRceOutputTxt() {
        return rceOutputTxt;
    }

    public JTextPane getRceBurpCollaboratorDomainTxt() {
        return rceBurpCollaboratorDomainTxt;
    }

    public JProgressBar getRceProgressBar() {
        return rceProgressBar;
    }

    public JButton getRceStopButton() {
        return rceStopButton;
    }

    public JButton getExecuteButton() {
        return executeButton;
    }

    public JComboBox<String> getOsComboBox() {
        return osComboBox;
    }

    public JTextField getCommandTxt() {
        return commandTxt;
    }
}