package burp;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

public class ToggleSwitch extends JPanel {
    private boolean activated = false;
    private Color switchColor = new Color(200, 200, 200);
    private Color buttonColor = new Color(255, 255, 255);
    private Color borderColor = new Color(50, 50, 50);
    private Color activeSwitch = new Color(0, 125, 255);
    private int borderRadius = 10;

    public ToggleSwitch() {
        this.setPreferredSize(new Dimension(41, 21));
        this.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseReleased(MouseEvent e) {
                activated = !activated;
                repaint();
            }
        });
        this.setCursor(new Cursor(Cursor.HAND_CURSOR));
    }

    @Override
    protected void paintComponent(Graphics g) {
        super.paintComponent(g);
        Graphics2D g2 = (Graphics2D) g;
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

        // Background color
        g2.setColor(activated ? activeSwitch : switchColor);
        g2.fillRoundRect(0, 0, getWidth() - 1, getHeight() - 1, borderRadius, borderRadius);

        // Border color
        g2.setColor(borderColor);
        g2.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, borderRadius, borderRadius);

        // Button color
        g2.setColor(buttonColor);
        if (activated) {
            g2.fillRoundRect(getWidth() / 2, 1, (getWidth() - 1) / 2 - 2, getHeight() - 2, borderRadius, borderRadius);
        } else {
            g2.fillRoundRect(1, 1, (getWidth() - 1) / 2 - 2, getHeight() - 2, borderRadius, borderRadius);
        }
    }

    public boolean isSelected() {
        return activated;
    }

    public void setSelected(boolean activated) {
        this.activated = activated;
        repaint();
    }
}