package burp;

public class HexDumpUtil {
    public static String xxdStyle(byte[] data) {
        StringBuilder result = new StringBuilder();
        StringBuilder hex = new StringBuilder();
        StringBuilder ascii = new StringBuilder();
        
        for (int i = 0; i < data.length; i++) {
            // Print offset at start of each line
            if (i % 16 == 0) {
                if (i > 0) {
                    // Pad hex section to full width
                    while (hex.length() < 40) {
                        hex.append(" ");
                    }
                    result.append(hex).append("  ").append(ascii).append("\n");
                    hex.setLength(0);
                    ascii.setLength(0);
                }
                result.append(String.format("%08x: ", i));
            }
            
            // Add hex representation
            hex.append(String.format("%02x", data[i] & 0xFF));
            if (i % 2 == 1) {
                hex.append(" ");
            }
            
            // Add ASCII representation
            if (data[i] >= 32 && data[i] < 127) {
                ascii.append((char) data[i]);
            } else {
                ascii.append(".");
            }
        }
        
        // Handle the last line
        if (hex.length() > 0) {
            // Pad the hex section to full width (48 characters including spaces)
            while (hex.length() < 40) {
                hex.append(" ");
            }
            // Ensure consistent spacing between hex and ASCII sections
            result.append(hex).append("  ").append(ascii);
        }
        
        return result.toString();
    }
}