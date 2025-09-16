#Added JSON Request param detection
#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import threading
import re

# Handle Python 2 encoding
if sys.version_info[0] == 2:
    try:
        reload(sys)
        sys.setdefaultencoding('utf8')
    except:
        pass

# Burp imports
from burp import IBurpExtender, ITab, IHttpListener, IMessageEditorController

# Java imports
from java.lang import Runnable, Integer
from java.awt import BorderLayout, Color, Dimension, FlowLayout
from java.awt.event import ActionListener
from javax.swing.event import ListSelectionListener
from javax.swing import (
    JPanel, JTable, JSplitPane, JScrollPane, 
    JLabel, SwingUtilities, JTabbedPane,
    JButton, JTextPane, JSeparator, SwingConstants,
    BoxLayout, BorderFactory, JTextArea
)
from javax.swing.table import AbstractTableModel, DefaultTableCellRenderer
from java.util import ArrayList
from javax.swing.text import DefaultHighlighter


class BurpExtender(IBurpExtender, ITab, IHttpListener, IMessageEditorController, ActionListener):
    """
    Main Burp Suite extension class that implements SQL injection testing
    by comparing original, modified (with single quote), and repaired (with double quote) requests.
    """
    
    def registerExtenderCallbacks(self, callbacks):
        """Initialize the extension and set up the UI"""
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Tripwire Extension")
        
        self._log = ArrayList()
        self._tableModel = LogTableModel(self._log)
        self._lock = threading.Lock()
        self.currentRequestNumber = 1
        self._currentlyDisplayedItem = None
        
        self._captureEnabled = False

        self._setupUI()

        self._evidenceTab = None
        
        callbacks.registerHttpListener(self)
        callbacks.addSuiteTab(self)
        
        print("Tripwire Extension loaded successfully!")
    
    def _setupUI(self):
        """Create and configure the main user interface"""
        self._mainPanel = JPanel(BorderLayout())
        
        # Create horizontal split pane
        splitPane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        splitPane.setResizeWeight(0.5)
        
        # Left panel - table
        leftPanel = self._createTablePanel()
        splitPane.setLeftComponent(leftPanel)
        
        # Right panel - viewers
        rightPanel = self._createViewerPanel()
        splitPane.setRightComponent(rightPanel)
        
        self._mainPanel.add(splitPane, BorderLayout.CENTER)
    
    def _createTablePanel(self):
        """Create the table panel showing request logs"""
        tablePanel = JPanel(BorderLayout())
        
        self._table = JTable(self._tableModel)
        self._table.setAutoCreateRowSorter(True)
        self._table.getColumn("Result").setCellRenderer(ResultCellRenderer())
        
        self._table.getSelectionModel().addListSelectionListener(
            TableSelectionListener(self)
        )
        
        rowSorter = self._table.getRowSorter()
        rowSorter.toggleSortOrder(0)
        
        columnModel = self._table.getColumnModel()
        columnModel.getColumn(0).setPreferredWidth(50)   # ID
        columnModel.getColumn(1).setPreferredWidth(50)   # Method
        columnModel.getColumn(2).setPreferredWidth(300)  # URL
        columnModel.getColumn(3).setPreferredWidth(80)   # Orig. Len
        columnModel.getColumn(4).setPreferredWidth(80)   # Modif. Len
        columnModel.getColumn(5).setPreferredWidth(80)   # Repair. Len
        columnModel.getColumn(6).setPreferredWidth(100)  # Params
        
        scrollPane = JScrollPane(self._table)
        tablePanel.add(scrollPane, BorderLayout.CENTER)
        
        return tablePanel
    
    def _createViewerPanel(self):
        """Create the viewer panel with tabbed panes for different request/response views"""
        viewerPanel = JPanel(BorderLayout())
        
        self._tabbedPane = JTabbedPane()
        
        self._originalRequestViewer = self._callbacks.createMessageEditor(self, False)
        self._originalResponseViewer = self._callbacks.createMessageEditor(self, False)
        originalPanel = self._createRequestResponsePanel(
            "Original", self._originalRequestViewer, self._originalResponseViewer
        )
        self._tabbedPane.addTab("Original", originalPanel)
        
        # Modified Request/Response tab (with single quote)
        self._modifiedRequestViewer = self._callbacks.createMessageEditor(self, False)
        self._modifiedResponseViewer = self._callbacks.createMessageEditor(self, False)
        modifiedPanel = self._createRequestResponsePanel(
            "Modified", self._modifiedRequestViewer, self._modifiedResponseViewer
        )
        self._tabbedPane.addTab("Modified", modifiedPanel)
        
        # Repaired Request/Response tab (with double quote)
        self._repairedRequestViewer = self._callbacks.createMessageEditor(self, False)
        self._repairedResponseViewer = self._callbacks.createMessageEditor(self, False)
        repairedPanel = self._createRequestResponsePanel(
            "Repaired", self._repairedRequestViewer, self._repairedResponseViewer
        )
        self._tabbedPane.addTab("Repaired", repairedPanel)
        
        self._configPanel = self._createConfigPanel()
        self._tabbedPane.addTab("Configuration", self._configPanel)
        
        viewerPanel.add(self._tabbedPane, BorderLayout.CENTER)
        return viewerPanel
    
    def _createRequestResponsePanel(self, title, requestViewer, responseViewer):
        """Create a split panel showing request and response"""
        panel = JPanel(BorderLayout())
        
        splitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        splitPane.setResizeWeight(0.5)
        
        requestPanel = JPanel(BorderLayout())
        requestPanel.add(JLabel(title + " Request"), BorderLayout.NORTH)
        requestPanel.add(requestViewer.getComponent(), BorderLayout.CENTER)
        splitPane.setTopComponent(requestPanel)
        
        responsePanel = JPanel(BorderLayout())
        responsePanel.add(JLabel(title + " Response"), BorderLayout.NORTH)
        responsePanel.add(responseViewer.getComponent(), BorderLayout.CENTER)
        splitPane.setBottomComponent(responsePanel)
        
        panel.add(splitPane, BorderLayout.CENTER)
        return panel
    
    def getTabCaption(self):
        """Return the tab caption for the Burp Suite interface"""
        return "Tripwire"
    
    def getUiComponent(self):
        """Return the main UI component"""
        return self._mainPanel
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """Process HTTP messages from Burp Suite"""
        if not self._captureEnabled:
            return  # ignore if capture is OFF
        
        # Only process requests from Proxy tool
        if toolFlag != self._callbacks.TOOL_PROXY:
            return
        
        # Only process responses
        if messageIsRequest:
            return
        
        # Process in separate thread to avoid blocking
        t = threading.Thread(target=self._processMessage, args=[messageInfo])
        t.daemon = True
        t.start()
    
    def _processMessage(self, messageInfo):
        """Process a single HTTP message for SQL injection testing"""
        try:
            originalRequest = messageInfo.getRequest()
            originalResponse = messageInfo.getResponse()
            if originalResponse is None:
                return

            requestInfo = self._helpers.analyzeRequest(messageInfo)
            method = requestInfo.getMethod()
            url = requestInfo.getUrl()
            urlPath = url.getPath().lower() if url else ""
            
            excluded_exts = self.get_excluded_extensions()

            if any(urlPath.endswith(ext) for ext in excluded_exts):
                return

            # --- 2. Filter out unwanted paths (logging/analytics/etc.) ---
            SKIP_KEYWORDS = ["log", "metrics", "analytics", "tracking", "telemetry", "ads", "embed"]
            if any(kw in urlPath for kw in SKIP_KEYWORDS):
                return

            # --- 3. Filter based on Content-Type ---
            responseInfo = self._helpers.analyzeResponse(originalResponse)
            headers = responseInfo.getHeaders()
            contentType = next((h for h in headers if h.lower().startswith("content-type")), "")
            if not any(ct in contentType.lower() for ct in ["text/html", "json", "x-www-form-urlencoded"]):
                return

            # Extract non-cookie parameters
            parameters = [p for p in requestInfo.getParameters() if p.getType() != p.PARAM_COOKIE]
            if not parameters:
                try:
                    body_bytes = originalRequest[requestInfo.getBodyOffset():]
                    body_str = self._helpers.bytesToString(body_bytes)

                    content_type = ""
                    for h in requestInfo.getHeaders():
                        if h.lower().startswith("content-type"):
                            content_type = h.lower()
                            break

                    if "application/json" in content_type:
                        import json
                        try:
                            parsed_json = json.loads(body_str)
                            if isinstance(parsed_json, dict):
                                self._processJsonRecursive(messageInfo, parsed_json, [])
                        except Exception as e:
                            print("JSON parse failed:", e)
                except Exception as e:
                    print("Error handling JSON body:", e)

            # For each parameter, test individually
            for param in parameters:
                paramName = param.getName()

                # Build modified request (param + ')
                modifiedRequestResponse = self._performSQLInjection(messageInfo, param, "'")
                modifiedResponse = modifiedRequestResponse.getResponse() if modifiedRequestResponse else None
                result = ""

                if modifiedResponse:
                    responseInfo = self._helpers.analyzeResponse(modifiedResponse)
                    body = modifiedResponse[responseInfo.getBodyOffset():].tostring().lower()
                    
                    sql_signatures = self.get_sql_error_signatures()

                    if any(err in body for err in sql_signatures):
                        result = "Possible(?)"
                        for err in sql_signatures:
                            if err in body:
                                print("  Matched keyword:", err)

                # Build repaired request (param + '')
                repairedRequestResponse = self._performSQLInjection(messageInfo, param, "''")

                # Calculate content lengths
                originalLen = len(originalResponse) if originalResponse else 0
                modifiedLen = (len(modifiedRequestResponse.getResponse())
                            if modifiedRequestResponse and modifiedRequestResponse.getResponse() else 0)
                repairedLen = (len(repairedRequestResponse.getResponse())
                            if repairedRequestResponse and repairedRequestResponse.getResponse() else 0)

                # Create log entry (per parameter)
                logEntry = LogEntry(
                    self.currentRequestNumber,
                    method,
                    str(url),
                    originalLen,
                    modifiedLen,
                    repairedLen,
                    paramName,
                    messageInfo,
                    modifiedRequestResponse,
                    repairedRequestResponse,
                    result
                )

                # Add to log thread-safely
                with self._lock:
                    self._log.add(logEntry)
                    row = self._log.size() - 1
                    SwingUtilities.invokeLater(UpdateTableRunnable(self._tableModel, row))
                    self.currentRequestNumber += 1

        except Exception as e:
            print("Error processing message: " + str(e))
    
    def _processJsonRecursive(self, messageInfo, node, path):
        """Recursively walk JSON dicts/lists and inject payloads at each key/value"""
        if isinstance(node, dict):
            for key, value in node.items():
                current_path = path + [key]
                self._processJsonParam(messageInfo, current_path, node)
                self._processJsonRecursive(messageInfo, value, current_path)
        elif isinstance(node, list):
            for i, item in enumerate(node):
                self._processJsonRecursive(messageInfo, item, path + [str(i)])
    
    def _processJsonParam(self, messageInfo, path, parsed_json):
        try:
            method = self._helpers.analyzeRequest(messageInfo).getMethod()
            url = self._helpers.analyzeRequest(messageInfo).getUrl()
            sql_signatures = self._extender.get_sql_error_signatures()

            import copy, json
            mutated = copy.deepcopy(parsed_json)

            # Walk down path and inject
            node = mutated
            for p in path[:-1]:
                node = node[p]
            last_key = path[-1]
            node[last_key] = str(node[last_key]) + "'"

            new_body = json.dumps(mutated)
            headers = self._helpers.analyzeRequest(messageInfo).getHeaders()
            new_message = self._helpers.buildHttpMessage(headers, new_body)

            httpService = messageInfo.getHttpService()
            modifiedReqResp = self._callbacks.makeHttpRequest(httpService, new_message)

            result = ""
            if modifiedReqResp and modifiedReqResp.getResponse():
                resp = modifiedReqResp.getResponse()
                respInfo = self._helpers.analyzeResponse(resp)
                body = resp[respInfo.getBodyOffset():].tostring().lower()
                if any(err in body for err in sql_signatures):
                    result = "Possible(?)"
                    for err in sql_signatures:
                            if err in body:
                                print("  Matched keyword:", err)
                        

            # Repaired variant
            repaired = copy.deepcopy(parsed_json)
            node = repaired
            for p in path[:-1]:
                node = node[p]
            node[last_key] = str(node[last_key]) + "''"
            repaired_body = json.dumps(repaired)
            repaired_msg = self._helpers.buildHttpMessage(headers, repaired_body)
            repairedReqResp = self._callbacks.makeHttpRequest(httpService, repaired_msg)

            logEntry = LogEntry(
                self.currentRequestNumber,
                method,
                str(url),
                len(messageInfo.getResponse()) if messageInfo.getResponse() else 0,
                len(modifiedReqResp.getResponse()) if modifiedReqResp else 0,
                len(repairedReqResp.getResponse()) if repairedReqResp else 0,
                ".".join(path),  # key path like user.email
                messageInfo,
                modifiedReqResp,
                repairedReqResp,
                result
            )

            with self._lock:
                self._log.add(logEntry)
                row = self._log.size() - 1
                SwingUtilities.invokeLater(UpdateTableRunnable(self._tableModel, row))
                self.currentRequestNumber += 1

        except Exception as e:
            print("Error processing JSON param:", e)
    
    def _performSQLInjection(self, originalMessageInfo, param, payload):
        """Perform SQL injection by modifying a single parameter with the given payload"""
        try:
            originalRequest = originalMessageInfo.getRequest()
            requestInfo = self._helpers.analyzeRequest(originalMessageInfo)

            headers = requestInfo.getHeaders()
            body_bytes = originalRequest[requestInfo.getBodyOffset():]
            body_str = self._helpers.bytesToString(body_bytes)

            # Check if this is JSON
            is_json = any("application/json" in h.lower() for h in headers if h.lower().startswith("content-type"))

            if is_json:
                # --- JSON case ---
                import json, copy

                try:
                    parsed_json = json.loads(body_str)
                except Exception:
                    print("[!] Failed to parse JSON body")
                    return None

                mutated = copy.deepcopy(parsed_json)

                # Only mutate the specific parameter we're testing
                key = param.getName()
                if key in mutated:
                    mutated[key] = str(mutated[key]) + payload
                else:
                    print("[!] JSON key not found:", key)
                    return None

                # Rebuild request
                new_body = json.dumps(mutated)
                modifiedRequest = self._helpers.buildHttpMessage(headers, new_body)

            else:
                # --- Normal case (query, form, cookie, etc.) ---
                newParam = self._helpers.buildParameter(
                    param.getName(),
                    param.getValue() + payload,
                    param.getType()
                )
                modifiedRequest = self._helpers.updateParameter(originalRequest, newParam)

            # Send modified request
            httpService = originalMessageInfo.getHttpService()
            modifiedRequestResponse = self._callbacks.makeHttpRequest(httpService, modifiedRequest)

            return modifiedRequestResponse

        except Exception as e:
            print("Error performing SQL injection: " + str(e))
            return None

    def _createConfigPanel(self):
        panel = JPanel(BorderLayout(10, 10))
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
        panel.setBorder(BorderFactory.createTitledBorder("Extension Settings"))

        topPanel = JPanel(FlowLayout(FlowLayout.CENTER, 40, 10))  
        # (20 = horizontal gap, 10 = vertical gap, tweak if needed)

        if getattr(self, "_captureEnabled", False):
            btn_text, btn_bg = "Capture ON", Color(0, 200, 0)
        else:
            btn_text, btn_bg = "Capture OFF", None

        self._captureButton = JButton(btn_text)
        if btn_bg:
            self._captureButton.setBackground(btn_bg)
        self._captureButton.setPreferredSize(Dimension(120, 35))

        def toggleCapture(_):
            self._captureEnabled = not self._captureEnabled
            if self._captureEnabled:
                self._captureButton.setText("Capture ON")
                self._captureButton.setBackground(Color(0, 200, 0))
            else:
                self._captureButton.setText("Capture OFF")
                self._captureButton.setBackground(None)

        self._captureButton.addActionListener(toggleCapture)
        topPanel.add(self._captureButton)

        # --- Clear Logs Button ---
        clearBtn = JButton("Clear Logs")
        clearBtn.setPreferredSize(Dimension(120,35))
        topPanel.add(clearBtn)
        panel.add(topPanel, BorderLayout.NORTH)

        def onClear(_):
            try:
                # clear the log table
                self._tableModel.clearLogs()

                # also clear all viewers
                try:
                    empty_bytes = bytearray()
                    self._originalRequestViewer.setMessage(empty_bytes, True)
                    self._originalResponseViewer.setMessage(empty_bytes, False)
                    self._modifiedRequestViewer.setMessage(empty_bytes, True)
                    self._modifiedResponseViewer.setMessage(empty_bytes, False)
                    self._repairedRequestViewer.setMessage(empty_bytes, True)
                    self._repairedResponseViewer.setMessage(empty_bytes, False)
                except Exception as e:
                    print("Error clearing viewers:", e)

                # clear Evidence tab 
                if getattr(self, "_evidenceTab", None):
                    try:
                        self._tabbedPane.remove(self._evidenceTab)
                        self._evidenceTab = None
                    except Exception:
                        pass

            except Exception as e:
                print("Error clearing logs:", e)

        clearBtn.addActionListener(onClear)

        panel.add(JSeparator(SwingConstants.HORIZONTAL))
        
        sqlErrorPanel = JPanel()
        sqlErrorPanel.setLayout(BoxLayout(sqlErrorPanel, BoxLayout.Y_AXIS))
        sqlErrorPanel.setBorder(BorderFactory.createTitledBorder("SQL Error"))
        
        self._sqlErrorArea = JTextArea(
            ", ".join([
                '"sql syntax"', '"mysql"', '"odbc"', '"oracle"', '"ora-"',
                '"unclosed quotation mark"', '"syntax error"', '"postgresql"', '"sqlite"'
            ])
        )
        self._sqlErrorArea.setLineWrap(True)
        self._sqlErrorArea.setWrapStyleWord(True)
        
        scrollPane = JScrollPane(self._sqlErrorArea)
        scrollPane.setPreferredSize(Dimension(300, 350))

        buttonPanel = JPanel(FlowLayout(FlowLayout.RIGHT))
        saveButton = JButton("Save signature", actionPerformed=self.saveSqlSignatures)
        clearButton = JButton("Clear signature", actionPerformed=self.clearSqlSignatures)
        buttonPanel.add(saveButton)
        buttonPanel.add(clearButton)

        sqlErrorPanel.add(scrollPane)
        sqlErrorPanel.add(buttonPanel)

        panel.add(sqlErrorPanel, BorderLayout.CENTER)
        
        excludePanel = JPanel()
        excludePanel.setLayout(BoxLayout(excludePanel, BoxLayout.Y_AXIS))
        excludePanel.setBorder(BorderFactory.createTitledBorder("Excluded Extension"))
        
        self._notExtensionArea = JTextArea(
            ",".join([
                '".js"', '".css"', '".png"', '".jpg"', '".jpeg"', 
                '".gif"', '".ico"', '".svg"', '".woff"', '".woff2"', 
                '".ttf"', '".eot"', '".map"', '".mp4"', '".webm"',
            ])
        )
        self._notExtensionArea.setLineWrap(True)
        self._notExtensionArea.setWrapStyleWord(True)
        
        scrollPane = JScrollPane(self._notExtensionArea)
        scrollPane.setPreferredSize(Dimension(300,350))
        
        buttonExtPanel = JPanel(FlowLayout(FlowLayout.RIGHT))
        saveExtButton = JButton("Save Extension", actionPerformed=self.saveExtErrors)
        clearExtButton = JButton("Clear Extension", actionPerformed=self.clearExtErrors)
        buttonExtPanel.add(saveExtButton)
        buttonExtPanel.add(clearExtButton)

        excludePanel.add(scrollPane)
        excludePanel.add(buttonExtPanel)
        
        panel.add(excludePanel, BorderLayout.SOUTH)
        
        return panel
    
    def saveSqlSignatures(self, event):
        self._sqlErrorList = self._extender.get_sql_error_signatures()
        self.sql_signatures = self._sqlErrorList

    def clearSqlSignatures(self, event):
        self._sqlErrorArea.setText("")
        self._sqlErrorList = []
        print("[*] SQL Signature cleared")
        
    def get_sql_error_signatures(self):
        if getattr(self, "_sqlErrorList", None):
            return [s.lower() for s in self._sqlErrorList]
        text = (self._sqlErrorArea.getText() or "").strip()
        items = [s.strip().strip('"').strip("'") for s in text.split(",") if s.strip()]
        return [it.lower() for it in items]
        
    def saveExtErrors(self, event):
        self._extErrorList = self.get_excluded_extensions()
        self.excluded_exts = self._extErrorList

    def clearExtErrors(self, event):
        self._notExtensionArea.setText("")
        self._extErrorList = []
        print("[*] Excluded Extension cleared")
    
    def get_excluded_extensions(self):
        # Return extensions in a canonical form, e.g. ".js", "png" -> ".png"
        if getattr(self, "_extErrorList", None):
            raw = self._extErrorList
        else:
            text = (self._notExtensionArea.getText() or "").strip()
            raw = [s.strip().strip('"').strip("'") for s in text.split(",") if s.strip()]

        out = []
        for it in raw:
            if not it:
                continue
            # if user wrote ".js" or "js" -> normalize to ".js"
            val = it.lower()
            if not val.startswith("."):
                val = "." + val
            out.append(val)
        return out
    
    def _createTabs(self):
        """Create the lower tabs (Original, Modified, Repaired, Evidence)"""
        self._requestViewer = self._callbacks.createMessageEditor(self, False)
        self._modifiedViewer = self._callbacks.createMessageEditor(self, False)
        self._repairedViewer = self._callbacks.createMessageEditor(self, False)

        self._tabs = JTabbedPane()
        self._tabs.addTab("Original Request/Response", self._requestViewer.getComponent())
        self._tabs.addTab("Modified Request/Response", self._modifiedViewer.getComponent())
        self._tabs.addTab("Repaired Request/Response", self._repairedViewer.getComponent())
        
        # evidence tab placeholder (added dynamically only if needed)
        self._evidenceTab = None

        return self._tabs

    def _updateTabs(self, logEntry):
        """Update tab contents when a row is selected"""
        self._requestViewer.setMessage(logEntry.originalMessage.getRequest(), True)
        if logEntry.modifiedMessage:
            self._modifiedViewer.setMessage(logEntry.modifiedMessage.getResponse(), False)
        if logEntry.repairedMessage:
            self._repairedViewer.setMessage(logEntry.repairedMessage.getResponse(), False)

        # Remove evidence tab if it exists
        if self._evidenceTab is not None:
            index = self._tabs.indexOfComponent(self._evidenceTab)
            if index != -1:
                self._tabs.remove(index)
            self._evidenceTab = None

        # Add evidence tab only if result == "Possible(?)"
        if logEntry.result == "Possible(?)" and logEntry.modifiedMessage:
            modifiedResponse = logEntry.modifiedMessage.getResponse()
            if modifiedResponse:
                responseInfo = self._helpers.analyzeResponse(modifiedResponse)
                body = modifiedResponse[responseInfo.getBodyOffset():].tostring()

                self._evidenceTab = self._createEvidenceTab(body)
                self._tabs.addTab("Evidence", self._evidenceTab)
    
    def _createEvidenceTab(self, messageInfo):
        """Create the Evidence tab with highlighted SQL keywords in the response."""
        # Create a standard Burp message viewer (like Original/Modified tabs)
        viewer = self._callbacks.createMessageEditor(None, False)
        viewer.setMessage(messageInfo.getResponse(), False)

        try:
            # Extract body text for keyword highlighting
            response = messageInfo.getResponse()
            if response:
                resInfo = self._helpers.analyzeResponse(response)
                body_bytes = response[resInfo.getBodyOffset():]
                body_text = self._helpers.bytesToString(body_bytes)
                #sql_signatures = self._extender.get_sql_error_signatures()

                # Build a JTextPane overlay for highlighting
                textPane = JTextPane()
                textPane.setEditable(False)
                textPane.setText(body_text)

                highlighter = textPane.getHighlighter()
                highlighter.removeAllHighlights()
                painter = DefaultHighlighter.DefaultHighlightPainter(Color(255, 255, 0))
                
                sql_signatures = self.get_sql_error_signatures()
                text_lower = body_text.lower()
                for keyword in sql_signatures:
                    kw = keyword.lower()
                    start = 0
                    while True:
                        idx = text_lower.find(kw, start)
                        if idx == -1:
                            break
                        try:
                            highlighter.addHighlight(idx, idx + len(kw), painter)
                        except:
                            pass
                        start = idx + len(kw)

                # Wrap both Burp viewer + evidence panel
                tabs = JTabbedPane()
                tabs.addTab("Raw", viewer.getComponent())
                tabs.addTab("Highlighted", JScrollPane(textPane))

                return tabs

        except Exception as e:
            # fallback to just Burp viewer if highlighting fails
            return viewer.getComponent()

    def _highlightKeyword(self, textPane, keyword, highlighter):
        """Highlight all occurrences of keyword in yellow inside textPane (case-insensitive)"""
        try:
            doc = textPane.getDocument()
            text = doc.getText(0, doc.getLength()).lower()
        except Exception:
            # fallback - if Document access fails, use getText()
            text = textPane.getText().lower()

        kw = keyword.lower()
        start = 0
        painter = DefaultHighlighter.DefaultHighlightPainter(Color(255, 255, 0))  # yellow painter
        while True:
            idx = text.find(kw, start)
            if idx == -1:
                break
            try:
                highlighter.addHighlight(idx, idx + len(kw), painter)
            except Exception:
                # ignore highlight errors (e.g., invalid bounds)
                pass
            start = idx + len(kw)
    
    # IMessageEditorController implementation
    def getHttpService(self):
        """Return the HTTP service for the currently displayed item"""
        return (self._currentlyDisplayedItem.getHttpService() 
                if self._currentlyDisplayedItem else None)
    
    def getRequest(self):
        """Return the request for the currently displayed item"""
        return (self._currentlyDisplayedItem.getRequest() 
                if self._currentlyDisplayedItem else None)
    
    def getResponse(self):
        """Return the response for the currently displayed item"""
        return (self._currentlyDisplayedItem.getResponse() 
                if self._currentlyDisplayedItem else None)
    
    # ActionListener implementation
    def actionPerformed(self, actionEvent):
        if actionEvent.getSource() == self._captureButton:
            self._captureEnabled = not getattr(self, '_captureEnabled', False)
            if self._captureEnabled:
                self._captureButton.setText("Capture ON")
                try:
                    self._captureButton.setBackground(Color(0, 200, 0))  # green
                    self._captureButton.setOpaque(True)
                except:
                    pass
            else:
                self._captureButton.setText("Capture OFF")
                try:
                    self._captureButton.setBackground(None)  # default
                    self._captureButton.setOpaque(False)
                except:
                    pass

class ResultCellRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        comp = super(ResultCellRenderer, self).getTableCellRendererComponent(
            table, value, isSelected, hasFocus, row, column)

        if value == "Possible(?)":
            comp.setBackground(Color(255, 230, 150))
            comp.setForeground(Color(120, 60, 0))  
        else:
            comp.setBackground(Color.white)
            comp.setForeground(Color.black)

        return comp

class LogEntry:
    """Data class representing a single log entry with original, modified, and repaired requests"""
    
    def __init__(self, id, method, url, originalLen, modifiedLen, repairedLen, params,
                 originalRequestResponse, modifiedRequestResponse, repairedRequestResponse, result=""):
        self._id = id
        self._method = method
        self._url = url
        self._originalLen = originalLen
        self._modifiedLen = modifiedLen
        self._repairedLen = repairedLen
        self._params = params
        self._originalRequestResponse = originalRequestResponse
        self._modifiedRequestResponse = modifiedRequestResponse
        self._repairedRequestResponse = repairedRequestResponse
        self.result = result

class LogTableModel(AbstractTableModel):
    def __init__(self, log):
        self._log = log
        self._columnNames = ["ID", "Method", "URL", "Orig. Len", "Modif. Len", "Repair. Len", "Params", "Result"]
    
    def getRowCount(self):
        return self._log.size()
    
    def getColumnCount(self):
        return len(self._columnNames)
    
    def getColumnName(self, columnIndex):
        return self._columnNames[columnIndex]
    
    def getValueAt(self, rowIndex, columnIndex):
        logEntry = self._log.get(rowIndex)
        
        if columnIndex == 0:
            return Integer(rowIndex + 1)  
        elif columnIndex == 1:
            return logEntry._method
        elif columnIndex == 2:
            return logEntry._url
        elif columnIndex == 3:
            return logEntry._originalLen
        elif columnIndex == 4:
            return logEntry._modifiedLen
        elif columnIndex == 5:
            return logEntry._repairedLen
        elif columnIndex == 6:
            return logEntry._params
        elif columnIndex == 7:
            return logEntry.result
        
        return ""
    
    def getColumnClass(self, columnIndex):
        if columnIndex in [0, 3, 4, 5, 6]:
            return Integer  # numeric sorting
        return str
    
    def clearLogs(self):
        self._log.clear()
        self.fireTableDataChanged()

class HighlightedTextPane(JTextPane):
    def __init__(self, keywords):
        super(HighlightedTextPane, self).__init__()
        self.keywords = keywords
        self.setEditable(False)

    def setTextWithHighlights(self, text):
        self.setText(text)
        highlighter = self.getHighlighter()
        highlighter.removeAllHighlights()
        content = self.getText().lower()
        for kw in self.keywords:
            start = 0
            while True:
                idx = content.find(kw.lower(), start)
                if idx == -1:
                    break
                highlighter.addHighlight(
                    idx,
                    idx + len(kw),
                    DefaultHighlighter.DefaultHighlightPainter(Color.yellow)
                )
                start = idx + len(kw)

class TableSelectionListener(ListSelectionListener):
    """Listener for table selection events to update the viewers and optionally add Evidence tab"""

    def __init__(self, extender):
        self._extender = extender

    def valueChanged(self, e):
        if e.getValueIsAdjusting():
            return

        selectedRow = self._extender._table.getSelectedRow()
        if selectedRow < 0:
            # no selection -> remove evidence tab if present
            self._removeEvidenceTab()
            return

        modelRow = self._extender._table.convertRowIndexToModel(selectedRow)
        logEntry = self._extender._log.get(modelRow)

        # set the currently displayed item for IMessageEditorController
        self._extender._currentlyDisplayedItem = logEntry._originalRequestResponse

        # Update Original viewers
        try:
            if logEntry._originalRequestResponse:
                self._extender._originalRequestViewer.setMessage(
                    logEntry._originalRequestResponse.getRequest(), True)
                self._extender._originalResponseViewer.setMessage(
                    logEntry._originalRequestResponse.getResponse(), False)
        except Exception:
            pass

        # Update Modified viewers
        try:
            if logEntry._modifiedRequestResponse:
                self._extender._modifiedRequestViewer.setMessage(
                    logEntry._modifiedRequestResponse.getRequest(), True)
                self._extender._modifiedResponseViewer.setMessage(
                    logEntry._modifiedRequestResponse.getResponse(), False)
        except Exception:
            pass

        # Update Repaired viewers
        try:
            if logEntry._repairedRequestResponse:
                self._extender._repairedRequestViewer.setMessage(
                    logEntry._repairedRequestResponse.getRequest(), True)
                self._extender._repairedResponseViewer.setMessage(
                    logEntry._repairedRequestResponse.getResponse(), False)
        except Exception:
            pass

        # Remove previous Evidence tab (if any)
        self._removeEvidenceTab()

        # Create Evidence tab only if result == "Possible(?)" and modified response contains keywords
        try:
            if getattr(logEntry, "result", "") == "Possible(?)" and logEntry._modifiedRequestResponse:

                resp_bytes = logEntry._modifiedRequestResponse.getResponse()

                if resp_bytes:
                    try:
                        resInfo = self._extender._helpers.analyzeResponse(resp_bytes)
                        body_bytes = resp_bytes[resInfo.getBodyOffset():]
                        body_text = self._extender._helpers.bytesToString(body_bytes)
                    except Exception as e:
                        print("[ERROR] analyzeResponse/bytesToString failed:", e)
                        try:
                            body_text = resp_bytes.tostring()
                        except Exception:
                            body_text = ""
                    
                    sql_signatures = self._extender.get_sql_error_signatures()
                    
                    if body_text and any(err in body_text.lower() for err in sql_signatures):
                        # create and insert Evidence tab at position 2
                        evidence_comp = self._extender._createEvidenceTab(logEntry._modifiedRequestResponse)
                        self._extender._evidenceTab = evidence_comp
                        try:
                            # insert at index 2 (Original|Modified|Evidence|Repaired|Configuration)
                            self._extender._tabbedPane.insertTab("Evidence", None, evidence_comp, None, 2)
                            idx = self._extender._tabbedPane.indexOfComponent(evidence_comp)
                            if idx != -1:
                                self._extender._tabbedPane.setSelectedIndex(idx)
                        except Exception:
                            try:
                                self._extender._tabbedPane.addTab("Evidence", evidence_comp)
                            except:
                                pass
        except Exception:
            # swallow UI errors to avoid breaking the listener
            pass

    def _removeEvidenceTab(self):
        try:
            if hasattr(self._extender, "_evidenceTab") and self._extender._evidenceTab is not None:
                idx = self._extender._tabbedPane.indexOfComponent(self._extender._evidenceTab)
                if idx != -1:
                    self._extender._tabbedPane.removeTabAt(idx)
                self._extender._evidenceTab = None
        except Exception:
            pass

class UpdateTableRunnable(Runnable):
    """Runnable for updating the table model in the Swing EDT"""
    
    def __init__(self, tableModel, row):
        self._tableModel = tableModel
        self._row = row
    
    def run(self):
        """Execute the table update"""
        self._tableModel.fireTableRowsInserted(self._row, self._row)