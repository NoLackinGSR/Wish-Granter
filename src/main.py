# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from __future__ import print_function

# Ajouter l'import manquant de urllib2
try:
    # Python 2
    import urllib2
except ImportError:
    # Python 3
    import urllib.request as urllib2

import os
import sys
from burp import IBurpExtender, ITab, IContextMenuFactory
from javax.swing import JMenuItem, JOptionPane, SwingWorker
from java.util import ArrayList
import json

class BurpExtender(IBurpExtender, ITab):
    def registerExtenderCallbacks(self, callbacks):
        try:
            # Initialisation de base
            self._callbacks = callbacks
            self._helpers = callbacks.getHelpers()
            callbacks.setExtensionName("Wish Granter")
            
            # Configuration du chemin
            extension_dir = os.path.dirname(callbacks.getExtensionFilename())
            if extension_dir not in sys.path:
                sys.path.append(extension_dir)
            
            # Import des modules
            from core import WishGranterService
            from ui import BurpAIMainPanel
            
            # Initialisation du service
            self.service = WishGranterService()
            self.service.initialize(callbacks)
            
            # Initialisation de l'UI
            self.panel = BurpAIMainPanel(self.service)
            
            # Initialisation des références
            self.initializePanels()
            
            # Enregistrement des composants Burp
            callbacks.addSuiteTab(self)
            callbacks.registerContextMenuFactory(BurpExtenderContextMenu(self))
            
            callbacks.printOutput("[+] Extension loaded successfully")
            
        except Exception as e:
            callbacks.printError("Error during initialization: " + str(e))
            raise

    def initializePanels(self):
        """Initialise les références pour tous les panneaux"""
        panels = [
            self.panel.testPanel,
            self.panel.aiResponsePanel,
            self.panel.configPanel,
            self.panel.httpDisplayPanel,
            self.panel.chatPanel,
            self.panel.systemPromptPanel,
            self.panel.detailedPromptPanel,
            self.panel.templatesPanel
        ]
        
        for panel in panels:
            panel.extender = self
            panel._callbacks = self._callbacks
            panel._helpers = self._helpers

    def getTabCaption(self):
        return "Wish Granter"

    def getUiComponent(self):
        return self.panel

    def sendToAI(self, prompt, debug=False):
        """Envoie une requête à l'API et retourne la réponse"""
        try:
            if debug:
                self._callbacks.printOutput("Sending prompt to AI (length: {0})".format(len(prompt)))
            
            response = self.service.analyze(prompt)
            
            if debug:
                self._callbacks.printOutput("Received response from AI")
            
            return response
            
        except Exception as e:
            error_msg = "Error in sendToAI: {0}".format(str(e))
            self._callbacks.printError(error_msg)
            raise Exception(error_msg)

class BurpExtenderContextMenu(IContextMenuFactory):
    def __init__(self, extender):
        self.extender = extender
        self._helpers = extender._helpers
        self.is_analyzing = False

    def createMenuItems(self, invocation):
        self._invocation = invocation
        if not invocation.getSelectedMessages():
            return ArrayList()
        
        menuList = ArrayList()
        menuItem = JMenuItem("Analyze with AI")
        menuItem.addActionListener(lambda e: self.analyzeWithAI(e))
        menuList.add(menuItem)
        return menuList

    def analyzeWithAI(self, event):
        try:
            if self.is_analyzing:
                return
            
            self.is_analyzing = True
            
            messageInfo = self._invocation.getSelectedMessages()[0]
            url = str(self._helpers.analyzeRequest(messageInfo).getUrl())
            request = messageInfo.getRequest()
            response = messageInfo.getResponse() if messageInfo.getResponse() else b""
            
            # Ensure UTF-8 encoding for requests and responses
            request_str = self._helpers.bytesToString(request).encode('utf-8').decode('utf-8', errors='replace')
            response_str = self._helpers.bytesToString(response).encode('utf-8').decode('utf-8', errors='replace') if response else ""
            
            self.extender.panel.mainTabs.setSelectedComponent(
                self.extender.panel.aiResponsePanel
            )
            response_area = self.extender.panel.aiResponsePanel.addNewAnalysis(url)
            self.extender.panel.httpDisplayPanel.updateContent(request, response)
            response_area.setText("Analysis in progress...")
            
            context = "URL: {0}\n\nRequest:\n{1}\n\nResponse:\n{2}".format(
                url, request_str, response_str
            )
            self.extender.panel.chatPanel.current_context = context
            
            detailed_prompt = self.extender.panel.detailedPromptPanel.prompt_area.getText()
            prompt = "{}\n\nURL: {}\n\nRequest:\n{}\n\nResponse:\n{}".format(
                detailed_prompt, url, request_str, response_str
            )
            
            worker = AnalysisWorker(self.extender, prompt, response_area, self)
            worker.execute()
            
        except Exception as e:
            self.extender._callbacks.printError("Error in analyzeWithAI: {0}".format(str(e)))
            if response_area:
                response_area.setText("Error: {0}".format(str(e)))
            self.is_analyzing = False

class AnalysisWorker(SwingWorker):
    def __init__(self, extender, prompt, response_area, menu_factory):
        SwingWorker.__init__(self)
        self.extender = extender
        self.prompt = prompt
        self.response_area = response_area
        self.menu_factory = menu_factory
        self.worker_cancelled = [False]

    def doInBackground(self):
        try:
            if self.worker_cancelled[0]:
                return "Analysis cancelled by user"
                
            self.extender._callbacks.printOutput(
                "Starting AI analysis (prompt length: {})".format(len(self.prompt))
            )
            result = self.extender.service.analyze(self.prompt)
            self.extender._callbacks.printOutput("Analysis completed")
            return result
            
        except Exception as e:
            self.extender._callbacks.printError("Error in analysis: {}".format(str(e)))
            return "Error: {}".format(str(e))

    def done(self):
        try:
            if not self.worker_cancelled[0]:
                result = self.get()
                self.response_area.setText(result)
                self.response_area.setCaretPosition(0)
        except Exception as e:
            self.extender._callbacks.printError("Error displaying results: {}".format(str(e)))
            self.response_area.setText("Error: {}".format(str(e)))
        finally:
            # Reset the analyzing flag
            self.menu_factory.is_analyzing = False 