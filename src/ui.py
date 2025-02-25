# -*- coding: utf-8 -*-

from javax.swing import (
    JPanel, JButton, JTextField, JLabel, JTextArea, JScrollPane,
    JOptionPane, JMenuItem, BoxLayout, Box, JTabbedPane, JPopupMenu, JCheckBox,
    BorderFactory, JFileChooser, JSeparator, JSplitPane, SwingConstants, JList,
    KeyStroke, AbstractAction, ListSelectionModel, SwingWorker, JPasswordField
)
from javax.swing.border import TitledBorder, EmptyBorder
from java.awt import (
    BorderLayout, FlowLayout, GridBagLayout, GridBagConstraints,
    Dimension, Insets, Font, Toolkit, Color, RenderingHints
)
from java.awt.event import KeyAdapter, KeyEvent, FocusAdapter, MouseAdapter, ActionEvent, KeyListener
from java.lang import System, Runtime
from javax.swing.text import JTextComponent
from javax.swing.event import DocumentListener
from java.awt.datatransfer import StringSelection, DataFlavor
import os
import json
from burp import IMessageEditorController
from core import RequestManager
from utils import (
    ModernScrollBarUI, styleButton, add_copy_paste_menu, create_titled_border,
    createStyledComponent, ErrorHandler, createScrollPane, JTextFieldWithPlaceholder
)
from constants import (
    BACKGROUND_COLOR, TEXT_COLOR, ACCENT_COLOR, INPUT_BG, BORDER_COLOR,
    DEFAULT_SYSTEM_PROMPT, DEFAULT_DETAILED_PROMPT,
    DEFAULT_API_URL, DEFAULT_API_KEY, DEFAULT_MODEL, DEFAULT_TIMEOUT
)
from main import AnalysisWorker

TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")
if not os.path.exists(TEMPLATES_DIR):
    os.makedirs(TEMPLATES_DIR)

# Modifier la constante DEFAULT_DETAILED_PROMPT pour inclure le contexte
DEFAULT_DETAILED_PROMPT = """Analyze this HTTP interaction briefly.

1. CONTEXT
- What type of request is this? (static file, API call, form submission, etc.)
- What appears to be its purpose?
- What kind of data/content is being exchanged?

2. QUICK SECURITY ASSESSMENT
- Key security findings
- Most critical vulnerabilities (if any)
- Notable security headers or controls

3. RECOMMENDATIONS
Keep recommendations concise and actionable.

Note: For detailed analysis, use the templates panel.

Keep your response brief but informative. Focus on helping the pentester understand what they're looking at and any immediate security concerns."""

class BasePanel(JPanel):
    """Classe de base pour tous les panneaux avec des fonctionnalités communes"""
    def __init__(self, title=None):
        JPanel.__init__(self)
        self.setLayout(BorderLayout(10, 10))
        self.setBackground(BACKGROUND_COLOR)
        if title:
            self.setBorder(create_titled_border(title))
    def createScrollableTextArea(self, editable=False):
        """Crée une zone de texte scrollable avec le style commun"""
        textArea = JTextArea()
        textArea.setEditable(editable)
        textArea.setLineWrap(True)
        textArea.setWrapStyleWord(True)
        textArea.setBackground(INPUT_BG)
        textArea.setForeground(TEXT_COLOR)
        textArea.setCaretColor(TEXT_COLOR)
        
        scrollPane = createScrollPane(textArea)
        add_copy_paste_menu(textArea)
        return textArea, scrollPane
    def checkExtender(self):
        """Vérifie si l'extender est initialisé"""
        if not hasattr(self, 'extender') or not self.extender:
            JOptionPane.showMessageDialog(
                self,
                "Error: Extender not initialized",
                "Error",
                JOptionPane.ERROR_MESSAGE
            )
            return False
        return True

class APIConfigPanel(BasePanel):
    def __init__(self, service):
        BasePanel.__init__(self, "API Configuration")
        self.service = service
        
        # Charger la configuration au démarrage
        self.config = service.config_manager.load_config()
        
        # Debug pour voir la config chargée
        if hasattr(service, '_callbacks'):
            service._callbacks.printOutput("[APIConfigPanel] Current config: {}".format(self.config))
        
        # Panel principal avec grille
        inputPanel = JPanel(GridBagLayout())
        inputPanel.setBackground(BACKGROUND_COLOR)
        constraints = GridBagConstraints()
        constraints.fill = GridBagConstraints.HORIZONTAL
        constraints.insets = Insets(5, 5, 5, 5)
        constraints.weightx = 1.0
        # Création des champs avec les valeurs de la config
        self.api_url = self.createTextField(self.config.get('api_url', DEFAULT_API_URL))
        self.api_key = JPasswordField(self.config.get('api_key', DEFAULT_API_KEY))
        self.api_key.setEchoChar('*')  # Utiliser un caractère simple
        self.model = self.createTextField(self.config.get('model', DEFAULT_MODEL))
        self.timeout = self.createTextField(str(self.config.get('timeout', DEFAULT_TIMEOUT)))
        # Style du champ password
        self.api_key.setBackground(INPUT_BG)
        self.api_key.setForeground(TEXT_COLOR)
        self.api_key.setCaretColor(TEXT_COLOR)
        # Ajout des champs avec leurs labels
        self.addLabelAndField(inputPanel, constraints, 0, "API URL:", self.api_url)
        self.addLabelAndField(inputPanel, constraints, 1, "API Key:", self.api_key)
        self.addLabelAndField(inputPanel, constraints, 2, "Model:", self.model)
        self.addLabelAndField(inputPanel, constraints, 3, "Timeout (seconds):", self.timeout)
        
        # Show API Key checkbox
        self.show_key_checkbox = JCheckBox("Show API Key", False)
        self.show_key_checkbox.setForeground(TEXT_COLOR)
        self.show_key_checkbox.setBackground(BACKGROUND_COLOR)
        self.show_key_checkbox.addActionListener(self.toggleApiKeyVisibility)
        constraints.gridy = 4
        inputPanel.add(self.show_key_checkbox, constraints)
        
        # Debug Mode checkbox
        self.debug_checkbox = JCheckBox("Debug Mode", self.config.get("debug_mode", False))
        self.debug_checkbox.setForeground(TEXT_COLOR)
        self.debug_checkbox.setBackground(BACKGROUND_COLOR)
        constraints.gridy = 5
        inputPanel.add(self.debug_checkbox, constraints)
        
        # Show Chat checkbox
        self.show_chat_checkbox = JCheckBox("Show Chat Panel", self.config.get("show_chat", True))
        self.show_chat_checkbox.setForeground(TEXT_COLOR)
        self.show_chat_checkbox.setBackground(BACKGROUND_COLOR)
        self.show_chat_checkbox.addActionListener(self.toggleChatVisibility)
        constraints.gridy = 6
        inputPanel.add(self.show_chat_checkbox, constraints)
        
        # Boutons
        buttonPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        buttonPanel.setBackground(BACKGROUND_COLOR)
        
        saveButton = JButton("Save Configuration")
        clearCacheButton = JButton("Clear Cache")
        
        saveButton.addActionListener(self.saveConfig)
        clearCacheButton.addActionListener(self.clearCache)
        
        for btn in [saveButton, clearCacheButton]:
            styleButton(btn, ACCENT_COLOR, TEXT_COLOR)
            buttonPanel.add(btn)
        
        # Layout final
        self.add(inputPanel, BorderLayout.CENTER)
        self.add(buttonPanel, BorderLayout.SOUTH)
    def createTextField(self, value):
        field = JTextField(str(value))
        field.setBackground(INPUT_BG)
        field.setForeground(TEXT_COLOR)
        field.setCaretColor(TEXT_COLOR)
        return field
    def addLabelAndField(self, panel, constraints, y, labelText, field):
        constraints.gridy = y
        
        label = JLabel(labelText)
        label.setForeground(TEXT_COLOR)
        constraints.gridx = 0
        panel.add(label, constraints)
        
        constraints.gridx = 1
        panel.add(field, constraints)
    def toggleApiKeyVisibility(self, event):
        """Bascule l'affichage de la clé API"""
        if self.show_key_checkbox.isSelected():
            self.api_key.setEchoChar('\0')  # Affiche le texte en clair
        else:
            self.api_key.setEchoChar('*')  # Cache avec des astérisques
        self.api_key.repaint()
    def toggleChatVisibility(self, event=None):
        """Gère le changement de visibilité du panneau de chat"""
        show_chat = self.show_chat_checkbox.isSelected()
        if hasattr(self, 'service'):
            # Sauvegarder la configuration
            config = self.service.config_manager.load_config()
            config['show_chat'] = show_chat
            self.service.config_manager.save_config(config)
            
            # Mettre à jour l'UI
            main_panel = self.getParent()
            while main_panel and not isinstance(main_panel, BurpAIMainPanel):
                main_panel = main_panel.getParent()
                
                if isinstance(main_panel, BurpAIMainPanel):
                    main_panel.rightSepPanel.setVisible(show_chat)
                    main_panel.rightPanel.setVisible(show_chat)
                    main_panel.revalidate()
                    main_panel.repaint()
    def saveConfig(self):
        config = {
            "api_url": self.getApiUrl(),
            "api_key": self.getApiKey(),
            "model": self.getModel(),
            "timeout": self.getTimeout(),
            "debug_mode": self.getDebugMode(),
            "show_chat": self.show_chat_checkbox.isSelected()
        }
        
        if self.service.config_manager.save_config(config):
            JOptionPane.showMessageDialog(
                self,
                "Configuration saved successfully",
                "Success",
                JOptionPane.INFORMATION_MESSAGE
            )
        else:
            JOptionPane.showMessageDialog(
                self,
                "Error saving configuration",
                "Error",
                JOptionPane.ERROR_MESSAGE
            )
    def getApiUrl(self): return self.api_url.getText()
    def getApiKey(self):
        """Récupère la clé API du champ password"""
        return ''.join(self.api_key.getPassword())
    def getModel(self): return self.model.getText()
    def getTimeout(self):
        try:
            return int(self.timeout.getText())
        except:
            return 30
    def getDebugMode(self): return self.debug_checkbox.isSelected()
    def clearCache(self, event):
        """Vide le cache des réponses AI"""
        try:
            self.service.cache_manager.cache.clear()
            self.service.cache_manager.save_cache()
            JOptionPane.showMessageDialog(
                self,
                "Cache cleared successfully",
                "Success",
                JOptionPane.INFORMATION_MESSAGE
            )
        except Exception as e:
            JOptionPane.showMessageDialog(
                self,
                "Error clearing cache: " + str(e),
                "Error",
                JOptionPane.ERROR_MESSAGE
            )
    def setApiUrl(self, url):
        self.api_url.setText(url)
    def setApiKey(self, key):
        self.api_key.setText(key)
    def setModel(self, model):
        self.model.setText(model)
    def updateFromConfig(self, config):
        self.api_url.setText(config.get('api_url', ''))
        self.api_key.setText(config.get('api_key', ''))
        self.model.setText(config.get('model', ''))

class ChatPanel(BasePanel):
    def __init__(self, service):
        BasePanel.__init__(self, "Chat")
        self.service = service
        self.history_manager = service.history_manager
        self.conversation_history = []
        self.current_context = None
        
        # Configuration de l'encodage pour les composants texte
        System.setProperty("file.encoding", "UTF-8")
        System.setProperty("swing.defaultlaf", "javax.swing.plaf.metal.MetalLookAndFeel")
        
        # Zone de chat
        self.chatArea, chatScroll = self.createScrollableTextArea(editable=False)
        
        # Zone de saisie améliorée
        inputPanel = JPanel(BorderLayout(5, 5))
        inputPanel.setBackground(BACKGROUND_COLOR)
        inputPanel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(1, 0, 0, 0, BORDER_COLOR),
            EmptyBorder(10, 10, 10, 10)
        ))
        
        # Champ de saisie avec placeholder
        self.questionField = JTextFieldWithPlaceholder("Ask a question about this request/response...")
        self.questionField.setBackground(INPUT_BG)
        self.questionField.setForeground(TEXT_COLOR)
        self.questionField.setCaretColor(TEXT_COLOR)

        class EnterListener(KeyListener):
            def __init__(self, chat_panel):
                self.chat_panel = chat_panel

            def keyPressed(self, e):
                if e.getKeyCode() == KeyEvent.VK_ENTER and e.isControlDown():
                    self.chat_panel.sendQuestion()

            def keyTyped(self, e):
                pass

            def keyReleased(self, e):
                pass

        self.questionField.addKeyListener(EnterListener(self))
        
        # Ajouter des tooltips
        self.questionField.setToolTipText(
            "Enter your question about the current request/response. " +
            "Use natural language to ask about security implications, " +
            "potential vulnerabilities, or technical details."
        )
        
        sendButton = JButton("Send")
        styleButton(sendButton, ACCENT_COLOR, TEXT_COLOR)
        sendButton.addActionListener(lambda e: self.sendMessage())
        
        inputPanel.add(self.questionField, BorderLayout.CENTER)
        inputPanel.add(sendButton, BorderLayout.EAST)
        
        self.add(chatScroll, BorderLayout.CENTER)
        self.add(inputPanel, BorderLayout.SOUTH)

    def sendMessage(self):
        if not self.checkExtender():
            return
        message = self.questionField.getText().strip()
        if not message:
            return
        
        try:
            if self.extender:
                # Construction du prompt sans manipulation d'encodage
                prompt = ""
                if self.current_context:
                    prompt += "Context (HTTP Requests/Responses):\n" + self.current_context + "\n\n"
                    prompt += "You are a penetration testing assistant. Maintain context of our conversation.\n\n"
                    if self.conversation_history:
                        prompt += "Previous conversation:\n"
                        for role, content in self.conversation_history:
                            prompt += "{}: {}\n".format(role, content)
                        prompt += "\n"
                    prompt += "User: {}".format(message)
                    self.conversation_history.append(("User", message))
                self.questionField.setText("")
                
                response = self.extender.sendToAI(prompt)
                self.conversation_history.append(("Assistant", response))
                self.updateChatDisplay()
                
                self.history_manager.save_history(self.conversation_history)
        except Exception as e:
            self.chatArea.append("Error: {}\n\n".format(str(e)))

    def updateChatDisplay(self):
        self.chatArea.setText("")
        for role, content in self.conversation_history:
            self.chatArea.append("{}: {}\n\n".format(role, content))
        self.chatArea.setCaretPosition(self.chatArea.getDocument().getLength())

class HistoryPanel(JPanel):
    def __init__(self):
        JPanel.__init__(self)
        self.setLayout(BorderLayout(10, 10))
        
        # Zone d'historique
        self.history_area = JTextArea()
        self.history_area.setEditable(False)
        self.history_area.setLineWrap(True)
        self.history_area.setWrapStyleWord(True)
        
        historyScroll = JScrollPane(self.history_area)
        historyScroll.getVerticalScrollBar().setUI(ModernScrollBarUI())
        
        # Boutons
        buttonPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        clearButton = JButton("Clear History")
        exportButton = JButton("Export History")
        
        styleButton(clearButton, ACCENT_COLOR, TEXT_COLOR)
        styleButton(exportButton, ACCENT_COLOR, TEXT_COLOR)
        
        clearButton.addActionListener(lambda e: self.clear_history())
        exportButton.addActionListener(lambda e: self.export_history())
        
        buttonPanel.add(clearButton)
        buttonPanel.add(exportButton)
        
        # Layout
        self.add(historyScroll, BorderLayout.CENTER)
        self.add(buttonPanel, BorderLayout.SOUTH)
        
        # Style
        self.setBorder(create_titled_border("Analysis History"))
        add_copy_paste_menu(self.history_area)
    def clear_history(self):
        """Efface l'historique"""
        self.history_area.setText("")
    def export_history(self):
        """Exporte l'historique dans un fichier"""
        try:
            fileChooser = JFileChooser()
            if fileChooser.showSaveDialog(self) == JFileChooser.APPROVE_OPTION:
                file = fileChooser.getSelectedFile()
                with open(file.getPath(), 'w') as f:
                    f.write(self.history_area.getText())
                JOptionPane.showMessageDialog(self,
                    "History exported successfully!",
                    "Success",
                    JOptionPane.INFORMATION_MESSAGE
                )
        except Exception as e:
            JOptionPane.showMessageDialog(self,
                "Error exporting history: " + str(e),
                "Error",
                JOptionPane.ERROR_MESSAGE
            )

class AIResponsePanel(BasePanel):
    def __init__(self):
        BasePanel.__init__(self)
        self.setLayout(BorderLayout())
        
        # Créer un panneau d'onglets avec style
        self.responseTabs = self.createStyledTabbedPane()
        self.tab_counter = 1
        self.response_area = None  # Initialiser à None
        self.add(self.responseTabs, BorderLayout.CENTER)
        
        # Garder une trace des URLs analysées pour éviter les doublons
        self.analyzed_urls = set()
        
        # Variable pour suivre l'analyse en cours
        self.current_analysis = None

    def createStyledTabbedPane(self):
        """Crée un JTabbedPane stylisé"""
        tabs = JTabbedPane()
        tabs.setFont(Font("Segoe UI", Font.PLAIN, 12))
        tabs.setBackground(BACKGROUND_COLOR)
        tabs.setForeground(TEXT_COLOR)
        return tabs

    def createButtonPanel(self, response_area):
        """Crée un panneau de boutons standardisé"""
        buttonPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        buttonPanel.setBackground(BACKGROUND_COLOR)
        
        buttons = [
            ("Cancel Analysis", lambda e: self.cancelAnalysis(response_area)),
            ("Copy to Clipboard", lambda e: self.copyToClipboard(response_area)),
            ("Clear Response", lambda e: self.clearResponse(response_area)),
            ("Close Tab", lambda e: self.closeCurrentTab())
        ]
        
        for text, action in buttons:
            button = JButton(text)
            styleButton(button, ACCENT_COLOR, TEXT_COLOR)
            button.addActionListener(action)
            buttonPanel.add(button)
        
        return buttonPanel

    def update_response(self, text):
        """Callback pour mettre à jour la réponse en streaming"""
        if self.response_area:
            try:
                # Ajouter le nouveau texte à la zone de réponse
                current_text = self.response_area.getText()
                if current_text == "Analysis in progress...\n":
                    self.response_area.setText(text)
                else:
                    self.response_area.setText(current_text + text)
                # Défiler automatiquement vers le bas
                self.response_area.setCaretPosition(self.response_area.getDocument().getLength())
            except Exception as e:
                if hasattr(self, 'extender'):
                    self.extender._callbacks.printError("Error updating response: " + str(e))
    
    def addNewAnalysis(self, url):
        """Ajoute un nouvel onglet d'analyse"""
        try:
            # Normaliser l'URL pour la comparaison
            normalized_url = url.strip()
            
            # Créer un nouvel onglet
            analysisPanel = JPanel(BorderLayout())
            analysisPanel.setBackground(BACKGROUND_COLOR)
            
            # Créer la zone de réponse
            response_area, scrollPane = self.createScrollableTextArea(editable=False)
            self.response_area = response_area  # Garder une référence
            
            # Ajouter les composants au panneau
            analysisPanel.add(scrollPane, BorderLayout.CENTER)
            analysisPanel.add(self.createButtonPanel(response_area), BorderLayout.SOUTH)
            
            # Créer le titre de l'onglet
            tab_title = "Analysis #{} - {}".format(
                self.tab_counter,
                normalized_url[:27] + "..." if len(normalized_url) > 30 else normalized_url
            )
            
            # Ajouter et sélectionner l'onglet
            self.responseTabs.addTab(tab_title, analysisPanel)
            self.responseTabs.setSelectedIndex(self.responseTabs.getTabCount() - 1)
            self.tab_counter += 1
            
            return response_area
            
        except Exception as e:
            if hasattr(self, 'extender'):
                self.extender._callbacks.printError("Error adding new analysis: " + str(e))
            return None

    def copyToClipboard(self, response_area):
        """Copie le contenu dans le presse-papier"""
        try:
            text = response_area.getText()
            if text:
                selection = StringSelection(text)
                clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
                clipboard.setContents(selection, None)
        except Exception as e:
            if hasattr(self, 'extender'):
                self.extender._callbacks.printError("Error copying to clipboard: " + str(e))

    def clearResponse(self, response_area):
        """Efface le contenu de la zone de réponse"""
        try:
            response_area.setText("")
        except Exception as e:
            if hasattr(self, 'extender'):
                self.extender._callbacks.printError("Error clearing response: " + str(e))

    def cancelAnalysis(self, response_area):
        """Annule l'analyse en cours"""
        try:
            response_area.setText("Analysis cancelled by user")
            if hasattr(self, 'current_analysis') and self.current_analysis:
                self.current_analysis.worker_cancelled[0] = True
        except Exception as e:
            if hasattr(self, 'extender'):
                self.extender._callbacks.printError("Error cancelling analysis: " + str(e))

    def closeCurrentTab(self):
        """Ferme l'onglet actuellement sélectionné"""
        try:
            current_index = self.responseTabs.getSelectedIndex()
            if current_index != -1:
                self.responseTabs.remove(current_index)
        except Exception as e:
            if hasattr(self, 'extender'):
                self.extender._callbacks.printError("Error closing tab: " + str(e))

class SystemPromptPanel(JPanel):
    def __init__(self):
        JPanel.__init__(self)
        self.setLayout(BorderLayout(10, 10))
        
        # Zone de prompt système
        self.prompt_area = JTextArea()
        self.prompt_area.setLineWrap(True)
        self.prompt_area.setWrapStyleWord(True)
        self.prompt_area.setText(DEFAULT_SYSTEM_PROMPT)
        
        promptScroll = JScrollPane(self.prompt_area)
        promptScroll.getVerticalScrollBar().setUI(ModernScrollBarUI())
        
        # Boutons
        buttonPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        saveButton = JButton("Save Prompt")
        resetButton = JButton("Reset to Default")
        
        styleButton(saveButton, ACCENT_COLOR, TEXT_COLOR)
        styleButton(resetButton, ACCENT_COLOR, TEXT_COLOR)
        
        saveButton.addActionListener(lambda e: self.save_prompt())
        resetButton.addActionListener(lambda e: self.reset_prompt())
        
        buttonPanel.add(saveButton)
        buttonPanel.add(resetButton)
        
        # Layout
        self.add(promptScroll, BorderLayout.CENTER)
        self.add(buttonPanel, BorderLayout.SOUTH)
        
        # Style
        self.setBorder(create_titled_border("System Prompt"))
        add_copy_paste_menu(self.prompt_area)
    def save_prompt(self):
        if hasattr(self, 'extender'):
            config = self.extender.panel.service.config_manager.load_config()
            config['system_prompt'] = self.prompt_area.getText()
            if self.extender.panel.service.config_manager.save_config(config):
                JOptionPane.showMessageDialog(self,
                    "System prompt saved successfully!",
                    "Success",
                    JOptionPane.INFORMATION_MESSAGE
                )
    def reset_prompt(self):
        self.prompt_area.setText(DEFAULT_SYSTEM_PROMPT)

class DetailedPromptPanel(JPanel):
    def __init__(self):
        JPanel.__init__(self)
        self.setLayout(BorderLayout(10, 10))
        
        # Zone de prompt détaillé
        self.prompt_area = JTextArea()
        self.prompt_area.setLineWrap(True)
        self.prompt_area.setWrapStyleWord(True)
        self.prompt_area.setText(DEFAULT_DETAILED_PROMPT)
        
        promptScroll = JScrollPane(self.prompt_area)
        promptScroll.getVerticalScrollBar().setUI(ModernScrollBarUI())
        
        # Boutons
        buttonPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        saveButton = JButton("Save Analysis Prompt")
        resetButton = JButton("Reset to Default")
        
        styleButton(saveButton, ACCENT_COLOR, TEXT_COLOR)
        styleButton(resetButton, ACCENT_COLOR, TEXT_COLOR)
        
        saveButton.addActionListener(lambda e: self.save_prompt())
        resetButton.addActionListener(lambda e: self.reset_prompt())
        
        buttonPanel.add(saveButton)
        buttonPanel.add(resetButton)
        
        # Layout
        self.add(promptScroll, BorderLayout.CENTER)
        self.add(buttonPanel, BorderLayout.SOUTH)
        
        # Style
        self.setBorder(create_titled_border("Detailed Analysis Prompt"))
        add_copy_paste_menu(self.prompt_area)
    def save_prompt(self):
        if hasattr(self, 'extender'):
            config = self.extender.panel.service.config_manager.load_config()
            config['detailed_prompt'] = self.prompt_area.getText()
            if self.extender.panel.service.config_manager.save_config(config):
                JOptionPane.showMessageDialog(self,
                    "Analysis prompt saved successfully!",
                    "Success",
                    JOptionPane.INFORMATION_MESSAGE
                )
    def reset_prompt(self):
        self.prompt_area.setText(DEFAULT_DETAILED_PROMPT)

class TestPanel(BasePanel):
    def __init__(self):
        BasePanel.__init__(self, "API Test")
        
        # Zone de réponse de test
        self.responseArea, responseScroll = self.createScrollableTextArea(editable=False)
        
        # Boutons
        buttonPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        testButton = JButton("Run Test")
        clearButton = JButton("Clear")
        
        styleButton(testButton, ACCENT_COLOR, TEXT_COLOR)
        styleButton(clearButton, ACCENT_COLOR, TEXT_COLOR)
        
        testButton.addActionListener(self.runTest)
        clearButton.addActionListener(lambda e: self.responseArea.setText(""))
        
        buttonPanel.add(testButton)
        buttonPanel.add(clearButton)
        
        # Layout
        self.add(responseScroll, BorderLayout.CENTER)
        self.add(buttonPanel, BorderLayout.SOUTH)
        
        # Style
        self.setBorder(create_titled_border("API Test"))
        add_copy_paste_menu(self.responseArea)
    
    def runTest(self, event):
        if not self.checkExtender():
            return
            
        self.responseArea.setText("Running test...\n")
        testPrompt = "This is a test prompt to verify the API connection. Please respond with a short acknowledgement."
        
        try:
            # Réutiliser directement le service qui fonctionne déjà
            response = self.extender.service.analyze(testPrompt)
            
            if response:
                self.responseArea.setText("Test successful!\n\nAPI Response:\n" + str(response))
            else:
                self.responseArea.setText("Test failed: Empty response from API")
            
            self.responseArea.setCaretPosition(0)
            
        except Exception as e:
            error_msg = "Error during test: " + str(e)
            self.responseArea.setText(error_msg)
            JOptionPane.showMessageDialog(
                self,
                error_msg,
                "Error",
                JOptionPane.ERROR_MESSAGE
            )

class HTTPDisplayPanel(BasePanel, IMessageEditorController):
    def __init__(self):
        BasePanel.__init__(self, "HTTP Request/Response")
        self.setLayout(BorderLayout())
        
        # Initialiser les composants à None
        self.requestViewer = None
        self.responseViewer = None
        self.current_request = None
        self.current_response = None
        self.extender = None
        self._callbacks = None
        self._helpers = None
        self._httpService = None  # Renommé avec underscore
        
        # Créer un panneau divisé verticalement pour la requête et la réponse
        self.splitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self.splitPane.setResizeWeight(0.5)  # Répartition 50/50
        
        self.add(self.splitPane, BorderLayout.CENTER)

    def initializeComponents(self):
        """Initialise les composants Burp si ce n'est pas déjà fait"""
        if not self._callbacks:
            return
        
        if not self.requestViewer:
            # Créer un MessageEditor avec tous les onglets (Pretty, Raw, Hex)
            controller = MessageEditorController(self)
            self.requestViewer = self._callbacks.createMessageEditor(controller, False)
            self.responseViewer = self._callbacks.createMessageEditor(controller, False)
            
            self.splitPane.setTopComponent(self.requestViewer.getComponent())
            self.splitPane.setBottomComponent(self.responseViewer.getComponent())

    def updateContent(self, request, response):
        """Met à jour le contenu des viewers"""
        if not self._callbacks:
            return
        
        # Initialiser les composants si nécessaire
        self.initializeComponents()
        
        # Mettre à jour le contenu
        if isinstance(request, str):
            request = request.encode('utf-8')
        if isinstance(response, str):
            response = response.encode('utf-8')
        
        self.current_request = request
        self.current_response = response
        
        if self.requestViewer:
            self.requestViewer.setMessage(request, True)
        if self.responseViewer:
            self.responseViewer.setMessage(response, False)

    # Méthodes pour les boutons d'action
    def reanalyze(self, event):
        """Relance l'analyse"""
        if hasattr(self, 'extender'):
            self.extender.panel.aiResponsePanel.reanalyzeCurrentTab()

    def cancelAnalysis(self, event):
        """Annule l'analyse en cours"""
        if hasattr(self, 'extender'):
            self.extender.panel.aiResponsePanel.cancelCurrentAnalysis()

    def copyToClipboard(self, event):
        """Copie le contenu dans le presse-papier"""
        if hasattr(self, 'extender'):
            self.extender.panel.aiResponsePanel.copyCurrentToClipboard()

    def clearResponse(self, event):
        """Efface la réponse actuelle"""
        if hasattr(self, 'extender'):
            self.extender.panel.aiResponsePanel.clearCurrentResponse()

    def closeTab(self, event):
        """Ferme l'onglet actuel"""
        if hasattr(self, 'extender'):
            self.extender.panel.aiResponsePanel.closeCurrentTab()

    # Méthodes requises par IMessageEditorController
    def getHttpService(self):
        return self._httpService

    def getMessage(self):
        return self.current_request

    def isMessageModified(self):
        return False

    def setHttpService(self, httpService):
        self._httpService = httpService

class MessageEditorController(IMessageEditorController):
    def __init__(self, panel):
        self.panel = panel
    def getHttpService(self):
        return None
    def getMessage(self):
        return self.panel.current_request
    def isMessageModified(self):
        return False
    def getSelectedData(self):
        return self.panel.requestViewer.getSelectedData() if self.panel.requestViewer else None

class StatusIndicator(JPanel):
    def __init__(self):
        JPanel.__init__(self)
        self.setPreferredSize(Dimension(10, 10))
        self.status = "idle"  # idle, thinking, error
    def paintComponent(self, g):
        g2 = g.create()
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING,
                            RenderingHints.VALUE_ANTIALIAS_ON)
        
        if self.status == "idle":
            color = Color(100, 100, 100)
        elif self.status == "thinking":
            color = ACCENT_COLOR
        else:
            color = Color(255, 80, 80)
        
        g2.setColor(color)
        g2.fillOval(0, 0, 10, 10)
        g2.dispose()

class BurpAIMainPanel(JPanel):
    def __init__(self, service):
        JPanel.__init__(self)
        self.service = service
        self.setLayout(BorderLayout(0, 0))
        
        # Définir les dimensions minimales et préférées
        self.setMinimumSize(Dimension(800, 600))
        self.setPreferredSize(Dimension(1200, 800))
        
        # Initialiser les panneaux
        self.configPanel = APIConfigPanel(self.service)
        self.systemPromptPanel = SystemPromptPanel()
        self.detailedPromptPanel = DetailedPromptPanel()
        self.aiResponsePanel = AIResponsePanel()
        self.chatPanel = ChatPanel(self.service)
        self.testPanel = TestPanel()
        self.httpDisplayPanel = HTTPDisplayPanel()
        self.templatesPanel = MCPTemplatesPanel()  # Nouveau panneau
        
        # Créer un panneau central qui contient les onglets principaux et l'affichage HTTP
        centerPanel = JPanel(BorderLayout())
        centerPanel.setBackground(BACKGROUND_COLOR)
        
        # Créer un panneau divisé horizontalement
        splitPane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        splitPane.setBackground(BACKGROUND_COLOR)
        splitPane.setDividerLocation(500)
        
        # Panneau de gauche (HTTP display)
        splitPane.setLeftComponent(self.httpDisplayPanel)
        
        # Panneau de droite (onglets)
        rightPanel = JPanel(BorderLayout())
        rightPanel.setBackground(BACKGROUND_COLOR)
        
        # Onglets principaux
        self.mainTabs = JTabbedPane()
        self.mainTabs.setFont(Font("Segoe UI", Font.PLAIN, 12))
        self.mainTabs.setBackground(BACKGROUND_COLOR)
        self.mainTabs.setForeground(TEXT_COLOR)
        
        # Créer le panneau de configuration
        configurationPanel = JPanel(BorderLayout())
        configurationPanel.setBackground(BACKGROUND_COLOR)
        
        # Sous-onglets de configuration
        configTabs = JTabbedPane()
        configTabs.setFont(Font("Segoe UI", Font.PLAIN, 12))
        configTabs.setBackground(BACKGROUND_COLOR)
        configTabs.setForeground(TEXT_COLOR)
        
        configTabs.addTab("API", self.configPanel)
        configTabs.addTab("System Prompt", self.systemPromptPanel)
        configTabs.addTab("Analysis", self.detailedPromptPanel)
        configTabs.addTab("Templates", self.templatesPanel)  # Nouvel onglet
        
        # Ajouter le gestionnaire de requêtes et le panneau de groupes
        if hasattr(self.service, 'request_manager'):
            self.groupPanel = RequestGroupPanel(self.service.request_manager)
            configTabs.addTab("Request Groups", self.groupPanel)
        
        configurationPanel.add(configTabs, BorderLayout.CENTER)
        
        # Ajouter les onglets principaux
        self.mainTabs.addTab("Results", self.aiResponsePanel)
        self.mainTabs.addTab("Configuration", configurationPanel)
        self.mainTabs.addTab("Test", self.testPanel)
        
        rightPanel.add(self.mainTabs, BorderLayout.CENTER)
        
        # Ajouter le panneau d'onglets au splitPane
        splitPane.setRightComponent(rightPanel)
        splitPane.setResizeWeight(0.4)
        
        centerPanel.add(splitPane, BorderLayout.CENTER)
        
        # Panneau de chat à droite
        self.rightPanel = JPanel(BorderLayout())
        self.rightPanel.setBackground(BACKGROUND_COLOR)
        self.rightPanel.setPreferredSize(Dimension(300, 0))
        self.rightPanel.add(self.chatPanel, BorderLayout.CENTER)
        
        # Ajouter des séparateurs verticaux
        rightSeparator = JSeparator(JSeparator.VERTICAL)
        rightSeparator.setForeground(BORDER_COLOR)
        
        # Créer un panneau pour le séparateur avec marge
        self.rightSepPanel = JPanel(BorderLayout())
        self.rightSepPanel.setBackground(BACKGROUND_COLOR)
        self.rightSepPanel.setBorder(EmptyBorder(0, 5, 0, 5))
        self.rightSepPanel.add(rightSeparator, BorderLayout.CENTER)
        
        # Layout final
        self.add(centerPanel, BorderLayout.CENTER)
        self.add(self.rightSepPanel, BorderLayout.EAST)
        self.add(self.rightPanel, BorderLayout.EAST)
        
        # Appliquer les styles globaux
        self.applyGlobalStyles(self)
        
        self.extender = None
        
        # Appliquer la configuration initiale de visibilité du chat
        self.applyVisibilityConfiguration()
    def applyGlobalStyles(self, component):
        """Applique les styles de manière récursive à tous les composants"""
        component.setBackground(BACKGROUND_COLOR)
        
        if isinstance(component, JTextArea) or isinstance(component, JTextField):
            component.setBackground(INPUT_BG)
            component.setForeground(TEXT_COLOR)
            component.setCaretColor(TEXT_COLOR)
            component.setFont(Font("Segoe UI", Font.PLAIN, 12))
            
            if isinstance(component, JScrollPane):
                component.getVerticalScrollBar().setUI(ModernScrollBarUI())
                component.getHorizontalScrollBar().setUI(ModernScrollBarUI())
                component.setBorder(BorderFactory.createLineBorder(BORDER_COLOR))
            
            if isinstance(component, JLabel):
                component.setForeground(TEXT_COLOR)
                component.setFont(Font("Segoe UI", Font.PLAIN, 12))
        
        # Appliquer récursivement aux sous-composants
        if hasattr(component, 'getComponents'):
            for child in component.getComponents():
                self.applyGlobalStyles(child)
    def tabChanged(self, event):
        def updateUI():
            source = event.getSource()
            selectedComponent = source.getSelectedComponent()
            if selectedComponent:
                selectedComponent.revalidate()
                selectedComponent.repaint()
                parent = selectedComponent.getParent()
                if parent:
                    parent.revalidate()
                    parent.repaint()
                invokeLater(updateUI)
    def applyVisibilityConfiguration(self):
        """Applique la configuration de visibilité du chat"""
        config = self.service.config_manager.load_config()
        show_chat = config.get("show_chat", True)
        
        # Mettre à jour la checkbox
        self.configPanel.show_chat_checkbox.setSelected(show_chat)
        
        # Mettre à jour la visibilité des composants
        self.rightSepPanel.setVisible(show_chat)
        self.rightPanel.setVisible(show_chat)
        
        # Forcer le rafraîchissement de l'interface
        self.revalidate()
        self.repaint()

class ErrorHandler:
    @staticmethod
    def showError(parent, error, title="Error"):
        if "timeout" in str(error).lower():
            message = "The request timed out. Please check your internet connection or try again."
        elif "api key" in str(error).lower():
            message = "Invalid API key. Please check your configuration."
        else:
            message = str(error)
        
        JOptionPane.showMessageDialog(
            parent,
            message,
            title,
            JOptionPane.ERROR_MESSAGE
        )

class RequestGroupPanel(BasePanel):
    def __init__(self, request_manager):
        BasePanel.__init__(self, "Request Groups")
        self.request_manager = request_manager
        
        # Panneau d'informations
        infoPanel = JPanel(BorderLayout(5, 5))
        infoPanel.setBackground(BACKGROUND_COLOR)
        infoLabel = JLabel("<html>Create groups of related requests for analysis.<br>Groups can help analyze workflows and find patterns.</html>")
        infoLabel.setForeground(TEXT_COLOR)
        infoPanel.add(infoLabel, BorderLayout.CENTER)
        
        # Liste des groupes avec description
        listPanel = JPanel(BorderLayout(5, 5))
        listPanel.setBackground(BACKGROUND_COLOR)
        
        self.groupList = JList()
        self.groupList.setBackground(INPUT_BG)
        self.groupList.setForeground(TEXT_COLOR)
        self.groupList.addListSelectionListener(self.onGroupSelected)
        
        # Panneau de détails du groupe
        self.detailsPanel = JPanel(BorderLayout(5, 5))
        self.detailsPanel.setBackground(BACKGROUND_COLOR)
        
        self.requestCountLabel = JLabel("Requests: 0")
        self.requestCountLabel.setForeground(TEXT_COLOR)
        
        self.notesArea = JTextArea()
        self.notesArea.setBackground(INPUT_BG)
        self.notesArea.setForeground(TEXT_COLOR)
        
        self.detailsPanel.add(self.requestCountLabel, BorderLayout.NORTH)
        self.detailsPanel.add(JScrollPane(self.notesArea), BorderLayout.CENTER)
        
        # Panneau d'actions
        actionPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        actionPanel.setBackground(BACKGROUND_COLOR)
        
        newGroupBtn = JButton("New Group")
        addToGroupBtn = JButton("Add Current")
        analyzeGroupBtn = JButton("Analyze Group")
        removeGroupBtn = JButton("Remove Group")
        
        for btn in [newGroupBtn, addToGroupBtn, analyzeGroupBtn, removeGroupBtn]:
            styleButton(btn, ACCENT_COLOR, TEXT_COLOR)
            actionPanel.add(btn)
        
        # Layout
        mainPanel = JPanel(BorderLayout(5, 5))
        mainPanel.setBackground(BACKGROUND_COLOR)
        
        mainPanel.add(infoPanel, BorderLayout.NORTH)
        
        splitPane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        splitPane.setLeftComponent(JScrollPane(self.groupList))
        splitPane.setRightComponent(self.detailsPanel)
        splitPane.setResizeWeight(0.3)
        
        mainPanel.add(splitPane, BorderLayout.CENTER)
        mainPanel.add(actionPanel, BorderLayout.SOUTH)
        
        self.add(mainPanel, BorderLayout.CENTER)
        
        # Gestionnaires d'événements
        newGroupBtn.addActionListener(self.createNewGroup)
        addToGroupBtn.addActionListener(self.addCurrentToGroup)
        analyzeGroupBtn.addActionListener(self.analyzeGroup)
        removeGroupBtn.addActionListener(self.removeGroup)
        
        # Initialiser la liste
        self.updateGroupList()
    def onGroupSelected(self, event):
        if not event.getValueIsAdjusting():
            selected = self.groupList.getSelectedValue()
            if selected and selected in self.request_manager.groups:
                group = self.request_manager.groups[selected]
                self.requestCountLabel.setText("Requests: {}".format(len(group.requests)))
                self.notesArea.setText(group.notes)
            else:
                self.requestCountLabel.setText("Requests: 0")
                self.notesArea.setText("")
    def removeGroup(self, event):
        selected = self.groupList.getSelectedValue()
        if selected:
            if JOptionPane.showConfirmDialog(
                self,
                "Remove group '{}'?".format(selected),
                "Confirm Removal",
                JOptionPane.YES_NO_OPTION
            ) == JOptionPane.YES_OPTION:
                del self.request_manager.groups[selected]
                self.updateGroupList()
    def createNewGroup(self, event):
        name = JOptionPane.showInputDialog(self, "Enter group name:")
        if name:
            self.request_manager.create_group(name)
            self.updateGroupList()
    def addCurrentToGroup(self, event):
        if not self.checkExtender():
            return
        
        selected = self.groupList.getSelectedValue()
        if not selected:
            JOptionPane.showMessageDialog(
                self,
                "Please select a group first",
                "Warning",
                JOptionPane.WARNING_MESSAGE
            )
            return
        
        current_request = self.extender.panel.httpDisplayPanel.current_request
        current_response = self.extender.panel.httpDisplayPanel.current_response
        
        if not current_request or not current_response:
            JOptionPane.showMessageDialog(
                self,
                "No request/response loaded. Use 'Set as Context' first.",
                "Warning",
                JOptionPane.WARNING_MESSAGE
            )
            return
        
        try:
            # Les données sont déjà encodées correctement dans HTTPDisplayPanel
            self.request_manager.add_to_group(
                selected,
                current_request,
                current_response
            )
            self.updateGroupList()
            JOptionPane.showMessageDialog(
                self,
                "Request added to group '{}'".format(selected),
                "Success",
                JOptionPane.INFORMATION_MESSAGE
            )
        except Exception as e:
            JOptionPane.showMessageDialog(
                self,
                "Error adding to group: " + str(e),
                "Error",
                JOptionPane.ERROR_MESSAGE
            )
    def analyzeGroup(self, event):
        selected = self.groupList.getSelectedValue()
        if not selected or not self.extender:
            return
        
        group = self.request_manager.groups[selected]
        prompt = """Analyze this group of related HTTP interactions.Focus on:1. Common patterns2. Security implications3. Potential vulnerabilities4. Workflow analysis{}""".format(group.get_context())
        
        # Créer une nouvelle analyse dans le panneau de réponse
        response_area = self.extender.panel.aiResponsePanel.addNewAnalysis("Group: " + selected)
        response_area.setText("Analyzing group...")
        self.extender.panel.mainTabs.setSelectedComponent(self.extender.panel.aiResponsePanel)
        
        try:
            response = self.extender.sendToAI(prompt, debug=True)
            response_area.setText(response)
        except Exception as e:
            response_area.setText("Error: {}".format(str(e)))
    def updateGroupList(self):
        """Met à jour la liste des groupes affichée"""
        groups = list(self.request_manager.groups.keys())
        self.groupList.setListData(groups)

class AnalysisTab(BasePanel):
    def __init__(self, request, response, analysis_result, tab_name):
        BasePanel.__init__(self)
        self.setLayout(BorderLayout(5, 5))
        
        # Créer un split pane vertical
        splitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        
        # Panneau supérieur pour la requête/réponse
        httpPanel = JPanel(BorderLayout(5, 5))
        httpPanel.setBackground(BACKGROUND_COLOR)
        
        # Zone de requête
        requestPanel = JPanel(BorderLayout(5, 5))
        requestPanel.setBackground(BACKGROUND_COLOR)
        requestPanel.setBorder(create_titled_border("Request"))
        
        self.requestArea, requestScroll = self.createScrollableTextArea(editable=False)
        self.requestArea.setText(request)
        requestPanel.add(requestScroll, BorderLayout.CENTER)
        
        # Zone de réponse
        responsePanel = JPanel(BorderLayout(5, 5))
        responsePanel.setBackground(BACKGROUND_COLOR)
        responsePanel.setBorder(create_titled_border("Response"))
        
        self.responseArea, responseScroll = self.createScrollableTextArea(editable=False)
        self.responseArea.setText(response)
        responsePanel.add(responseScroll, BorderLayout.CENTER)
        
        # Split pane horizontal pour requête/réponse
        httpSplitPane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        httpSplitPane.setLeftComponent(requestPanel)
        httpSplitPane.setRightComponent(responsePanel)
        httpSplitPane.setResizeWeight(0.5)
        
        httpPanel.add(httpSplitPane, BorderLayout.CENTER)
        
        # Panneau inférieur pour l'analyse
        analysisPanel = JPanel(BorderLayout(5, 5))
        analysisPanel.setBackground(BACKGROUND_COLOR)
        analysisPanel.setBorder(create_titled_border("AI Analysis"))
        
        self.analysisArea, analysisScroll = self.createScrollableTextArea(editable=False)
        self.analysisArea.setText(analysis_result)
        analysisPanel.add(analysisScroll, BorderLayout.CENTER)
        
        # Configurer le split pane principal
        splitPane.setTopComponent(httpPanel)
        splitPane.setBottomComponent(analysisPanel)
        splitPane.setResizeWeight(0.5)
        
        self.add(splitPane, BorderLayout.CENTER)

class ConfigPanel(JPanel):
    def __init__(self):
        # ... code existant ...
        
        # Ajouter les listeners pour sauvegarder en temps réel
        self.systemPromptArea.getDocument().addDocumentListener(ConfigChangeListener(self))
        self.detailedPromptArea.getDocument().addDocumentListener(ConfigChangeListener(self))
    def saveConfig(self):
        config = {
            "api_url": self.getApiUrl(),
            "api_key": self.getApiKey(),
            "model": self.getModel(),
            "system_prompt": self.systemPromptArea.getText(),
            "detailed_prompt": self.detailedPromptArea.getText(),
            "timeout": self.getTimeout()
        }
        
        config_path = os.path.join(os.path.dirname(self._callbacks.getExtensionFilename()), "local_config.json")
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=4)
    def setApiUrl(self, url):
        self.api_url_field.setText(url)
    def setApiKey(self, key):
        self.api_key_field.setText(key)
    def setModel(self, model):
        self.model_field.setText(model)

class ConfigChangeListener(DocumentListener):
    def __init__(self, config_panel):
        self.config_panel = config_panel
    def changedUpdate(self, e):
        self.config_panel.saveConfig()
    def removeUpdate(self, e):
        self.config_panel.saveConfig()
    def insertUpdate(self, e):
        self.config_panel.saveConfig()

class MCPTemplatesPanel(BasePanel):
    def __init__(self):
        BasePanel.__init__(self, "Analysis Templates")
        self.setLayout(BorderLayout(5, 5))
        
        # Charger les templates
        self.templates = self.load_templates()
        
        # Liste des templates disponibles
        self.templateList = JList(sorted(self.templates.keys()))
        self.templateList.setBackground(INPUT_BG)
        self.templateList.setForeground(TEXT_COLOR)
        self.templateList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        
        # Zone de description du template
        self.descriptionArea = JTextArea()
        self.descriptionArea.setEditable(False)
        self.descriptionArea.setLineWrap(True)
        self.descriptionArea.setWrapStyleWord(True)
        self.descriptionArea.setBackground(INPUT_BG)
        self.descriptionArea.setForeground(TEXT_COLOR)
        
        # Panneau de boutons
        buttonPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        buttonPanel.setBackground(BACKGROUND_COLOR)
        
        applyButton = JButton("Apply Template")
        styleButton(applyButton, ACCENT_COLOR, TEXT_COLOR)
        applyButton.addActionListener(self.applyTemplate)
        
        buttonPanel.add(applyButton)
        
        # Layout
        splitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        splitPane.setTopComponent(JScrollPane(self.templateList))
        splitPane.setBottomComponent(JScrollPane(self.descriptionArea))
        splitPane.setResizeWeight(0.3)
        
        self.add(splitPane, BorderLayout.CENTER)
        self.add(buttonPanel, BorderLayout.SOUTH)
        
        # Ajouter le listener pour la sélection
        self.templateList.addListSelectionListener(self.templateSelected)
    def load_templates(self):
        """Charge tous les templates depuis le dossier templates"""
        templates = {}
        
        # Charger les templates intégrés (fallback)
        templates.update(self.get_builtin_templates())
        
        # Charger les templates personnalisés
        if os.path.exists(TEMPLATES_DIR):
            for filename in os.listdir(TEMPLATES_DIR):
                if filename.endswith('.json'):
                    try:
                        with open(os.path.join(TEMPLATES_DIR, filename), 'r') as f:
                            template = json.load(f)
                            if self.validate_template(template):
                                templates[template['name']] = template
                    except Exception as e:
                        if hasattr(self, 'extender'):
                            self.extender._callbacks.printError(
                                "Error loading template {}: {}".format(filename, str(e))
                            )
        
        return templates

    def validate_template(self, template):
        """Vérifie qu'un template a tous les champs requis"""
        required_fields = ['name', 'description', 'prompt_format']
        return all(field in template for field in required_fields)

    def get_builtin_templates(self):
        """Templates par défaut intégrés"""
        return {
            "Vulnerability Assessment": {
                "name": "Vulnerability Assessment",
                "description": "Detailed vulnerability analysis...",
                "prompt_format": "..."
            }
            # ... autres templates par défaut ...
        }
    def templateSelected(self, event):
        if not event.getValueIsAdjusting():
            selected = self.templateList.getSelectedValue()
            if selected in self.templates:
                self.descriptionArea.setText(self.templates[selected]["description"])
    def applyTemplate(self, event):
        if not self.checkExtender():
            return
        
        selected = self.templateList.getSelectedValue()
        if not selected or selected not in self.templates:
            return
        
        template = self.templates[selected]
        
        # Create response area
        response_area = self.extender.panel.aiResponsePanel.addNewAnalysis(
            "Template: " + selected
        )
        response_area.setText("Analysis in progress...")

        try:
            # Get current request/response
            http_panel = self.extender.panel.httpDisplayPanel
            if not http_panel.current_request or not http_panel.current_response:
                response_area.setText("Error: No request/response loaded")
                return

            # Build prompt
            request_str = self.extender._helpers.bytesToString(http_panel.current_request)
            response_str = self.extender._helpers.bytesToString(http_panel.current_response)
            
            prompt = "Template Analysis: {}\n\n".format(selected)
            if "prompt_format" in template:
                prompt += template["prompt_format"] + "\n\n"
            else:
                prompt += "Description:\n{}\n\n".format(template["description"])
            
            prompt += "Request:\n{}\n\nResponse:\n{}".format(request_str, response_str)
            
            # Create and execute worker
            worker = AnalysisWorker(self.extender, prompt, response_area, None)
            worker.execute()
            
        except Exception as e:
            error_msg = "Error applying template: {}".format(str(e))
            self.extender._callbacks.printError(error_msg)
            response_area.setText(error_msg)

class AnalysisWorker(SwingWorker):
    def __init__(self, extender, prompt, response_area, menu_factory=None):
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
            # Reset the analyzing flag if menu_factory exists
            if self.menu_factory:
                self.menu_factory.is_analyzing = False 