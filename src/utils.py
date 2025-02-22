# -*- coding: utf-8 -*-

"""Utility functions and classes for the WishGranter extension"""

from javax.swing.plaf.basic import BasicScrollBarUI
from java.awt import Color, Font, Toolkit
from javax.swing import JMenuItem, JPopupMenu, JScrollPane, JTextField
from java.awt.datatransfer import StringSelection, DataFlavor
from javax.swing.border import TitledBorder
from java.awt.event import MouseAdapter, FocusAdapter, FocusEvent

from constants import (
    BACKGROUND_COLOR, TEXT_COLOR, ACCENT_COLOR, INPUT_BG, BORDER_COLOR,
    CONFIG_FILENAME, CACHE_FILENAME, HISTORY_FILENAME
)

class ModernScrollBarUI(BasicScrollBarUI):
    """Modern UI for scroll bars"""
    def configureScrollBarColors(self):
        self.thumbColor = ACCENT_COLOR
        self.trackColor = BACKGROUND_COLOR
    
    def paintThumb(self, g, c, thumbBounds):
        g.setColor(self.thumbColor)
        g.fillRoundRect(
            thumbBounds.x, thumbBounds.y,
            thumbBounds.width, thumbBounds.height,
            5, 5
        )
    
    def paintTrack(self, g, c, trackBounds):
        g.setColor(self.trackColor)
        g.fillRect(
            trackBounds.x, trackBounds.y,
            trackBounds.width, trackBounds.height
        )

def styleButton(button, bgColor=ACCENT_COLOR, fgColor=TEXT_COLOR):
    """Apply modern styling to buttons"""
    button.setBackground(bgColor)
    button.setForeground(fgColor)
    button.setBorderPainted(False)
    button.setFocusPainted(False)
    button.setOpaque(True)
    
    class ButtonHoverListener(MouseAdapter):
        def mouseEntered(self, e):
            button.setBackground(Color(
                min(bgColor.getRed() + 20, 255),
                min(bgColor.getGreen() + 20, 255),
                min(bgColor.getBlue() + 20, 255)
            ))
        
        def mouseExited(self, e):
            button.setBackground(bgColor)
        
        def mousePressed(self, e):
            button.setBackground(Color(
                max(bgColor.getRed() - 20, 0),
                max(bgColor.getGreen() - 20, 0),
                max(bgColor.getBlue() - 20, 0)
            ))
        
        def mouseReleased(self, e):
            button.setBackground(bgColor)
    
    button.addMouseListener(ButtonHoverListener())

def add_copy_paste_menu(text_component):
    """Add copy/paste context menu to a text component"""
    popup = JPopupMenu()
    
    copy_item = JMenuItem("Copy")
    copy_item.addActionListener(lambda e: _copy_text(text_component))
    
    paste_item = JMenuItem("Paste")
    paste_item.addActionListener(lambda e: _paste_text(text_component))
    
    popup.add(copy_item)
    popup.add(paste_item)
    
    text_component.setComponentPopupMenu(popup)

def _copy_text(component):
    """Copy text from a component to clipboard"""
    selected_text = component.getSelectedText()
    if selected_text:
        selection = StringSelection(selected_text)
        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        clipboard.setContents(selection, None)

def _paste_text(component):
    """Paste text from clipboard to component"""
    clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
    if clipboard.isDataFlavorAvailable(DataFlavor.stringFlavor):
        try:
            text = clipboard.getData(DataFlavor.stringFlavor)
            component.replaceSelection(text)
        except Exception as e:
            print("Error pasting text: {}".format(e))

def create_titled_border(title, color=TEXT_COLOR):
    """Create a titled border with consistent styling"""
    border = TitledBorder(title)
    border.setTitleColor(color)
    return border

def createStyledComponent(component, background=BACKGROUND_COLOR, foreground=TEXT_COLOR):
    """Apply base styles to a component"""
    component.setBackground(background)
    component.setForeground(foreground)
    if hasattr(component, 'setCaretColor'):
        component.setCaretColor(foreground)
    if hasattr(component, 'setFont'):
        component.setFont(Font("Segoe UI", Font.PLAIN, 12))
    return component

class ErrorHandler:
    """Centralized error handling"""
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

def ensure_unicode(text):
    if isinstance(text, bytes):
        return text.decode('utf-8')
    return str(text)

def handle_errors(func):
    """Décorateur pour gérer les erreurs de manière uniforme"""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            if hasattr(args[0], '_callbacks'):
                args[0]._callbacks.printError("Error in {}: {}".format(
                    func.__name__, str(e)
                ))
            return "Error: {}".format(str(e))
    return wrapper

def createScrollPane(component):
    """Helper function to create a styled scroll pane"""
    scrollPane = JScrollPane(component)
    scrollPane.getVerticalScrollBar().setUI(ModernScrollBarUI())
    scrollPane.getHorizontalScrollBar().setUI(ModernScrollBarUI())
    return scrollPane

class JTextFieldWithPlaceholder(JTextField):
    """A JTextField with placeholder text that disappears when focused"""
    def __init__(self, placeholder):
        JTextField.__init__(self)
        self.placeholder = placeholder
        self.showingPlaceholder = True
        self.setText(placeholder)
        self.setForeground(Color(150, 150, 150))  # Gris clair pour le placeholder
        
        class PlaceholderFocusListener(FocusAdapter):
            def focusGained(self, e):
                if JTextFieldWithPlaceholder.this.showingPlaceholder:
                    JTextFieldWithPlaceholder.this.setText("")
                    JTextFieldWithPlaceholder.this.setForeground(TEXT_COLOR)
                    JTextFieldWithPlaceholder.this.showingPlaceholder = False
            
            def focusLost(self, e):
                if JTextFieldWithPlaceholder.this.getText().strip() == "":
                    JTextFieldWithPlaceholder.this.setText(JTextFieldWithPlaceholder.this.placeholder)
                    JTextFieldWithPlaceholder.this.setForeground(Color(150, 150, 150))
                    JTextFieldWithPlaceholder.this.showingPlaceholder = True
        
        self.addFocusListener(PlaceholderFocusListener())
    
    def getText(self):
        """Override getText to return empty string when showing placeholder"""
        if self.showingPlaceholder:
            return ""
        return JTextField.getText(self)

__all__ = [
    'BACKGROUND_COLOR',
    'TEXT_COLOR',
    'ACCENT_COLOR',
    'INPUT_BG',
    'BORDER_COLOR',
    'ModernScrollBarUI',
    'styleButton',
    'add_copy_paste_menu',
    'create_titled_border',
    'createStyledComponent',
    'ensure_unicode',
    'ErrorHandler',
    'createScrollPane',
    'JTextFieldWithPlaceholder'
] 