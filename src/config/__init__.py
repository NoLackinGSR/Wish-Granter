# -*- coding: utf-8 -*-

import json
import os

# Default configuration values
DEFAULT_API_URL = "https://api.openrouter.ai/api/v1/chat/completions"
DEFAULT_API_KEY = "your-api-key-here"
DEFAULT_MODEL = "google/gemini-pro"
DEFAULT_TIMEOUT = 30

# Default prompts
DEFAULT_SYSTEM_PROMPT = """You are a senior penetration tester assistant. Focus on identifying genuine security vulnerabilities. Provide clear, actionable insights and avoid false positives. When analyzing HTTP interactions, consider:
1. Authentication/Authorization issues
2. Injection vulnerabilities
3. Information disclosure
4. Business logic flaws
5. Security misconfigurations
Prioritize findings by severity and provide remediation guidance."""

DEFAULT_DETAILED_PROMPT = """Analyze the following HTTP interaction for security vulnerabilities. Consider:
1. Request method and parameters
2. Headers and cookies
3. Response status and content
4. Data validation and encoding
5. Security controls
Report only confirmed vulnerabilities with clear evidence."""

def load_config(config_path):
    """Charge la configuration depuis un fichier JSON"""
    try:
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                return json.load(f)
    except Exception as e:
        print("Error loading config: {}".format(str(e)))
    
    return {
        'api_url': DEFAULT_API_URL,
        'api_key': DEFAULT_API_KEY,
        'model': DEFAULT_MODEL,
        'timeout': DEFAULT_TIMEOUT,
        'system_prompt': DEFAULT_SYSTEM_PROMPT,
        'detailed_prompt': DEFAULT_DETAILED_PROMPT,
        'allow_insecure': False
    }

def save_config(config_path, config):
    """Sauvegarde la configuration dans un fichier JSON"""
    try:
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=4)
        return True
    except Exception as e:
        print("Error saving config: {}".format(str(e)))
        return False

__all__ = [
    'DEFAULT_API_URL',
    'DEFAULT_API_KEY',
    'DEFAULT_MODEL',
    'DEFAULT_TIMEOUT',
    'DEFAULT_SYSTEM_PROMPT',
    'DEFAULT_DETAILED_PROMPT',
    'load_config',
    'save_config'
] 