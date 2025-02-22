# -*- coding: utf-8 -*-

"""Constants for the Wish Granter extension"""

from java.awt import Color

# File names
CONFIG_FILENAME = "local_config.json"
CACHE_FILENAME = "wish_granter_cache.json"
HISTORY_FILENAME = "wish_granter_history.json"

# UI Colors
BACKGROUND_COLOR = Color(30, 31, 34)
TEXT_COLOR = Color(197, 200, 198)
ACCENT_COLOR = Color(104, 151, 187)
INPUT_BG = Color(43, 43, 43)
BORDER_COLOR = Color(86, 86, 86)

# API Defaults
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