# -*- coding: utf-8 -*-

import os
import json
from datetime import datetime
import urllib2
import io  # Ajouter l'import de io
from config import DEFAULT_API_URL, DEFAULT_API_KEY, DEFAULT_MODEL, DEFAULT_TIMEOUT, DEFAULT_SYSTEM_PROMPT, DEFAULT_DETAILED_PROMPT

# Constants
CONFIG_FILENAME = "local_config.json"
CACHE_FILENAME = "wish_granter_cache.json"
HISTORY_FILENAME = "wish_granter_history.json"

class WishGranterService:
    def __init__(self):
        self.config_manager = None
        self.cache_manager = None
        self.request_manager = None
        self.history_manager = None
        self.callbacks = None
        self.debug_mode = False

    def _normalize_string(self, text, source_desc="text"):
        """Normalize text to UTF-8 string format"""
        try:
            if self.debug_mode:
                self.callbacks.printOutput("[Wish Granter] Normalizing {}".format(source_desc))
            
            # Direct conversion to string if needed
            if not isinstance(text, (str, unicode)):
                text = str(text)
            
            # Convert to UTF-8 bytes and then to Burp string format
            return self.helpers.bytesToString(text.encode('utf-8', 'replace'))
            
        except Exception as e:
            self.callbacks.printError("[Wish Granter] Error normalizing {}: {}".format(source_desc, str(e)))
            return str(text)

    def initialize(self, callbacks):
        self.callbacks = callbacks
        self.config_manager = ConfigManager(callbacks)
        self.cache_manager = CacheManager(
            os.path.join(os.path.dirname(callbacks.getExtensionFilename()), 
                        CACHE_FILENAME)
        )
        self.request_manager = RequestManager(callbacks)
        self.history_manager = HistoryManager(callbacks)
        
        # Initialize Burp helpers
        self.helpers = callbacks.getHelpers()
        
        # Load configuration and set debug mode
        config = self.config_manager.load_config()
        self.debug_mode = config.get('debug_mode', False)
        
        # Log debug mode state on startup
        callbacks.printOutput("[Wish Granter Service] Debug mode state: {}".format(self.debug_mode))
        
        if self.debug_mode:
            callbacks.printOutput("[Wish Granter Service] Debug mode is ENABLED")
            callbacks.printOutput("[Wish Granter Service] Configuration loaded: {}".format(config))
        
        # Log initialization status
        callbacks.printOutput("[Wish Granter Service] Initialized successfully")

    def analyze(self, prompt, callback=None):
        try:
            self.callbacks.printOutput("=== DEBUG START ===")
            self.callbacks.printOutput("Starting analysis...")
            
            # Prepare API request
            config = self.config_manager.load_config()
            api_url = str(config.get('api_url', '')).strip()
            api_key = str(config.get('api_key', '')).strip()
            model = str(config.get('model', '')).strip()
            
            self.callbacks.printOutput("API URL: " + api_url)
            self.callbacks.printOutput("Model: " + model)
            
            if not api_url or not api_key:
                raise Exception("API URL or key not configured")

            try:
                # Convert to basic ASCII
                if isinstance(prompt, unicode):
                    prompt = prompt.encode('ascii', 'replace')
                else:
                    prompt = str(prompt).encode('ascii', 'replace')

                system_prompt = str(config.get('system_prompt', '')).encode('ascii', 'replace')
                
                # Build minimal JSON payload with streaming enabled
                payload = {
                    "model": model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": prompt}
                    ],
                    "stream": True
                }
                
                # Convert to ASCII JSON
                json_data = json.dumps(payload, ensure_ascii=True)
                self.callbacks.printOutput("Payload prepared with streaming enabled")
                
            except Exception as e:
                self.callbacks.printError("Error preparing payload: " + str(e))
                raise Exception("Failed to prepare payload: " + str(e))

            # Send HTTP request
            try:
                self.callbacks.printOutput("Sending streaming request...")
                requestObj = urllib2.Request(
                    api_url,
                    json_data,
                    {'Content-Type': 'application/json'}
                )
                requestObj.add_header("Authorization", "Bearer " + api_key)
                
                response = urllib2.urlopen(requestObj)
                self.callbacks.printOutput("Connection established, starting to read response...")
                
                # Initialize buffer for complete response
                full_response = []
                
                # Read streaming response
                while True:
                    chunk = response.readline()
                    if not chunk:
                        self.callbacks.printOutput("End of stream reached")
                        break
                        
                    # Log raw chunk for debug
                    self.callbacks.printOutput("Raw chunk received: " + chunk.strip())
                        
                    # Ignore empty lines
                    if not chunk.strip():
                        continue
                        
                    # Remove prefix "data: " if present
                    if chunk.startswith('data: '):
                        chunk = chunk[6:]
                    
                    try:
                        # Parse chunk JSON
                        chunk_data = json.loads(chunk)
                        self.callbacks.printOutput("Parsed chunk data: " + str(chunk_data))
                        
                        # Extract text according to response format
                        text = None
                        
                        # Format 1: response.content[].text
                        if 'response' in chunk_data:
                            response_obj = chunk_data['response']
                            if 'content' in response_obj and isinstance(response_obj['content'], list):
                                for content_item in response_obj['content']:
                                    if isinstance(content_item, dict) and 'text' in content_item:
                                        text = content_item['text']
                        
                        # Format 2: choices[].delta.content (OpenAI style)
                        elif 'choices' in chunk_data and len(chunk_data['choices']) > 0:
                            delta = chunk_data['choices'][0].get('delta', {})
                            if 'content' in delta:
                                text = delta['content']
                        
                        # Format 3: content direct
                        elif 'content' in chunk_data:
                            text = chunk_data['content']
                        
                        if text:
                            self.callbacks.printOutput("Extracted text: " + text)
                            full_response.append(text)
                            if callback:
                                callback(text)
                        
                    except Exception as e:
                        self.callbacks.printError("Error processing chunk: " + str(e))
                        continue
                
                # Join all response pieces
                final_content = ''.join(full_response)
                
                # Convert to ASCII if necessary
                if isinstance(final_content, unicode):
                    final_content = final_content.encode('ascii', 'replace')
                else:
                    final_content = str(final_content).encode('ascii', 'replace')
                
                self.callbacks.printOutput("=== DEBUG END ===")
                return final_content
                
            except Exception as e:
                self.callbacks.printError("Error during streaming request: " + str(e))
                raise Exception("Streaming request failed: " + str(e))
            
        except Exception as e:
            error_msg = str(e)
            self.callbacks.printError("Analysis failed: " + error_msg)
            self.callbacks.printOutput("=== DEBUG END ===")
            return "Error: " + error_msg

class ConfigManager:
    def __init__(self, callbacks):
        self.callbacks = callbacks
        self.config_path = os.path.join(
            os.path.dirname(callbacks.getExtensionFilename()),
            CONFIG_FILENAME
        )
        self.callbacks.printOutput("Config path: " + self.config_path)
        self.config = self.load_config()
    
    def load_config(self):
        try:
            if os.path.exists(self.config_path):
                with io.open(self.config_path, 'r', encoding='utf-8') as f:
                    return json.loads(f.read())
            return {
                'api_url': DEFAULT_API_URL,
                'api_key': DEFAULT_API_KEY,
                'model': DEFAULT_MODEL,
                'timeout': DEFAULT_TIMEOUT,
                'system_prompt': DEFAULT_SYSTEM_PROMPT,
                'detailed_prompt': DEFAULT_DETAILED_PROMPT
            }
        except Exception as e:
            self.callbacks.printError("Error loading config: " + str(e))
            return {}
    
    def save_config(self, config):
        try:
            # Create parent directory if necessary
            config_dir = os.path.dirname(self.config_path)
            if not os.path.exists(config_dir):
                os.makedirs(config_dir)
            
            with io.open(self.config_path, 'w', encoding='utf-8') as f:
                json_str = json.dumps(config, indent=4, ensure_ascii=False)
                f.write(unicode(json_str))
            
            self.config = config
            return True
        except Exception as e:
            self.callbacks.printError("Error saving config: " + str(e))
            return False

class CacheManager:
    def __init__(self, cache_path):
        self.cache_path = cache_path
        self.cache = self.load_cache()
    
    def load_cache(self):
        if os.path.exists(self.cache_path):
            try:
                with open(self.cache_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except:
                pass
        return {}
    
    def save_cache(self):
        try:
            with open(self.cache_path, 'w', encoding='utf-8') as f:
                json.dump(self.cache, f, indent=4, ensure_ascii=False)
        except:
            pass
    
    def get(self, key):
        return self.cache.get(key)
    
    def set(self, key, value):
        # Ensure value is in Unicode before caching
        if isinstance(value, bytes):
            value = value.decode('utf-8', errors='replace')
        elif not isinstance(value, str):
            value = str(value)
        
        self.cache[key] = value
        self.save_cache()

class RequestManager:
    def __init__(self, callbacks):
        self.callbacks = callbacks
        self._http_listener = None
        self.groups = {}  # Dictionary to store groups
    
    def create_group(self, name):
        """Create a new group of requests"""
        if name not in self.groups:
            self.groups[name] = RequestGroup(name)
    
    def add_to_group(self, group_name, request, response):
        """Add a request/response to a group"""
        if group_name not in self.groups:
            self.create_group(group_name)
        self.groups[group_name].add_request(request, response)
    
    def process_request(self, message_info):
        request = message_info.getRequest()
        response = message_info.getResponse()
        
        if not request or not response:
            return None
            
        return {
            'request': self._process_http_message(request),
            'response': self._process_http_message(response),
            'url': message_info.getUrl().toString(),
            'timestamp': datetime.now().isoformat()
        }
    
    def _process_http_message(self, message):
        helpers = self.callbacks.getHelpers()
        info = helpers.analyzeRequest(message)
        
        headers = [helpers.bytesToString(header) for header in info.getHeaders()]
        body = helpers.bytesToString(message[info.getBodyOffset():])
        
        return {
            'headers': headers,
            'body': body
        }

class RequestGroup:
    def __init__(self, name):
        self.name = name
        self.requests = []
        self.notes = ""
    
    def add_request(self, request, response):
        """Add a request/response pair to the group"""
        self.requests.append({
            'request': request,
            'response': response,
            'timestamp': datetime.now().isoformat()
        })
    
    def get_context(self):
        """Return a textual representation of the group for analysis"""
        context = "Group: {0}\n\n".format(self.name)
        for idx, req in enumerate(self.requests, 1):
            context += "Request #{0}:\n".format(idx)
            context += "Timestamp: {0}\n".format(req['timestamp'])
            context += "Request:\n{0}\n".format(req['request'])
            context += "Response:\n{0}\n\n".format(req['response'])
        return context

class HistoryManager:
    def __init__(self, callbacks):
        self._callbacks = callbacks
        self.history_file = os.path.join(
            os.path.dirname(callbacks.getExtensionFilename()),
            HISTORY_FILENAME
        )
    
    def load_history(self):
        try:
            if os.path.exists(self.history_file):
                with open(self.history_file, 'rb') as f:
                    return json.loads(f.read().decode('utf-8'))
            return []
        except Exception as e:
            self._callbacks.printOutput("Error loading history: " + str(e))
            return []
    
    def save_history(self, history):
        try:
            with open(self.history_file, 'wb') as f:
                f.write(json.dumps(history, indent=2).encode('utf-8'))
            return True
        except Exception as e:
            self._callbacks.printOutput("Error saving history: " + str(e))
            return False 

    def analyze_request(self, message_info):
        request_data = self.request_manager.process_request(message_info)
        if not request_data:
            return None
            
        cache_key = "{url}_{timestamp}".format(
            url=request_data['url'],
            timestamp=request_data['timestamp']
        )
        cached_result = self.cache_manager.get(cache_key)
        
        if cached_result:
            return cached_result
            
        # TODO: Implement AI analysis here
        analysis_result = self._perform_ai_analysis(request_data)
        self.cache_manager.set(cache_key, analysis_result)
        
        return analysis_result
    
    def _perform_ai_analysis(self, request_data):
        # TODO: Implement actual AI analysis
        return {
            'vulnerabilities': [],
            'recommendations': [],
            'timestamp': datetime.now().isoformat()
        } 