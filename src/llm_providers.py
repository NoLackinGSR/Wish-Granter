# -*- coding: utf-8 -*-

class LLMProvider:
    def prepare_payload(self, prompt, system_prompt, model, stream=False):
        """Méthode à implémenter par chaque provider"""
        raise NotImplementedError
    
    def prepare_headers(self, api_key):
        """Méthode à implémenter par chaque provider"""
        raise NotImplementedError
    
    def extract_response(self, response_json):
        """Méthode à implémenter par chaque provider"""
        if not isinstance(response_json, dict):
            return None
            
        # Format OpenAI standard
        if 'choices' in response_json and len(response_json['choices']) > 0:
            choice = response_json['choices'][0]
            if isinstance(choice, dict):
                # Format message.content
                if 'message' in choice and isinstance(choice['message'], dict):
                    return choice['message'].get('content')
                # Format text direct
                if 'text' in choice:
                    return choice['text']
                    
        # Format simple
        if 'response' in response_json:
            return response_json['response']
            
        # Format contenu direct
        if 'content' in response_json:
            return response_json['content']
            
        return None
    
    def extract_stream_response(self, chunk):
        """Extrait le texte d'un chunk de streaming"""
        raise NotImplementedError

class OpenRouterProvider(LLMProvider):
    def prepare_payload(self, prompt, system_prompt, model, stream=False):
        return {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            "stream": stream
        }
    
    def prepare_headers(self, api_key):
        return {
            'Content-Type': 'application/json',
            'HTTP-Referer': 'https://burp.local',
            'Authorization': 'Bearer {}'.format(api_key)
        }
    
    def extract_stream_response(self, chunk):
        try:
            if 'choices' in chunk:
                delta = chunk['choices'][0].get('delta', {})
                return delta.get('content', '')
        except Exception:
            return None

class OpenAIProvider(LLMProvider):
    def prepare_payload(self, prompt, system_prompt, model):
        return {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ]
        }
    
    def prepare_headers(self, api_key):
        return {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer {}'.format(api_key)
        }
    
    def extract_stream_response(self, chunk):
        try:
            if 'choices' in chunk:
                delta = chunk['choices'][0].get('delta', {})
                return delta.get('content', '')
        except Exception:
            return None

class OllamaProvider(LLMProvider):
    def prepare_payload(self, prompt, system_prompt, model):
        return {
            "model": model,
            "prompt": prompt,
            "system": system_prompt
        }
    
    def prepare_headers(self, api_key):
        return {'Content-Type': 'application/json'}
    
    def extract_stream_response(self, chunk):
        try:
            if 'choices' in chunk:
                delta = chunk['choices'][0].get('delta', {})
                return delta.get('content', '')
        except Exception:
            return None

# Mapping des providers
PROVIDERS = {
    'openrouter.ai': OpenRouterProvider(),  # URL correcte selon la doc
    'api.openai.com': OpenAIProvider(),
    'localhost:11434': OllamaProvider(),  # Pour Ollama
    # Ajouter d'autres providers ici
}

def get_provider(api_url):
    """Retourne le provider approprié basé sur l'URL de l'API"""
    for url_part, provider in PROVIDERS.items():
        if url_part in api_url:
            return provider
    return OpenAIProvider()  # Provider par défaut 