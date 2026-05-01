import os
from typing import Any, Dict, List, Optional

try:
    import requests
except Exception:  # pragma: no cover - optional dependency for ollama direct calls
    requests = None
from openai import OpenAI

try:
    from google import genai  # type: ignore
except Exception:  # pragma: no cover - optional provider dependency
    genai = None

try:
    from anthropic import Anthropic  # type: ignore
except Exception:  # pragma: no cover - optional provider dependency
    Anthropic = None

class Client:
    def __init__(self):
        self.provider = os.getenv("LLM_PROVIDER", "openai").lower()
        self.model = os.getenv("LLM_MODEL", "local-model")
        
        # OpenAI / LM Studio / Local / Groq
        self.openai_client = OpenAI(
            base_url=os.getenv("OPENAI_BASE_URL", "http://127.0.0.1:1234/v1"),
            api_key=os.getenv("OPENAI_API_KEY", "lm-studio"),
        )
        
        # Anthropic
        self.anthropic_client = None
        if Anthropic is not None:
            self.anthropic_client = Anthropic(
                api_key=os.getenv("ANTHROPIC_API_KEY", "")
            )
        
        # Gemini
        gemini_key = os.getenv("GEMINI_API_KEY", "")
        self.gemini_client = genai.Client(api_key=gemini_key) if genai is not None and gemini_key else None

        # Ollama (Direct API)
        self.ollama_base_url = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")

    def generate_text(self, prompt: str, max_tokens: int = 1000) -> str:
        system_prompt = (
            "You are a penetration testing orchestrator. "
            "You MUST return a single JSON object matching the provided schema. "
            "Do not include explanations, markdown, or extra text."
        )
        
        if self.provider == "anthropic":
            return self._generate_anthropic(system_prompt, prompt, max_tokens)
        elif self.provider == "gemini":
            return self._generate_gemini(system_prompt, prompt, max_tokens)
        elif self.provider == "ollama":
            return self._generate_ollama(system_prompt, prompt, max_tokens)
        else:
            return self._generate_openai(system_prompt, prompt, max_tokens)

    def _generate_ollama(self, system: str, prompt: str, max_tokens: int) -> str:
        if requests is None:
            return '{"error": "requests package not configured"}'
        url = f"{self.ollama_base_url}/api/generate"
        payload = {
            "model": self.model if self.model != "local-model" else "llama3.1",
            "prompt": f"{system}\n\n{prompt}",
            "stream": False,
            "format": "json"
        }
        try:
            resp = requests.post(url, json=payload, timeout=120)
            return resp.json().get("response", "")
        except Exception as e:
            return f'{{"error": "{str(e)}"}}'

    def _generate_openai(self, system: str, prompt: str, max_tokens: int) -> str:
        response = self.openai_client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            temperature=0,
            max_tokens=max_tokens,
            response_format={"type": "json_object"} if "local" not in self.model else None
        )
        return response.choices[0].message.content

    def _generate_anthropic(self, system: str, prompt: str, max_tokens: int) -> str:
        if self.anthropic_client is None:
            return '{"error": "Anthropic package or API key not configured"}'
        # Note: Anthropic uses top-level system parameter
        message = self.anthropic_client.messages.create(
            model=self.model if self.model != "local-model" else "claude-3-5-sonnet-20241022",
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": prompt}],
            temperature=0
        )
        return message.content[0].text

    def _generate_gemini(self, system: str, prompt: str, max_tokens: int) -> str:
        if not self.gemini_client:
            return '{"error": "Gemini API key not configured"}'
        
        model_name = self.model if self.model != "local-model" else "gemini-2.0-flash-exp"
        response = self.gemini_client.models.generate_content(
            model=model_name,
            contents=prompt,
            config={
                "system_instruction": system,
                "temperature": 0,
                "max_output_tokens": max_tokens,
                "response_mime_type": "application/json"
            }
        )
        return response.text
