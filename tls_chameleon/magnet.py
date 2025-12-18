import re
import json
from typing import List, Dict, Any, Optional

class Magnet:
    def __init__(self, content: str):
        self.content = content

    def emails(self) -> List[str]:
        """Extracts all email addresses from the content."""
        # Basic email regex
        return list(set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', self.content)))

    def links(self) -> List[str]:
        """Extracts all href links."""
        return list(set(re.findall(r'href=["\'](.*?)["\']', self.content)))

    def json_ld(self) -> List[Dict[str, Any]]:
        """Extracts JSON-LD scripts."""
        results = []
        matches = re.findall(r'<script type="application/ld\+json">(.*?)</script>', self.content, re.DOTALL)
        for m in matches:
            try:
                results.append(json.loads(m))
            except json.JSONDecodeError:
                pass
        return results

    def deep_extract(self) -> Dict[str, List[str]]:
        """
        Deeply extracts potentially hidden data:
        - JWT Tokens
        - API Keys (patterns)
        - Hidden Input Fields
        - Config objects in Scripts
        """
        data = {
            "jwts": [],
            "api_keys": [],
            "hidden_inputs": [],
            "found_js_configs": []
        }
        
        # 1. JWT Tokens (Simple heuristic)
        # Search everywhere, including inside strings in scripts
        data["jwts"] = list(set(re.findall(r'ey[a-zA-Z0-9_-]{10,}\.ey[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}', self.content)))
        
        # 2. API Keys (Common formats)
        patterns = [
            r'(?:key|api|token|secret|auth|cid|sid)["\']?\s*[:=]\s*["\']([a-zA-Z0-9\-_]{20,})["\']', # Generic in JSON/Key-Value
            r'AIza[0-9A-Za-z\\-_]{35}', # Google API Key
            r'(?:["\'])(AIza[0-9A-Za-z\\-_]{35})(?:["\'])', # Google Key in quotes
        ]
        for p in patterns:
            matches = re.findall(p, self.content)
            for m in matches:
                # findall with groups returns the group, without groups returns the match
                data["api_keys"].append(m if isinstance(m, str) else m[0])
        data["api_keys"] = list(set(data["api_keys"]))
        
        # 3. Hidden Inputs
        # <input type="hidden" name="..." value="...">
        hidden_matches = re.finditer(r'<input[^>]*type=["\']hidden["\'][^>]*>', self.content, re.IGNORECASE)
        for hm in hidden_matches:
            tag = hm.group(0)
            name_m = re.search(r'name=["\'](.*?)["\']', tag, re.IGNORECASE)
            val_m = re.search(r'value=["\'](.*?)["\']', tag, re.IGNORECASE)
            if name_m:
                 data["hidden_inputs"].append({name_m.group(1): val_m.group(1) if val_m else ""})
                 
        # 4. Config objects in scripts (var config = { ... })
        configs = re.findall(r'(?:var|const|let)\s+(?:\w+Config|config|appData|initialState)\s*=\s*({.*?});', self.content, re.DOTALL)
        for c in configs:
            # Try to sanitize and parse
            try:
                # This is risky and might fail if not pure JSON, but worth a shot for deep extraction
                cleaned = re.sub(r'//.*?\n', '', c) # simple comment strip
                # In real world we might use a JS parser, here we just keep the string if parse fails
                data["found_js_configs"].append(cleaned.strip())
            except:
                pass
                
        return data

    def tables(self) -> List[List[List[str]]]:
        """
        Extracts HTML tables as nested lists.
        Very basic regex/logic, non-robust compared to creating a DOM tree.
        """
        # Note: Parsing tables with regex is famously bad. 
        # But per user request "not use any other lib", we do our best simple extraction.
        tables = []
        table_matches = re.findall(r'<table.*?>(.*?)</table>', self.content, re.DOTALL)
        for t_html in table_matches:
            rows = []
            tr_matches = re.findall(r'<tr.*?>(.*?)</tr>', t_html, re.DOTALL)
            for tr in tr_matches:
                cols = []
                # grab td or th
                td_matches = re.findall(r'<(?:td|th).*?>(.*?)</(?:td|th)>', tr, re.DOTALL)
                for td in td_matches:
                    # Clean tags inside
                    text = re.sub(r'<.*?>', '', td).strip()
                    cols.append(text)
                if cols:
                    rows.append(cols)
            if rows:
                tables.append(rows)
        return tables

    def get_forms(self) -> List[Dict[str, Any]]:
        """
        Extracts forms and their inputs.
        Returns list of dicts: {'action': '...', 'method': '...', 'inputs': {'name': 'value', ...}}
        """
        forms = []
        # Find forms
        form_matches = re.finditer(r'<form(.*?)>(.*?)</form>', self.content, re.DOTALL | re.IGNORECASE)
        for fm in form_matches:
            attrs_str = fm.group(1)
            inner_html = fm.group(2)
            
            # Extract action and method
            action_m = re.search(r'action=["\'](.*?)["\']', attrs_str, re.IGNORECASE)
            method_m = re.search(r'method=["\'](.*?)["\']', attrs_str, re.IGNORECASE)
            
            form_data = {
                "action": action_m.group(1) if action_m else None,
                "method": method_m.group(1) if method_m else "GET",
                "inputs": {}
            }
            
            # Extract inputs
            # <input name="foo" value="bar">
            input_matches = re.finditer(r'<input(.*?)>', inner_html, re.IGNORECASE)
            for im in input_matches:
                i_attrs = im.group(1)
                name_m = re.search(r'name=["\'](.*?)["\']', i_attrs, re.IGNORECASE)
                val_m = re.search(r'value=["\'](.*?)["\']', i_attrs, re.IGNORECASE)
                
                if name_m:
                    name = name_m.group(1)
                    val = val_m.group(1) if val_m else ""
                    form_data["inputs"][name] = val
                    
            forms.append(form_data)
    def ask(self, prompt: str, provider: str = "gemini", api_key: Optional[str] = None, model: Optional[str] = None) -> str:
        """
        Uses an AI provider to extract data or answer a question about the page content.
        
        Args:
            prompt: The question or extraction instruction.
            provider: "gemini", "anthropic", or "openai" (default: "gemini").
            api_key: API Key for the specific provider. If None, checks env vars.
            model: Model name. Defaults depend on provider:
                   - gemini: "gemini-flash-latest"
                   - anthropic: "claude-3-opus-20240229"
                   - openai: "gpt-4-turbo"
            
        Returns:
            The text response from the model.
        """
        import os
        
        # Max chars context safety (approx 25k tokens)
        max_chars = 100000 
        clean_content = self.content[:max_chars]
        full_prompt = f"Context:\n{clean_content}\n\nTask: {prompt}"

        if provider == "gemini":
            try:
                import google.generativeai as genai
            except ImportError:
                raise ImportError("Run `pip install tls-chameleon[ai]` to use Gemini.")
            
            key = api_key or os.environ.get("GEMINI_API_KEY")
            if not key:
                raise ValueError("Missing Gemini API Key (pass arg or set GEMINI_API_KEY).")
                
            model = model or "gemini-flash-latest"
            genai.configure(api_key=key)
            m = genai.GenerativeModel(model)
            try:
                return m.generate_content(full_prompt).text
            except Exception as e:
                return f"Gemini Error: {e}"

        elif provider == "anthropic":
            try:
                import anthropic
            except ImportError:
                raise ImportError("Run `pip install tls-chameleon[ai]` (ensure anthropic is installed).")
                
            key = api_key or os.environ.get("ANTHROPIC_API_KEY")
            if not key:
                raise ValueError("Missing Anthropic API Key (pass arg or set ANTHROPIC_API_KEY).")
                
            model = model or "claude-3-haiku-20240307"
            client = anthropic.Anthropic(api_key=key)
            try:
                msg = client.messages.create(
                    model=model,
                    max_tokens=4096,
                    messages=[{"role": "user", "content": full_prompt}]
                )
                return msg.content[0].text
            except Exception as e:
                return f"Anthropic Error: {e}"

        elif provider == "openai":
            try:
                import openai
            except ImportError:
                raise ImportError("Run `pip install tls-chameleon[ai]` (ensure openai is installed).")
            
            key = api_key or os.environ.get("OPENAI_API_KEY")
            if not key:
                raise ValueError("Missing OpenAI API Key (pass arg or set OPENAI_API_KEY).")
            
            # Supports Grok (via XAI base_url) or DeepSeek if user configures client differently,
            # but for now standard OpenAI structure.
            model = model or "gpt-4-turbo-preview"
            client = openai.OpenAI(api_key=key)
            try:
                chat_completion = client.chat.completions.create(
                    messages=[{"role": "user", "content": full_prompt}],
                    model=model,
                )
                return chat_completion.choices[0].message.content
            except Exception as e:
                return f"OpenAI Error: {e}"
        
        else:
            raise ValueError(f"Unknown provider '{provider}'. Supported: gemini, anthropic, openai.")
