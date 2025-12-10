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
        return forms
