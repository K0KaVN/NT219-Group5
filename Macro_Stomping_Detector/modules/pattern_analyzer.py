"""
Pattern Analyzer Module
Extracts and compares patterns between P-code and VBA source code
"""
import re
from typing import Dict, Set, List

class PatternAnalyzer:
    """Analyzes and compares patterns between P-code and VBA source"""
    def __init__(self):
        # Regex patterns for extraction
        self.identifier_pattern = re.compile(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b')
        self.string_pattern = re.compile(r'"([^"\\]*(\\.[^"\\]*)*)"')
        self.comment_pattern = re.compile(r"(?:'|Rem\s)(.+?)$", re.MULTILINE | re.IGNORECASE)
        # VBA keywords to exclude from identifier analysis
        self.vba_keywords = {
            'sub', 'function', 'end', 'dim', 'as', 'integer', 'string', 'long',
            'boolean', 'double', 'variant', 'object', 'if', 'then', 'else',
            'elseif', 'select', 'case', 'for', 'to', 'next', 'while', 'wend',
            'do', 'loop', 'until', 'exit', 'return', 'call', 'set', 'let',
            'const', 'public', 'private', 'static', 'byval', 'byref', 'optional',
            'paramarray', 'withevents', 'new', 'nothing', 'true', 'false',
            'and', 'or', 'not', 'xor', 'mod', 'is', 'like', 'msgbox', 'inputbox',
            'attribute', 'option', 'explicit', 'base', 'compare', 'text', 'binary'
        }
        # P-code instruction keywords to exclude
        self.pcode_keywords = {
            'ld', 'st', 'litstr', 'concat', 'argscall', 'argsld', 'argsmemld',
            'argsmemcall', 'funcdefn', 'endsub', 'endifblock', 'endif', 'vardefn',
            'paramomitted', 'line', 'processing', 'file', 'module', 'streams',
            'bytes', 'type', 'length', 'offset', 'name', 'version', 'data',
            'argsldfld', 'argsldv', 'memargscall', 'impargscall', 'impargsmemcall',
            'redim', 'redimpreserve', 'erase', 'sharp', 'midstmtvar', 'lbound',
            'ubound', 'vbmethod', 'parambyref', 'raiseevent', 'onerror', 'resume',
            'bos', 'bosstmt', 'bol', 'endproc', 'dimarray', 'argsldvar', 'literal'
        }
        # pcodedmp metadata patterns to filter out
        self.pcode_metadata_patterns = [
            r'^Processing file:.*$',
            r'^=+$',
            r'^Module streams:.*$',
            r'^VBA/\w+ - \d+ bytes$',
            r'^\d+ bytes$',
            r'^-+$'
        ]
        # High-risk API calls and keywords (MITRE ATT&CK T1059, T1106)
        self.high_risk_indicators = {
            'createobject', 'wscript.shell', 'shell', 'exec', 'run',
            'powershell', 'cmd.exe', 'cmd', 'vbscript', 'jscript',
            'activexobject', 'shellexecute', 'winexec', 'createprocess'
        }
        # Medium-risk API calls (File/Registry operations)
        self.medium_risk_indicators = {
            'filesystemobject', 'opentextfile', 'writefile', 'copyfile',
            'deletefile', 'movefile', 'createfolder', 'regwrite', 'regread',
            'environ', 'tempfile', 'scripting.filesystemobject'
        }
        # Network/Download indicators
        self.network_indicators = {
            'xmlhttp', 'winhttp', 'urldownloadtofile', 'internetopen',
            'http', 'https', 'ftp', 'download'
        }
    def clean_pcode_metadata(self, pcode: str) -> str:
        """Remove pcodedmp metadata/header lines from P-code output"""
        lines = pcode.split('\n')
        cleaned_lines = []
        for line in lines:
            # Skip empty lines
            if not line.strip():
                continue
            # Check if line matches any metadata pattern
            is_metadata = False
            for pattern in self.pcode_metadata_patterns:
                if re.match(pattern, line.strip()):
                    is_metadata = True
                    break
            # Keep only actual P-code lines
            if not is_metadata:
                cleaned_lines.append(line)
        return '\n'.join(cleaned_lines)
    def clean_vba_attributes(self, vba_source: str) -> str:
        """Remove VBA Attribute lines (Office metadata) from VBA source"""
        lines = vba_source.split('\n')
        cleaned_lines = []
        for line in lines:
            stripped = line.strip()
            if stripped.startswith('Attribute '):
                continue
            if not stripped:
                continue
            cleaned_lines.append(line)
        return '\n'.join(cleaned_lines)
    def extract_identifiers(self, code: str, is_pcode: bool = False) -> Set[str]:
        """Extract variable and function identifiers"""
        identifiers = set()
        for match in self.identifier_pattern.finditer(code):
            identifier = match.group(0).lower()
            if identifier in self.vba_keywords:
                continue
            if is_pcode and identifier in self.pcode_keywords:
                continue
            if len(identifier) > 1 and not identifier.startswith('0x'):
                identifiers.add(identifier)
        return identifiers
    def extract_strings(self, code: str) -> Set[str]:
        """Extract string literals"""
        strings = set()
        for match in self.string_pattern.finditer(code):
            string_value = match.group(1)
            if string_value and len(string_value) > 2:
                strings.add(string_value.lower())
        return strings
    def extract_comments(self, code: str) -> Set[str]:
        """Extract comments"""
        comments = set()
        for match in self.comment_pattern.finditer(code):
            comment = match.group(1).strip()
            if comment and len(comment) > 3:
                comments.add(comment.lower())
        return comments
    def calculate_mismatch_rate(self, pcode_set: Set[str], vba_set: Set[str]) -> float:
        """Calculate mismatch rate between two sets"""
        if not pcode_set and not vba_set:
            return 0.0
        if not vba_set:
            return 100.0 if pcode_set else 0.0
        if not pcode_set:
            return 50.0
        intersection = len(pcode_set & vba_set)
        union = len(pcode_set | vba_set)
        if union == 0:
            return 0.0
        similarity = (intersection / union) * 100
        mismatch = 100 - similarity
        return round(mismatch, 2)
    def analyze_behavioral_indicators(self, pcode_ids: Set[str], pcode_strs: Set[str],
                                       vba_ids: Set[str], vba_strs: Set[str]) -> Dict:
        """Analyze behavioral indicators based on MITRE ATT&CK and YARA rules"""
        all_pcode = pcode_ids | {s.lower() for s in pcode_strs}
        all_vba = vba_ids | {s.lower() for s in vba_strs}
        hidden_high_risk = set()
        for indicator in self.high_risk_indicators:
            if any(indicator in item for item in all_pcode) and \
               not any(indicator in item for item in all_vba):
                hidden_high_risk.add(indicator)
        hidden_medium_risk = set()
        for indicator in self.medium_risk_indicators:
            if any(indicator in item for item in all_pcode) and \
               not any(indicator in item for item in all_vba):
                hidden_medium_risk.add(indicator)
        hidden_network = set()
        for indicator in self.network_indicators:
            if any(indicator in item for item in all_pcode) and \
               not any(indicator in item for item in all_vba):
                hidden_network.add(indicator)
        return {
            'high_risk': list(hidden_high_risk),
            'medium_risk': list(hidden_medium_risk),
            'network': list(hidden_network),
            'risk_score': len(hidden_high_risk) * 30 + len(hidden_medium_risk) * 15 + len(hidden_network) * 20
        }
    def calculate_confidence(self, identifier_mismatch: float, 
                           string_mismatch: float, 
                           comment_mismatch: float,
                           behavioral_score: int = 0) -> int:
        """
        Calculate overall confidence score based on:
        - Pattern mismatch (60%): Identifiers 30%, Strings 25%, Comments 5%
        - Behavioral indicators (40%): Risk score from API calls and suspicious patterns
        """
        # Pattern-based score (max 60)
        pattern_score = (
            identifier_mismatch * 0.30 +
            string_mismatch * 0.25 +
            comment_mismatch * 0.05
        )
        
        # Behavioral score (max 40) - normalized to 0-40 range
        behavioral_normalized = min(behavioral_score, 100) * 0.40
        
        confidence = pattern_score + behavioral_normalized
        
        return round(min(confidence, 100))  # Cap at 100
    def get_threat_level(self, confidence: int, has_high_risk: bool = False) -> str:
        """
        Determine threat level based on confidence and behavioral indicators
        Thresholds based on malware analysis industry standards:
        - HIGH: >= 60% or presence of hidden high-risk APIs
        - MEDIUM: 30-59%
        - LOW: < 30%
        """
        if confidence >= 60 or has_high_risk:
            return "HIGH"
        elif confidence >= 30:
            return "MEDIUM"
        else:
            return "LOW"
    def compare_patterns(self, pcode: str, vba_source: str) -> Dict:
        """
        Compare patterns between P-code and VBA source
        Returns detailed analysis results
        """
        pcode_cleaned = self.clean_pcode_metadata(pcode)
        vba_cleaned = self.clean_vba_attributes(vba_source)
        pcode_identifiers = self.extract_identifiers(pcode_cleaned, is_pcode=True)
        pcode_strings = self.extract_strings(pcode_cleaned)
        pcode_comments = self.extract_comments(pcode_cleaned)
        vba_identifiers = self.extract_identifiers(vba_cleaned, is_pcode=False)
        vba_strings = self.extract_strings(vba_cleaned)
        vba_comments = self.extract_comments(vba_cleaned)
        identifier_mismatch = self.calculate_mismatch_rate(pcode_identifiers, vba_identifiers)
        string_mismatch = self.calculate_mismatch_rate(pcode_strings, vba_strings)
        comment_mismatch = self.calculate_mismatch_rate(pcode_comments, vba_comments)
        behavioral_analysis = self.analyze_behavioral_indicators(
            pcode_identifiers, pcode_strings,
            vba_identifiers, vba_strings
        )
        confidence = self.calculate_confidence(
            identifier_mismatch,
            string_mismatch,
            comment_mismatch,
            behavioral_analysis['risk_score']
        )
        unique_identifiers = pcode_identifiers - vba_identifiers
        unique_strings = pcode_strings - vba_strings
        missing_identifiers = vba_identifiers - pcode_identifiers
        analysis = {
            'confidence': confidence,
            'threat_level': self.get_threat_level(confidence, len(behavioral_analysis['high_risk']) > 0),
            'behavioral_analysis': behavioral_analysis,
            'pcode_patterns': {
                'identifiers': sorted(list(pcode_identifiers)),
                'identifier_count': len(pcode_identifiers),
                'strings': sorted(list(pcode_strings)),
                'string_count': len(pcode_strings),
                'comments': sorted(list(pcode_comments)),
                'comment_count': len(pcode_comments)
            },
            'vba_patterns': {
                'identifiers': sorted(list(vba_identifiers)),
                'identifier_count': len(vba_identifiers),
                'strings': sorted(list(vba_strings)),
                'string_count': len(vba_strings),
                'comments': sorted(list(vba_comments)),
                'comment_count': len(vba_comments)
            },
            'mismatch_rates': {
                'identifiers': identifier_mismatch,
                'strings': string_mismatch,
                'comments': comment_mismatch
            },
            'unique_to_pcode': {
                'identifiers': sorted(list(unique_identifiers))[:20],  # Limit output
                'strings': sorted(list(unique_strings))[:20]
            },
            'missing_from_pcode': {
                'identifiers': sorted(list(missing_identifiers))[:20]
            },
            'indicators': self._generate_indicators(
                identifier_mismatch,
                string_mismatch,
                comment_mismatch,
                unique_identifiers,
                unique_strings,
                behavioral_analysis
            )
        }
        return analysis
    def _generate_indicators(self, id_mismatch: float, str_mismatch: float,
                           com_mismatch: float, unique_ids: Set[str],
                           unique_strs: Set[str], behavioral: Dict) -> List[str]:
        """Generate list of detection indicators based on MITRE ATT&CK and YARA patterns"""
        indicators = []
        if behavioral['high_risk']:
            indicators.append(f"CRITICAL: Hidden high-risk APIs detected - {', '.join(behavioral['high_risk'])}")
        if behavioral['network']:
            indicators.append(f"Network/Download capabilities hidden in P-code - {', '.join(behavioral['network'])}")
        if behavioral['medium_risk']:
            indicators.append(f"File/Registry operations hidden in P-code - {', '.join(behavioral['medium_risk'])}")
        if id_mismatch > 50:
            indicators.append(f"Significant identifier mismatch ({id_mismatch:.1f}%)")
        if str_mismatch > 50:
            indicators.append(f"Significant string literal mismatch ({str_mismatch:.1f}%)")
        if com_mismatch > 70:
            indicators.append(f"Comment discrepancy detected ({com_mismatch:.1f}%)")
        if len(unique_ids) > 20:
            indicators.append(f"{len(unique_ids)} unique identifiers only in P-code")
        if len(unique_strs) > 8:
            indicators.append(f"{len(unique_strs)} unique strings only in P-code")
        # Check for URL/IP patterns in unique strings
        url_pattern = re.compile(r'https?://|ftp://|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        for s in unique_strs:
            if url_pattern.search(s):
                indicators.append("Network indicators found in P-code")
                break
        if not indicators:
            indicators.append("No significant anomalies detected - File appears clean")
        return indicators
