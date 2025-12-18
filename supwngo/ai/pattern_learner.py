"""
CVE Pattern Learning and Matching.

Learns vulnerability patterns from CVE databases and matches them
against analyzed binaries to predict potential vulnerabilities.
"""

import json
import os
import pickle
import re
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union
import hashlib

from supwngo.core.binary import Binary
from supwngo.utils.logging import get_logger

logger = get_logger(__name__)

# Try to import ML libraries
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


class VulnPattern(Enum):
    """Categories of vulnerability patterns."""
    STACK_BOF = "Stack Buffer Overflow"
    HEAP_BOF = "Heap Buffer Overflow"
    FORMAT_STRING = "Format String"
    USE_AFTER_FREE = "Use After Free"
    DOUBLE_FREE = "Double Free"
    INTEGER_OVERFLOW = "Integer Overflow"
    NULL_DEREF = "Null Pointer Dereference"
    RACE_CONDITION = "Race Condition"
    COMMAND_INJECTION = "Command Injection"
    TYPE_CONFUSION = "Type Confusion"
    UNINITIALIZED_MEMORY = "Uninitialized Memory Use"
    OUT_OF_BOUNDS_READ = "Out of Bounds Read"
    OUT_OF_BOUNDS_WRITE = "Out of Bounds Write"


@dataclass
class CVEEntry:
    """Represents a CVE entry with vulnerability details."""
    cve_id: str
    description: str
    vulnerability_type: VulnPattern
    affected_product: str = ""
    cvss_score: float = 0.0
    cwe_ids: List[str] = field(default_factory=list)

    # Code patterns associated with this CVE
    code_patterns: List[str] = field(default_factory=list)
    function_patterns: List[str] = field(default_factory=list)
    call_patterns: List[str] = field(default_factory=list)

    # Extracted features
    features: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "vulnerability_type": self.vulnerability_type.value,
            "affected_product": self.affected_product,
            "cvss_score": self.cvss_score,
            "cwe_ids": self.cwe_ids,
            "code_patterns": self.code_patterns,
            "function_patterns": self.function_patterns,
            "call_patterns": self.call_patterns,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CVEEntry":
        vuln_type = VulnPattern.STACK_BOF
        for vt in VulnPattern:
            if vt.value == data.get("vulnerability_type"):
                vuln_type = vt
                break

        return cls(
            cve_id=data.get("cve_id", ""),
            description=data.get("description", ""),
            vulnerability_type=vuln_type,
            affected_product=data.get("affected_product", ""),
            cvss_score=data.get("cvss_score", 0.0),
            cwe_ids=data.get("cwe_ids", []),
            code_patterns=data.get("code_patterns", []),
            function_patterns=data.get("function_patterns", []),
            call_patterns=data.get("call_patterns", []),
        )


@dataclass
class PatternMatch:
    """A match between binary code and a learned pattern."""
    cve_entry: CVEEntry
    confidence: float
    matched_location: str
    matched_patterns: List[str]
    explanation: str = ""

    def __str__(self) -> str:
        return f"[{self.confidence:.0%}] {self.cve_entry.cve_id} - {self.cve_entry.vulnerability_type.value}"


class PatternDatabase:
    """
    Database of CVE patterns for matching.

    Stores learned patterns from CVE analysis and provides
    efficient matching against new code.
    """

    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize pattern database.

        Args:
            db_path: Path to database file (pickle format)
        """
        self.db_path = db_path or str(Path.home() / ".supwngo" / "pattern_db.pkl")
        self.entries: Dict[str, CVEEntry] = {}
        self.pattern_index: Dict[str, Set[str]] = defaultdict(set)  # pattern -> CVE IDs

        # TF-IDF vectorizer for description matching
        self._vectorizer = None
        self._description_matrix = None

        # Load existing database
        self._load()

    def _load(self):
        """Load database from disk."""
        if os.path.exists(self.db_path):
            try:
                with open(self.db_path, 'rb') as f:
                    data = pickle.load(f)
                    self.entries = {k: CVEEntry.from_dict(v) if isinstance(v, dict) else v
                                   for k, v in data.get('entries', {}).items()}
                    self.pattern_index = data.get('pattern_index', defaultdict(set))
                logger.info(f"Loaded {len(self.entries)} CVE entries from database")
            except Exception as e:
                logger.warning(f"Failed to load pattern database: {e}")

    def save(self):
        """Save database to disk."""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

        data = {
            'entries': {k: v.to_dict() for k, v in self.entries.items()},
            'pattern_index': dict(self.pattern_index),
        }

        with open(self.db_path, 'wb') as f:
            pickle.dump(data, f)

        logger.info(f"Saved {len(self.entries)} CVE entries to database")

    def add_entry(self, entry: CVEEntry):
        """Add a CVE entry to the database."""
        self.entries[entry.cve_id] = entry

        # Index patterns for fast lookup
        for pattern in entry.code_patterns:
            self.pattern_index[pattern].add(entry.cve_id)
        for pattern in entry.function_patterns:
            self.pattern_index[f"func:{pattern}"].add(entry.cve_id)
        for pattern in entry.call_patterns:
            self.pattern_index[f"call:{pattern}"].add(entry.cve_id)

        # Invalidate vectorizer cache
        self._vectorizer = None
        self._description_matrix = None

    def get_entries_by_type(self, vuln_type: VulnPattern) -> List[CVEEntry]:
        """Get all entries of a specific vulnerability type."""
        return [e for e in self.entries.values() if e.vulnerability_type == vuln_type]

    def get_entries_by_cwe(self, cwe_id: str) -> List[CVEEntry]:
        """Get all entries with a specific CWE ID."""
        return [e for e in self.entries.values() if cwe_id in e.cwe_ids]

    def find_by_pattern(self, pattern: str) -> List[CVEEntry]:
        """Find entries matching a specific pattern."""
        cve_ids = self.pattern_index.get(pattern, set())
        return [self.entries[cve_id] for cve_id in cve_ids if cve_id in self.entries]

    def build_vectorizer(self):
        """Build TF-IDF vectorizer for description matching."""
        if not SKLEARN_AVAILABLE:
            logger.warning("sklearn not available for TF-IDF matching")
            return

        if not self.entries:
            return

        descriptions = [e.description for e in self.entries.values()]
        self._vectorizer = TfidfVectorizer(
            max_features=5000,
            stop_words='english',
            ngram_range=(1, 2)
        )
        self._description_matrix = self._vectorizer.fit_transform(descriptions)

    def find_similar_by_description(
        self,
        description: str,
        top_k: int = 5
    ) -> List[Tuple[CVEEntry, float]]:
        """
        Find CVE entries with similar descriptions.

        Args:
            description: Description to match against
            top_k: Number of results to return

        Returns:
            List of (CVEEntry, similarity_score) tuples
        """
        if not SKLEARN_AVAILABLE:
            return []

        if self._vectorizer is None:
            self.build_vectorizer()

        if self._vectorizer is None or self._description_matrix is None:
            return []

        query_vec = self._vectorizer.transform([description])
        similarities = cosine_similarity(query_vec, self._description_matrix)[0]

        # Get top matches
        top_indices = similarities.argsort()[-top_k:][::-1]

        results = []
        entries_list = list(self.entries.values())
        for idx in top_indices:
            if similarities[idx] > 0.1:  # Minimum threshold
                results.append((entries_list[idx], float(similarities[idx])))

        return results


class CVEPatternLearner:
    """
    Learns vulnerability patterns from CVE data.

    Analyzes CVE descriptions, patches, and vulnerable code to
    extract patterns that can identify similar vulnerabilities.

    Example:
        learner = CVEPatternLearner()

        # Learn from CVE data
        learner.learn_from_nvd(year=2023)

        # Match against binary
        matches = learner.match_binary(binary)
    """

    # CWE to vulnerability pattern mapping
    CWE_MAPPING = {
        "CWE-121": VulnPattern.STACK_BOF,
        "CWE-122": VulnPattern.HEAP_BOF,
        "CWE-124": VulnPattern.HEAP_BOF,
        "CWE-125": VulnPattern.OUT_OF_BOUNDS_READ,
        "CWE-126": VulnPattern.HEAP_BOF,
        "CWE-127": VulnPattern.HEAP_BOF,
        "CWE-134": VulnPattern.FORMAT_STRING,
        "CWE-190": VulnPattern.INTEGER_OVERFLOW,
        "CWE-191": VulnPattern.INTEGER_OVERFLOW,
        "CWE-362": VulnPattern.RACE_CONDITION,
        "CWE-364": VulnPattern.RACE_CONDITION,
        "CWE-415": VulnPattern.DOUBLE_FREE,
        "CWE-416": VulnPattern.USE_AFTER_FREE,
        "CWE-476": VulnPattern.NULL_DEREF,
        "CWE-77": VulnPattern.COMMAND_INJECTION,
        "CWE-78": VulnPattern.COMMAND_INJECTION,
        "CWE-787": VulnPattern.OUT_OF_BOUNDS_WRITE,
        "CWE-843": VulnPattern.TYPE_CONFUSION,
        "CWE-908": VulnPattern.UNINITIALIZED_MEMORY,
    }

    # Common vulnerable function patterns
    DANGEROUS_PATTERNS = {
        VulnPattern.STACK_BOF: [
            r"gets\s*\(",
            r"strcpy\s*\(",
            r"strcat\s*\(",
            r"sprintf\s*\(",
            r"vsprintf\s*\(",
            r"scanf\s*\([^,]*,\s*[^&]",  # scanf without &
            r"read\s*\([^,]*,\s*[^,]*,\s*\d+\s*\)",
        ],
        VulnPattern.HEAP_BOF: [
            r"malloc\s*\([^)]*\)\s*;\s*\n[^}]*strcpy",
            r"realloc\s*\(",
            r"memcpy\s*\([^,]*,\s*[^,]*,\s*[^)]*size",
        ],
        VulnPattern.FORMAT_STRING: [
            r"printf\s*\(\s*[a-zA-Z_]\w*\s*\)",  # printf(var)
            r"fprintf\s*\([^,]*,\s*[a-zA-Z_]\w*\s*\)",
            r"sprintf\s*\([^,]*,\s*[a-zA-Z_]\w*\s*\)",
            r"syslog\s*\([^,]*,\s*[a-zA-Z_]\w*\s*\)",
        ],
        VulnPattern.USE_AFTER_FREE: [
            r"free\s*\([^)]+\)\s*;[^}]*\1",  # free then use
            r"delete\s+\w+\s*;[^}]*\1->",
        ],
        VulnPattern.DOUBLE_FREE: [
            r"free\s*\([^)]+\)[^}]*free\s*\(\s*\1\s*\)",
        ],
        VulnPattern.INTEGER_OVERFLOW: [
            r"\w+\s*\+\s*\w+\s*<\s*\w+",  # a + b < a (overflow check)
            r"malloc\s*\(\s*\w+\s*\*\s*\w+\s*\)",  # malloc(a * b)
            r"size_t\s+\w+\s*=\s*\w+\s*\*",
        ],
        VulnPattern.COMMAND_INJECTION: [
            r"system\s*\(",
            r"popen\s*\(",
            r"execl\s*\(",
            r"execlp\s*\(",
            r"execve\s*\(",
        ],
    }

    def __init__(self, database: Optional[PatternDatabase] = None):
        """
        Initialize pattern learner.

        Args:
            database: Pattern database to use (creates new if None)
        """
        self.database = database or PatternDatabase()
        self._compiled_patterns: Dict[VulnPattern, List[re.Pattern]] = {}

        # Compile regex patterns
        self._compile_patterns()

    def _compile_patterns(self):
        """Compile regex patterns for efficient matching."""
        for vuln_type, patterns in self.DANGEROUS_PATTERNS.items():
            self._compiled_patterns[vuln_type] = [
                re.compile(p, re.IGNORECASE | re.MULTILINE)
                for p in patterns
            ]

    def learn_from_cve(
        self,
        cve_id: str,
        description: str,
        cwe_ids: List[str] = None,
        code_snippets: List[str] = None,
        cvss_score: float = 0.0
    ):
        """
        Learn patterns from a single CVE.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2021-44228")
            description: CVE description
            cwe_ids: Associated CWE identifiers
            code_snippets: Vulnerable code snippets (if available)
            cvss_score: CVSS score
        """
        cwe_ids = cwe_ids or []
        code_snippets = code_snippets or []

        # Determine vulnerability type from CWE
        vuln_type = VulnPattern.STACK_BOF  # Default
        for cwe in cwe_ids:
            if cwe in self.CWE_MAPPING:
                vuln_type = self.CWE_MAPPING[cwe]
                break

        # Extract patterns from description
        code_patterns = self._extract_code_patterns(description)
        function_patterns = self._extract_function_patterns(description)
        call_patterns = self._extract_call_patterns(description)

        # Extract patterns from code snippets
        for snippet in code_snippets:
            code_patterns.extend(self._extract_code_patterns(snippet))
            function_patterns.extend(self._extract_function_patterns(snippet))
            call_patterns.extend(self._extract_call_patterns(snippet))

        entry = CVEEntry(
            cve_id=cve_id,
            description=description,
            vulnerability_type=vuln_type,
            cvss_score=cvss_score,
            cwe_ids=cwe_ids,
            code_patterns=list(set(code_patterns)),
            function_patterns=list(set(function_patterns)),
            call_patterns=list(set(call_patterns)),
        )

        self.database.add_entry(entry)
        logger.debug(f"Learned patterns from {cve_id}: {len(code_patterns)} code, "
                    f"{len(function_patterns)} function, {len(call_patterns)} call patterns")

    def _extract_code_patterns(self, text: str) -> List[str]:
        """Extract code-level patterns from text."""
        patterns = []

        # Look for code in backticks or code blocks
        code_blocks = re.findall(r'`([^`]+)`', text)
        code_blocks.extend(re.findall(r'```[a-z]*\n(.*?)```', text, re.DOTALL))

        for block in code_blocks:
            # Normalize and add
            normalized = block.strip().lower()
            if len(normalized) > 5:  # Skip very short patterns
                patterns.append(normalized)

        return patterns

    def _extract_function_patterns(self, text: str) -> List[str]:
        """Extract function name patterns from text."""
        patterns = []

        # Match function-like patterns
        func_matches = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', text)

        # Filter known dangerous functions
        dangerous = {
            'gets', 'strcpy', 'strcat', 'sprintf', 'vsprintf', 'scanf',
            'fscanf', 'sscanf', 'printf', 'fprintf', 'read', 'recv',
            'recvfrom', 'memcpy', 'memmove', 'system', 'popen', 'exec',
            'malloc', 'free', 'realloc', 'calloc'
        }

        for func in func_matches:
            if func.lower() in dangerous:
                patterns.append(func.lower())

        return patterns

    def _extract_call_patterns(self, text: str) -> List[str]:
        """Extract call sequence patterns from text."""
        patterns = []

        # Look for patterns like "func1 ... func2" indicating call sequences
        sequences = re.findall(
            r'(\w+)\s*\([^)]*\)[^{;]*(\w+)\s*\(',
            text
        )

        for seq in sequences:
            pattern = f"{seq[0]}->{seq[1]}"
            patterns.append(pattern)

        return patterns

    def learn_from_nvd_json(self, nvd_json_path: str):
        """
        Learn from NVD JSON feed file.

        Args:
            nvd_json_path: Path to NVD JSON file
        """
        with open(nvd_json_path, 'r') as f:
            data = json.load(f)

        cve_items = data.get('CVE_Items', [])
        logger.info(f"Learning from {len(cve_items)} CVE entries")

        for item in cve_items:
            try:
                cve = item.get('cve', {})
                cve_id = cve.get('CVE_data_meta', {}).get('ID', '')

                # Get description
                desc_data = cve.get('description', {}).get('description_data', [])
                description = desc_data[0].get('value', '') if desc_data else ''

                # Get CWE IDs
                problem_data = cve.get('problemtype', {}).get('problemtype_data', [])
                cwe_ids = []
                for pd in problem_data:
                    for desc in pd.get('description', []):
                        if desc.get('value', '').startswith('CWE-'):
                            cwe_ids.append(desc['value'])

                # Get CVSS score
                impact = item.get('impact', {})
                cvss_v3 = impact.get('baseMetricV3', {}).get('cvssV3', {})
                cvss_score = cvss_v3.get('baseScore', 0.0)

                self.learn_from_cve(
                    cve_id=cve_id,
                    description=description,
                    cwe_ids=cwe_ids,
                    cvss_score=cvss_score
                )

            except Exception as e:
                logger.debug(f"Error processing CVE: {e}")
                continue

        # Save database
        self.database.save()

    def match_code(self, code: str) -> List[PatternMatch]:
        """
        Match code against learned patterns.

        Args:
            code: Source code or decompiled code

        Returns:
            List of pattern matches
        """
        matches = []

        # Check against compiled patterns
        for vuln_type, patterns in self._compiled_patterns.items():
            for pattern in patterns:
                match = pattern.search(code)
                if match:
                    # Find related CVE entries
                    related_entries = self.database.get_entries_by_type(vuln_type)

                    if related_entries:
                        best_entry = max(related_entries, key=lambda e: e.cvss_score)
                    else:
                        # Create synthetic entry
                        best_entry = CVEEntry(
                            cve_id="PATTERN-MATCH",
                            description=f"Code matches {vuln_type.value} pattern",
                            vulnerability_type=vuln_type,
                        )

                    matches.append(PatternMatch(
                        cve_entry=best_entry,
                        confidence=0.7,
                        matched_location=f"line ~{code[:match.start()].count(chr(10)) + 1}",
                        matched_patterns=[pattern.pattern],
                        explanation=f"Code matches pattern: {match.group()}"
                    ))

        # Check against learned patterns in database
        for pattern, cve_ids in self.database.pattern_index.items():
            if pattern.startswith("func:") or pattern.startswith("call:"):
                continue

            if pattern.lower() in code.lower():
                for cve_id in cve_ids:
                    entry = self.database.entries.get(cve_id)
                    if entry:
                        matches.append(PatternMatch(
                            cve_entry=entry,
                            confidence=0.5,
                            matched_location="unknown",
                            matched_patterns=[pattern],
                            explanation=f"Code contains pattern from {cve_id}"
                        ))

        # Deduplicate by CVE ID
        seen = set()
        unique_matches = []
        for match in matches:
            key = (match.cve_entry.cve_id, match.matched_location)
            if key not in seen:
                seen.add(key)
                unique_matches.append(match)

        return sorted(unique_matches, key=lambda m: m.confidence, reverse=True)

    def match_binary(self, binary: Binary) -> List[PatternMatch]:
        """
        Match binary against learned patterns.

        Args:
            binary: Binary to analyze

        Returns:
            List of pattern matches
        """
        matches = []

        # Check imported functions
        dangerous_imports = {
            'gets': VulnPattern.STACK_BOF,
            'strcpy': VulnPattern.STACK_BOF,
            'strcat': VulnPattern.STACK_BOF,
            'sprintf': VulnPattern.STACK_BOF,
            'scanf': VulnPattern.STACK_BOF,
            'printf': VulnPattern.FORMAT_STRING,
            'fprintf': VulnPattern.FORMAT_STRING,
            'system': VulnPattern.COMMAND_INJECTION,
            'popen': VulnPattern.COMMAND_INJECTION,
            'malloc': VulnPattern.HEAP_BOF,
            'free': VulnPattern.USE_AFTER_FREE,
        }

        for func_name in binary.functions:
            if func_name in dangerous_imports:
                vuln_type = dangerous_imports[func_name]
                related = self.database.get_entries_by_type(vuln_type)

                if related:
                    best = max(related, key=lambda e: e.cvss_score)
                else:
                    best = CVEEntry(
                        cve_id="FUNC-PATTERN",
                        description=f"Binary uses dangerous function {func_name}",
                        vulnerability_type=vuln_type,
                    )

                matches.append(PatternMatch(
                    cve_entry=best,
                    confidence=0.4,
                    matched_location=func_name,
                    matched_patterns=[f"func:{func_name}"],
                    explanation=f"Binary imports dangerous function: {func_name}"
                ))

        # Check for function call patterns
        for pattern, cve_ids in self.database.pattern_index.items():
            if pattern.startswith("call:"):
                funcs = pattern[5:].split("->")
                if all(f in binary.functions for f in funcs):
                    for cve_id in cve_ids:
                        entry = self.database.entries.get(cve_id)
                        if entry:
                            matches.append(PatternMatch(
                                cve_entry=entry,
                                confidence=0.6,
                                matched_location="call sequence",
                                matched_patterns=[pattern],
                                explanation=f"Binary has call pattern from {cve_id}"
                            ))

        return sorted(matches, key=lambda m: m.confidence, reverse=True)

    def find_similar_cves(self, description: str, top_k: int = 5) -> List[Tuple[CVEEntry, float]]:
        """
        Find CVEs similar to a description.

        Args:
            description: Vulnerability description to match
            top_k: Number of results

        Returns:
            List of (CVEEntry, similarity) tuples
        """
        return self.database.find_similar_by_description(description, top_k)

    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about learned patterns."""
        type_counts = defaultdict(int)
        for entry in self.database.entries.values():
            type_counts[entry.vulnerability_type.value] += 1

        return {
            "total_cves": len(self.database.entries),
            "total_patterns": len(self.database.pattern_index),
            "by_type": dict(type_counts),
            "avg_cvss": sum(e.cvss_score for e in self.database.entries.values()) /
                       max(len(self.database.entries), 1),
        }


# Built-in patterns for common vulnerabilities (no CVE database needed)
class BuiltinPatternMatcher:
    """
    Matches code against built-in vulnerability patterns.

    Does not require CVE database - uses hardcoded patterns
    for common vulnerability types.
    """

    PATTERNS = {
        VulnPattern.STACK_BOF: {
            "high_confidence": [
                (r'\bgets\s*\(', "Use of gets() is always vulnerable"),
                (r'\bstrcpy\s*\([^,]+,\s*\w+\s*\)', "strcpy without bounds checking"),
            ],
            "medium_confidence": [
                (r'\bscanf\s*\(\s*"[^"]*%s[^"]*"', "scanf with %s may overflow"),
                (r'\bsprintf\s*\([^,]+,\s*"[^"]*%s', "sprintf with %s may overflow"),
            ],
        },
        VulnPattern.FORMAT_STRING: {
            "high_confidence": [
                (r'\bprintf\s*\(\s*[a-zA-Z_]\w*\s*\)', "printf with user-controlled format"),
                (r'\bfprintf\s*\([^,]+,\s*[a-zA-Z_]\w*\s*\)', "fprintf with user-controlled format"),
            ],
            "medium_confidence": [
                (r'\bsyslog\s*\([^,]+,\s*[a-zA-Z_]\w*', "syslog with variable format"),
            ],
        },
        VulnPattern.COMMAND_INJECTION: {
            "high_confidence": [
                (r'\bsystem\s*\(\s*[a-zA-Z_]\w*\s*\)', "system() with variable argument"),
                (r'\bpopen\s*\(\s*[a-zA-Z_]\w*', "popen with variable command"),
            ],
        },
        VulnPattern.INTEGER_OVERFLOW: {
            "medium_confidence": [
                (r'\bmalloc\s*\(\s*\w+\s*\*\s*\w+\s*\)', "malloc with multiplication"),
                (r'size_t\s+\w+\s*=\s*\w+\s*\*\s*\w+', "size calculation with multiplication"),
            ],
        },
    }

    def __init__(self):
        self._compiled = {}
        for vuln_type, confidence_levels in self.PATTERNS.items():
            self._compiled[vuln_type] = {}
            for level, patterns in confidence_levels.items():
                self._compiled[vuln_type][level] = [
                    (re.compile(p, re.IGNORECASE), desc)
                    for p, desc in patterns
                ]

    def match(self, code: str) -> List[Dict[str, Any]]:
        """
        Match code against built-in patterns.

        Args:
            code: Source or decompiled code

        Returns:
            List of match dictionaries
        """
        results = []

        for vuln_type, confidence_levels in self._compiled.items():
            for level, patterns in confidence_levels.items():
                for pattern, description in patterns:
                    for match in pattern.finditer(code):
                        line_num = code[:match.start()].count('\n') + 1
                        confidence = 0.9 if level == "high_confidence" else 0.6

                        results.append({
                            "vulnerability_type": vuln_type.value,
                            "confidence": confidence,
                            "line": line_num,
                            "match": match.group(),
                            "description": description,
                        })

        return results
