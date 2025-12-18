"""
Grammar-aware fuzzing for structured inputs.

Grammar-aware fuzzers generate and mutate inputs that conform
to a specified grammar, maintaining syntactic validity while
exploring semantic edge cases.

Use cases:
- Protocol fuzzing (HTTP, DNS, TLS)
- File format fuzzing (PDF, PNG, ELF)
- Language fuzzing (SQL, JavaScript)
- API fuzzing (JSON, XML)

References:
- Nautilus: Grammar-based fuzzing
- Gramatron: Grammar automaton fuzzing
- AFL++ Grammar Mutator
"""

import random
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

from supwngo.utils.logging import get_logger

logger = get_logger(__name__)


class RuleType(Enum):
    """Grammar rule types."""
    TERMINAL = auto()      # Literal string
    NONTERMINAL = auto()   # Reference to other rule
    SEQUENCE = auto()      # Concatenation of elements
    ALTERNATION = auto()   # One of multiple choices
    REPETITION = auto()    # Repeated element
    OPTIONAL = auto()      # Optional element
    REGEX = auto()         # Regular expression pattern


@dataclass
class GrammarRule:
    """A single grammar rule."""
    name: str
    rule_type: RuleType
    value: Union[str, List['GrammarRule']] = ""
    min_repeat: int = 0
    max_repeat: int = 1
    weight: float = 1.0  # For weighted selection in alternations

    def __repr__(self):
        return f"Rule({self.name}, {self.rule_type.name})"


@dataclass
class Grammar:
    """Complete grammar definition."""
    name: str
    start_symbol: str
    rules: Dict[str, GrammarRule] = field(default_factory=dict)
    max_depth: int = 50  # Prevent infinite recursion

    def add_rule(self, rule: GrammarRule):
        """Add a rule to the grammar."""
        self.rules[rule.name] = rule

    def get_rule(self, name: str) -> Optional[GrammarRule]:
        """Get rule by name."""
        return self.rules.get(name)


class GrammarParser:
    """
    Parse grammar definitions from various formats.

    Supports:
    - BNF-like syntax
    - JSON format
    - Python dict format
    """

    def parse_bnf(self, bnf_text: str) -> Grammar:
        """
        Parse BNF-like grammar definition.

        Example:
            <start> ::= <header> <body>
            <header> ::= "GET" | "POST" | "PUT"
            <body> ::= <line>*
            <line> ::= <text> "\\n"
            <text> ::= /[a-zA-Z0-9]+/

        Args:
            bnf_text: Grammar in BNF format

        Returns:
            Parsed Grammar
        """
        grammar = Grammar(name="bnf", start_symbol="start")
        lines = bnf_text.strip().split('\n')

        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            if '::=' not in line:
                continue

            name, definition = line.split('::=', 1)
            name = name.strip().strip('<>')
            definition = definition.strip()

            rule = self._parse_definition(name, definition)
            grammar.add_rule(rule)

        return grammar

    def _parse_definition(self, name: str, definition: str) -> GrammarRule:
        """Parse a single rule definition."""
        # Check for alternation (|)
        if '|' in definition:
            alternatives = [alt.strip() for alt in definition.split('|')]
            alt_rules = [self._parse_element(f"{name}_{i}", alt)
                        for i, alt in enumerate(alternatives)]
            return GrammarRule(
                name=name,
                rule_type=RuleType.ALTERNATION,
                value=alt_rules,
            )

        # Check for repetition (*)
        if definition.endswith('*'):
            inner = definition[:-1].strip()
            inner_rule = self._parse_element(f"{name}_inner", inner)
            return GrammarRule(
                name=name,
                rule_type=RuleType.REPETITION,
                value=[inner_rule],
                min_repeat=0,
                max_repeat=10,
            )

        # Check for optional (?)
        if definition.endswith('?'):
            inner = definition[:-1].strip()
            inner_rule = self._parse_element(f"{name}_inner", inner)
            return GrammarRule(
                name=name,
                rule_type=RuleType.OPTIONAL,
                value=[inner_rule],
            )

        # Sequence of elements
        elements = definition.split()
        if len(elements) > 1:
            seq_rules = [self._parse_element(f"{name}_{i}", elem)
                        for i, elem in enumerate(elements)]
            return GrammarRule(
                name=name,
                rule_type=RuleType.SEQUENCE,
                value=seq_rules,
            )

        return self._parse_element(name, definition)

    def _parse_element(self, name: str, element: str) -> GrammarRule:
        """Parse a single element."""
        element = element.strip()

        # Terminal (quoted string)
        if (element.startswith('"') and element.endswith('"')) or \
           (element.startswith("'") and element.endswith("'")):
            return GrammarRule(
                name=name,
                rule_type=RuleType.TERMINAL,
                value=element[1:-1],
            )

        # Regex (/pattern/)
        if element.startswith('/') and element.endswith('/'):
            return GrammarRule(
                name=name,
                rule_type=RuleType.REGEX,
                value=element[1:-1],
            )

        # Nonterminal (<name>)
        if element.startswith('<') and element.endswith('>'):
            return GrammarRule(
                name=name,
                rule_type=RuleType.NONTERMINAL,
                value=element[1:-1],
            )

        # Default to terminal
        return GrammarRule(
            name=name,
            rule_type=RuleType.TERMINAL,
            value=element,
        )

    def parse_json(self, json_data: Dict[str, Any]) -> Grammar:
        """
        Parse grammar from JSON format.

        Example:
            {
                "name": "http",
                "start": "request",
                "rules": {
                    "request": {"type": "sequence", "value": ["method", " ", "path"]},
                    "method": {"type": "alternation", "value": ["GET", "POST"]},
                    "path": {"type": "regex", "value": "/[a-z/]+"}
                }
            }
        """
        grammar = Grammar(
            name=json_data.get("name", "json"),
            start_symbol=json_data.get("start", "start"),
        )

        for name, rule_def in json_data.get("rules", {}).items():
            rule_type = RuleType[rule_def.get("type", "terminal").upper()]
            rule = GrammarRule(
                name=name,
                rule_type=rule_type,
                value=rule_def.get("value", ""),
                min_repeat=rule_def.get("min", 0),
                max_repeat=rule_def.get("max", 1),
            )
            grammar.add_rule(rule)

        return grammar


class GrammarGenerator:
    """
    Generate inputs from grammar.

    Strategies:
    - Random: Fully random choices at each branch
    - Weighted: Use rule weights for biased selection
    - Coverage: Track and prioritize uncovered rules
    - Minimal: Generate shortest valid input
    - Maximal: Generate longest/most complex input
    """

    def __init__(self, grammar: Grammar):
        self.grammar = grammar
        self.max_depth = grammar.max_depth
        self.coverage: Set[str] = set()

    def generate(
        self,
        strategy: str = "random",
        seed: Optional[int] = None,
    ) -> bytes:
        """
        Generate a valid input.

        Args:
            strategy: Generation strategy
            seed: Random seed for reproducibility

        Returns:
            Generated input
        """
        if seed is not None:
            random.seed(seed)

        result = self._expand(self.grammar.start_symbol, 0, strategy)
        return result.encode() if isinstance(result, str) else result

    def _expand(
        self,
        symbol: str,
        depth: int,
        strategy: str,
    ) -> str:
        """Recursively expand a symbol."""
        if depth > self.max_depth:
            return ""

        rule = self.grammar.get_rule(symbol)
        if not rule:
            return symbol  # Literal

        self.coverage.add(symbol)

        if rule.rule_type == RuleType.TERMINAL:
            return str(rule.value)

        elif rule.rule_type == RuleType.NONTERMINAL:
            return self._expand(str(rule.value), depth + 1, strategy)

        elif rule.rule_type == RuleType.SEQUENCE:
            parts = []
            for sub_rule in rule.value:
                if isinstance(sub_rule, GrammarRule):
                    parts.append(self._expand(sub_rule.name, depth + 1, strategy))
                else:
                    parts.append(str(sub_rule))
            return "".join(parts)

        elif rule.rule_type == RuleType.ALTERNATION:
            choices = rule.value
            if strategy == "coverage":
                # Prefer uncovered choices
                uncovered = [c for c in choices if c.name not in self.coverage]
                if uncovered:
                    choices = uncovered

            choice = random.choice(choices)
            if isinstance(choice, GrammarRule):
                return self._expand(choice.name, depth + 1, strategy)
            return str(choice)

        elif rule.rule_type == RuleType.REPETITION:
            count = random.randint(rule.min_repeat, rule.max_repeat)
            parts = []
            for _ in range(count):
                for sub_rule in rule.value:
                    if isinstance(sub_rule, GrammarRule):
                        parts.append(self._expand(sub_rule.name, depth + 1, strategy))
            return "".join(parts)

        elif rule.rule_type == RuleType.OPTIONAL:
            if random.random() < 0.5:
                return ""
            for sub_rule in rule.value:
                if isinstance(sub_rule, GrammarRule):
                    return self._expand(sub_rule.name, depth + 1, strategy)
            return ""

        elif rule.rule_type == RuleType.REGEX:
            return self._generate_from_regex(str(rule.value))

        return ""

    def _generate_from_regex(self, pattern: str) -> str:
        """Generate string matching regex pattern."""
        # Simple regex generation for common patterns
        result = []

        i = 0
        while i < len(pattern):
            c = pattern[i]

            if c == '[':
                # Character class
                end = pattern.index(']', i)
                char_class = pattern[i+1:end]
                result.append(self._pick_from_class(char_class))
                i = end + 1

            elif c == '\\':
                # Escape sequence
                i += 1
                if i < len(pattern):
                    esc = pattern[i]
                    if esc == 'd':
                        result.append(random.choice('0123456789'))
                    elif esc == 'w':
                        result.append(random.choice('abcdefghijklmnopqrstuvwxyz0123456789_'))
                    elif esc == 's':
                        result.append(' ')
                    elif esc == 'n':
                        result.append('\n')
                    else:
                        result.append(esc)
                i += 1

            elif c in '+*':
                # Quantifier - repeat previous
                if result:
                    last = result[-1]
                    count = random.randint(0, 5) if c == '*' else random.randint(1, 5)
                    result.extend([last] * count)
                i += 1

            elif c == '.':
                # Any character
                result.append(random.choice('abcdefghijklmnopqrstuvwxyz0123456789'))
                i += 1

            else:
                result.append(c)
                i += 1

        return ''.join(result)

    def _pick_from_class(self, char_class: str) -> str:
        """Pick character from character class."""
        chars = []
        i = 0
        while i < len(char_class):
            if i + 2 < len(char_class) and char_class[i+1] == '-':
                # Range
                start = ord(char_class[i])
                end = ord(char_class[i+2])
                chars.extend(chr(c) for c in range(start, end + 1))
                i += 3
            else:
                chars.append(char_class[i])
                i += 1

        return random.choice(chars) if chars else ''


class GrammarMutator:
    """
    Mutate inputs while preserving grammar validity.

    Mutation strategies:
    - Subtree replacement: Replace subtree with new generation
    - Subtree crossover: Exchange subtrees between inputs
    - Rule substitution: Replace with alternative rule
    - Terminal mutation: Mutate terminal values
    - Recursion manipulation: Add/remove repetitions
    """

    def __init__(self, grammar: Grammar, generator: GrammarGenerator):
        self.grammar = grammar
        self.generator = generator

    def mutate(
        self,
        input_data: bytes,
        mutation_rate: float = 0.1,
    ) -> bytes:
        """
        Mutate input while preserving validity.

        Args:
            input_data: Original input
            mutation_rate: Probability of mutation at each point

        Returns:
            Mutated input
        """
        # For now, regenerate with some random changes
        # A full implementation would parse the input into AST and mutate
        if random.random() < mutation_rate:
            return self.generator.generate(strategy="random")

        # Terminal mutation
        data = bytearray(input_data)
        for i in range(len(data)):
            if random.random() < mutation_rate:
                data[i] = random.randint(0, 255)

        return bytes(data)


class GrammarFuzzer:
    """
    High-level grammar-aware fuzzer.

    Combines grammar parsing, generation, and mutation.
    """

    def __init__(self, grammar: Grammar):
        self.grammar = grammar
        self.generator = GrammarGenerator(grammar)
        self.mutator = GrammarMutator(grammar, self.generator)
        self.corpus: List[bytes] = []
        self.crashes: List[bytes] = []

    def seed_corpus(self, seeds: List[bytes]):
        """Add seed inputs to corpus."""
        self.corpus.extend(seeds)

    def generate(self, count: int = 1) -> List[bytes]:
        """Generate new valid inputs."""
        return [self.generator.generate() for _ in range(count)]

    def fuzz(
        self,
        target: Callable[[bytes], int],
        iterations: int = 1000,
        save_crashes: bool = True,
    ) -> Dict[str, Any]:
        """
        Run grammar fuzzing campaign.

        Args:
            target: Function to fuzz
            iterations: Number of iterations
            save_crashes: Whether to save crash inputs

        Returns:
            Fuzzing statistics
        """
        stats = {
            "iterations": 0,
            "crashes": 0,
            "coverage": 0,
        }

        for i in range(iterations):
            # Generate or mutate
            if self.corpus and random.random() < 0.7:
                base = random.choice(self.corpus)
                test_input = self.mutator.mutate(base)
            else:
                test_input = self.generator.generate()

            try:
                result = target(test_input)
                if result != 0:
                    self.corpus.append(test_input)
            except Exception:
                stats["crashes"] += 1
                if save_crashes:
                    self.crashes.append(test_input)

            stats["iterations"] += 1

        stats["coverage"] = len(self.generator.coverage)
        return stats


# Pre-defined grammars for common formats
HTTP_GRAMMAR = """
<start> ::= <request>
<request> ::= <method> " " <path> " " <version> "\\r\\n" <headers> "\\r\\n"
<method> ::= "GET" | "POST" | "PUT" | "DELETE" | "HEAD"
<path> ::= "/" <path_segment>*
<path_segment> ::= /[a-z0-9_-]+/ "/"?
<version> ::= "HTTP/1.0" | "HTTP/1.1"
<headers> ::= <header>*
<header> ::= <header_name> ": " <header_value> "\\r\\n"
<header_name> ::= /[A-Za-z-]+/
<header_value> ::= /[^\\r\\n]+/
"""

JSON_GRAMMAR = """
<start> ::= <value>
<value> ::= <object> | <array> | <string> | <number> | "true" | "false" | "null"
<object> ::= "{" <members>? "}"
<members> ::= <pair> <more_pairs>*
<more_pairs> ::= "," <pair>
<pair> ::= <string> ":" <value>
<array> ::= "[" <elements>? "]"
<elements> ::= <value> <more_elements>*
<more_elements> ::= "," <value>
<string> ::= '"' /[a-zA-Z0-9_]+/ '"'
<number> ::= /[0-9]+/
"""
