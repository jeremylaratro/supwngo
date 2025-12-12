#!/usr/bin/env python3
"""
Comprehensive test of all challenge binaries against writeup solutions.
"""
import json
from pathlib import Path
from supwngo.core.binary import Binary
from supwngo.analysis.protections import ProtectionAnalyzer
from supwngo.analysis.static import StaticAnalyzer
from supwngo.exploit.strategy import StrategySuggester, ExploitApproach
from supwngo.exploit.rop.gadgets import GadgetFinder

# Expected results based on writeups
CHALLENGE_INFO = {
    "laconic": {
        "path": "challenges/laconic",
        "writeup_solution": "SROP",
        "expected_approaches": ["SROP", "SHELLCODE"],
        "protections": {"canary": False, "nx": False, "pie": False, "static": True},
        "key_features": ["has /bin/sh at 0x43238", "minimal 26-byte code", "read 262 bytes to stack-8"],
        "gadgets_needed": ["syscall"],
    },
    "crossbow": {
        "path": "challenges/crossbow",
        "writeup_solution": "OOB write + stack pivot + mprotect + shellcode",
        "expected_approaches": ["SROP", "MPROTECT_SHELLCODE", "STACK_PIVOT"],
        "protections": {"canary": True, "nx": True, "pie": False, "static": True},
        "key_features": ["OOB array write via negative index", "leave;ret for stack pivot"],
        "gadgets_needed": ["leave; ret", "pop rdi", "pop rsi", "pop rdx", "syscall"],
    },
    "abyss": {
        "path": "challenges/pwn_abyss/challenge/abyss",
        "writeup_solution": "Stack BOF via strcpy -> ret2win/read function",
        "expected_approaches": ["ROP_SYSTEM", "RET2PLT", "ROP_EXECVE"],
        "protections": {"canary": False, "nx": True, "pie": False, "static": False},
        "key_features": ["strcpy overflow", "cmd_read function"],
        "gadgets_needed": ["pop rdi", "ret"],
    },
    "void": {
        "path": "challenges/challenge/void",
        "writeup_solution": "ret2dlresolve",
        "expected_approaches": ["RET2DLRESOLVE", "ROP_SYSTEM"],
        "protections": {"canary": False, "nx": True, "pie": False, "static": False},
        "key_features": ["Limited gadgets", "Partial RELRO"],
        "gadgets_needed": ["leave; ret"],
    },
    "htb-console": {
        "path": "challenges/171/htb-console",
        "writeup_solution": "Stack BOF + ROP",
        "expected_approaches": ["ROP_SYSTEM", "ROP_EXECVE"],
        "protections": {"canary": False, "nx": True, "pie": False, "static": False},
        "key_features": ["16-byte buffer", "stripped binary"],
        "gadgets_needed": ["pop rdi", "ret"],
    },
    "assemblers_avenge": {
        "path": "challenges/assemblers_avenge",
        "writeup_solution": "Shellcode/syscall writing",
        "expected_approaches": ["SHELLCODE"],
        "protections": {"canary": False, "nx": False, "pie": False, "static": True},
        "key_features": ["RWX segments", "Custom assembly"],
        "gadgets_needed": [],
    },
    "fleet_management": {
        "path": "challenges/339/fleet_management",
        "writeup_solution": "Shellcode with sendfile/openat syscalls",
        "expected_approaches": ["ROP_EXECVE", "SHELLCODE"],
        "protections": {"canary": False, "nx": True, "pie": True, "static": False},
        "key_features": ["File exfiltration"],
        "gadgets_needed": [],
    },
    "oxidized-rop": {
        "path": "challenges/pwn_oxidized_rop/oxidized-rop",
        "writeup_solution": "Rust BOF overwriting boolean",
        "expected_approaches": ["ROP_EXECVE", "ROP_SYSTEM"],
        "protections": {"canary": False, "nx": True, "pie": True, "static": False},
        "key_features": ["Rust binary", "unsafe buffer ops"],
        "gadgets_needed": [],
    },
    "ancient_interface": {
        "path": "challenges/488(1)-(1)/challenge/ancient_interface",
        "writeup_solution": "SIGALRM + buffer underflow",
        "expected_approaches": ["ROP_SYSTEM", "ROP_EXECVE"],
        "protections": {"canary": True, "nx": True, "pie": False, "static": False},
        "key_features": ["alarm timer", "negative index"],
        "gadgets_needed": ["pop rdi"],
    },
}

def test_binary(name, info):
    """Test a single binary against expected results."""
    path = Path(info["path"])
    if not path.exists():
        return {"name": name, "status": "SKIP", "reason": "not found"}
    
    result = {"name": name, "path": str(path)}
    
    try:
        # Load binary
        binary = Binary.load(str(path))
        result["arch"] = binary.arch
        result["bits"] = binary.bits
        
        # Protection analysis
        prot_analyzer = ProtectionAnalyzer(binary)
        prots = prot_analyzer.analyze()
        result["protections"] = {
            "canary": prots.canary,
            "nx": prots.nx,
            "pie": prots.pie,
            "relro": prots.relro,
            "static": prots.static,
        }
        
        # Check protections match expected
        expected_prots = info["protections"]
        prot_match = all(
            result["protections"].get(k) == v 
            for k, v in expected_prots.items()
        )
        result["protections_match"] = prot_match
        
        # Static analysis
        static = StaticAnalyzer(binary)
        static_results = static.analyze()
        result["dangerous_functions"] = [
            c["function"] for c in static_results.get("dangerous_calls", [])[:5]
        ]
        
        # Gadget analysis
        gadget_finder = GadgetFinder(binary)
        gadgets = gadget_finder.find_gadgets()
        result["total_gadgets"] = len(gadgets)
        
        # Check for specific needed gadgets
        found_gadgets = {}
        for gadget_name in info.get("gadgets_needed", []):
            if "pop" in gadget_name:
                reg = gadget_name.split()[1]
                found = gadget_finder.find_pop_reg(reg)
            elif gadget_name == "syscall":
                found = gadget_finder.find_syscall()
            elif gadget_name == "leave; ret":
                found = gadget_finder.find_leave_ret()
            elif gadget_name == "ret":
                found = gadget_finder.find_ret()
            else:
                found = gadget_finder.find_gadget([gadget_name])
            found_gadgets[gadget_name] = found is not None
        result["gadgets_found"] = found_gadgets
        
        # Strategy analysis
        suggester = StrategySuggester(binary, gadget_finder)
        report = suggester.analyze()
        
        result["recommended"] = report.recommended.approach.name if report.recommended else None
        result["all_strategies"] = [s.approach.name for s in report.strategies]
        result["has_binsh"] = report.has_binsh
        result["has_win_function"] = report.has_win_function
        
        # Check if expected approaches are found
        expected = info["expected_approaches"]
        found_expected = [a for a in expected if a in result["all_strategies"]]
        result["expected_approaches"] = expected
        result["expected_found"] = found_expected
        result["strategy_match"] = len(found_expected) > 0
        
        # Overall status
        result["status"] = "PASS" if result["strategy_match"] else "FAIL"
        
    except Exception as e:
        result["status"] = "ERROR"
        result["error"] = str(e)
    
    return result

def main():
    print("=" * 70)
    print("COMPREHENSIVE BINARY TESTING")
    print("=" * 70)
    
    results = []
    for name, info in CHALLENGE_INFO.items():
        print(f"\nTesting: {name}")
        result = test_binary(name, info)
        results.append(result)
        
        status = result["status"]
        if status == "PASS":
            print(f"  ✓ PASS - Recommended: {result.get('recommended')}")
            print(f"    Expected: {result.get('expected_approaches')}")
            print(f"    Found: {result.get('expected_found')}")
        elif status == "SKIP":
            print(f"  ⊘ SKIP - {result.get('reason')}")
        elif status == "ERROR":
            print(f"  ✗ ERROR - {result.get('error')}")
        else:
            print(f"  ✗ FAIL - Recommended: {result.get('recommended')}")
            print(f"    Expected: {result.get('expected_approaches')}")
            print(f"    All strategies: {result.get('all_strategies')}")
        
        # Print gadget info
        if result.get("gadgets_found"):
            missing = [k for k, v in result["gadgets_found"].items() if not v]
            if missing:
                print(f"    Missing gadgets: {missing}")
    
    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    
    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = sum(1 for r in results if r["status"] == "FAIL")
    skipped = sum(1 for r in results if r["status"] == "SKIP")
    errors = sum(1 for r in results if r["status"] == "ERROR")
    
    print(f"PASSED:  {passed}")
    print(f"FAILED:  {failed}")
    print(f"SKIPPED: {skipped}")
    print(f"ERRORS:  {errors}")
    
    # Save detailed results
    with open("output/test_results.json", "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nDetailed results saved to output/test_results.json")

if __name__ == "__main__":
    main()
