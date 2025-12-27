#!/bin/bash
#
# supwngo Auto-Implementation Script
# Runs Claude CLI to implement features phase by phase
#
# Usage:
#   ./auto_implement.sh          # Run next phase
#   ./auto_implement.sh --status # Check current status
#   ./auto_implement.sh --reset  # Reset to phase 1
#   ./auto_implement.sh --phase N # Run specific phase N
#
# Cron setup (every 2 hours):
#   0 */2 * * * /home/jay/Documents/cyber/dev/supwngo/scripts/auto_implement.sh >> /home/jay/Documents/cyber/dev/supwngo/logs/auto_implement.log 2>&1
#

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
STATE_FILE="$PROJECT_DIR/.implementation_state"
LOG_DIR="$PROJECT_DIR/logs"
PROMPTS_DIR="$SCRIPT_DIR/prompts"
MAX_PHASES=8

# Ensure directories exist
mkdir -p "$LOG_DIR" "$PROMPTS_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

log_success() {
    log "${GREEN}SUCCESS:${NC} $1"
}

log_error() {
    log "${RED}ERROR:${NC} $1"
}

log_info() {
    log "${BLUE}INFO:${NC} $1"
}

# Get current phase from state file
get_current_phase() {
    if [[ -f "$STATE_FILE" ]]; then
        cat "$STATE_FILE"
    else
        echo "1"
    fi
}

# Set current phase
set_current_phase() {
    echo "$1" > "$STATE_FILE"
}

# Check if Claude CLI is available
check_claude() {
    if ! command -v claude &> /dev/null; then
        log_error "Claude CLI not found. Please install it first."
        exit 1
    fi
}

# Generate prompt for a phase
get_phase_prompt() {
    local phase=$1
    local prompt_file="$PROMPTS_DIR/phase${phase}.txt"

    if [[ -f "$prompt_file" ]]; then
        cat "$prompt_file"
    else
        # Generate default prompt based on phase
        case $phase in
            1)
                cat << 'EOF'
Implement Phase 1: Stack Exploitation Enhancements for the supwngo framework.

Create the following modules:

1. `supwngo/exploit/rop/pivot.py` - Stack Pivoting
   - Detect stack pivot gadgets (xchg rsp, leave; ret, etc.)
   - Generate pivot payloads to redirect RSP to controlled buffer
   - Handle both relative and absolute pivots

2. Update `supwngo/exploit/rop/gadgets.py` - ret2reg support
   - Find jmp/call reg gadgets (jmp rax, call rsi, etc.)
   - Integrate with exploit generation when buffer address is in register
   - Add GadgetType enum entries for these

3. Update `supwngo/exploit/bypass.py` - Partial Overwrite
   - Add PartialOverwrite class for PIE bypass
   - Implement brute force for 12-bit randomization
   - Generate payload that overwrites only lower 2-3 bytes

Update __init__.py files to export new classes.
Add docstrings and type hints.
Test imports work correctly.

Reference IMPLEMENTATION_PLAN.md for details.
EOF
                ;;
            2)
                cat << 'EOF'
Implement Phase 2: Format String Automation for the supwngo framework.

Create/update the following:

1. Update `supwngo/vulns/format_string.py` - Blind Offset Finder
   - Add method to automatically find format string offset
   - Use binary search approach (send %N$p patterns)
   - Handle both 32-bit and 64-bit binaries

2. Create `supwngo/exploit/format_string.py` - Format String Exploiter
   - FormatStringExploit class for generating payloads
   - One-shot exploit generation (single printf for GOT overwrite)
   - Arbitrary write primitive abstraction
   - Support for %n, %hn, %hhn writes
   - Handle bad character restrictions

3. Integrate with auto.py
   - Add formatstring_auto technique
   - Auto-detect and exploit format string vulns

Update exports and add tests.
Reference IMPLEMENTATION_PLAN.md for details.
EOF
                ;;
            3)
                cat << 'EOF'
Implement Phase 3: Heap Fundamentals for the supwngo framework.

Create the following modules:

1. `supwngo/exploit/heap/house_of_force.py`
   - Detect House of Force conditions (top chunk overflow)
   - Calculate distance to target address
   - Generate payload to overwrite top chunk size
   - Handle malloc size wraparound

2. `supwngo/exploit/heap/house_of_spirit.py`
   - Identify locations for fake chunks (stack, bss, heap)
   - Generate fake chunk headers with valid size/flags
   - Create free() primitive to add fake chunk to freelist
   - Support both fastbin and tcache versions

3. `supwngo/exploit/heap/unsorted_bin.py`
   - Unsorted bin attack for arbitrary write
   - Corrupt bk pointer to write main_arena address
   - Common targets: __malloc_hook, __free_hook, _IO_list_all

Update heap/__init__.py exports.
Create simple test cases for each technique.
Reference IMPLEMENTATION_PLAN.md for details.
EOF
                ;;
            4)
                cat << 'EOF'
Implement Phase 4: Modern Heap Techniques for the supwngo framework.

Create/update the following:

1. Update `supwngo/exploit/heap/tcache.py`
   - Handle tcache key/count checks (glibc 2.32+)
   - Tcache stashing unlink attack
   - Double-free with tcache key bypass

2. Create `supwngo/exploit/heap/large_bin.py`
   - Large bin attack implementation
   - Corrupt bk_nextsize for arbitrary write
   - Calculate chunk sizes for large bin placement

3. Create `supwngo/exploit/heap/safe_linking.py`
   - Detect safe-linking (glibc 2.32+)
   - PROTECT_PTR / REVEAL_PTR implementations
   - Heap address leak requirement detection
   - Demangle safe-linked pointers

Add glibc version detection to select appropriate technique.
Update exports and create tests.
Reference IMPLEMENTATION_PLAN.md for details.
EOF
                ;;
            5)
                cat << 'EOF'
Implement Phase 5: Advanced ROP Techniques for the supwngo framework.

Create/update the following:

1. Create `supwngo/exploit/rop/ret2csu.py`
   - Automatic __libc_csu_init gadget detection
   - Generate chains for arbitrary function calls
   - Handle both pop rbx...ret and mov rdx, r15... gadgets
   - Support for calling functions with up to 3 args

2. Update `supwngo/exploit/rop/ret2dlresolve.py`
   - Full implementation with fake Elf64_Sym, Elf64_Rela
   - Stage the fake structures in writable memory
   - Resolve arbitrary libc functions without leak
   - Support both 32-bit and 64-bit

3. Create `supwngo/exploit/rop/optimizer.py`
   - Find minimal gadget chains for common ops
   - Reduce chain length by combining gadgets
   - Dead code elimination in chains
   - Common pattern: set_rdi_rsi_rdx_call

Update rop/__init__.py exports.
Add integration tests with static binaries.
Reference IMPLEMENTATION_PLAN.md for details.
EOF
                ;;
            6)
                cat << 'EOF'
Implement Phase 6: Kernel Exploitation Basics for the supwngo framework.

Create the following in supwngo/kernel/:

1. `supwngo/kernel/ret2usr.py`
   - Build userspace shellcode payload
   - commit_creds(prepare_kernel_cred(0)) pattern
   - Return to userspace after privilege escalation
   - Handle SMEP/SMAP detection

2. `supwngo/kernel/modprobe.py`
   - modprobe_path overwrite technique
   - Generate trigger script (unknown file format)
   - Path to overwrite detection
   - Payload generation for arbitrary command

3. `supwngo/kernel/krop.py`
   - Kernel ROP chain builder
   - Find kernel gadgets from /proc/kallsyms or vmlinux
   - Common gadgets: prepare_kernel_cred, commit_creds
   - Stack pivot for kernel context

Create kernel/__init__.py with exports.
Document QEMU test setup requirements.
Reference IMPLEMENTATION_PLAN.md for details.
EOF
                ;;
            7)
                cat << 'EOF'
Implement Phase 7: Race Conditions & Misc for the supwngo framework.

Create the following:

1. `supwngo/vulns/race.py`
   - TOCTOU vulnerability detection
   - Identify access() followed by open() patterns
   - symlink race condition exploitation
   - Thread/fork race primitives

2. `supwngo/exploit/signal_handler.py`
   - Detect signal handler vulnerabilities
   - Exploit async-signal-unsafe function calls
   - Double-fetch in signal context
   - Generate race payloads with alarm()

3. `supwngo/exploit/ld_preload.py`
   - Generate malicious shared object
   - Constructor/destructor hooks
   - Function interposition templates
   - SUID binary exploitation via LD_PRELOAD

Update main vulns/__init__.py and exploit/__init__.py.
Add detection to CLI analyze command.
Reference IMPLEMENTATION_PLAN.md for details.
EOF
                ;;
            8)
                cat << 'EOF'
Implement Phase 8: Integration & Auto-Chaining for the supwngo framework.

Create/update the following:

1. Create `supwngo/exploit/chainer.py`
   - ExploitChain class to combine primitives
   - Automatic leak → calculate → write → execute flow
   - Primitive dependency graph
   - Multi-stage exploit orchestration

2. Update `supwngo/exploit/auto.py`
   - Comprehensive technique selection based on:
     - Binary protections (RELRO, canary, NX, PIE)
     - Available primitives (leak, write, exec)
     - Detected vulnerabilities
   - Try techniques in optimal order
   - Fall back to partial exploits with templates

3. Create comprehensive test suite in `tests/`
   - test_stack_exploits.py
   - test_heap_exploits.py
   - test_format_string.py
   - test_rop_techniques.py
   - Integration tests with sample binaries

4. Update CLI
   - Add --technique flag to force specific technique
   - Improve exploit command output
   - Add 'chain' subcommand for multi-stage

Reference IMPLEMENTATION_PLAN.md for details.
Run full test suite and fix any issues.
EOF
                ;;
            *)
                echo "Invalid phase: $phase"
                exit 1
                ;;
        esac
    fi
}

# Run implementation for a phase
run_phase() {
    local phase=$1
    local log_file="$LOG_DIR/phase${phase}_$(date '+%Y%m%d_%H%M%S').log"

    log_info "Starting Phase $phase implementation"
    log_info "Log file: $log_file"

    # Get the prompt
    local prompt=$(get_phase_prompt $phase)

    # Change to project directory
    cd "$PROJECT_DIR"

    # Run Claude CLI with the prompt
    # Using -p to pass prompt, output captured to log
    # Add timeout of 90 minutes
    log_info "Invoking Claude CLI..."

    if claude --verbose --dangerously-skip-permissions -p "$prompt" >> "$log_file" 2>&1; then
        log_success "Phase $phase completed successfully"

        # Increment phase for next run
        local next_phase=$((phase + 1))
        if [[ $next_phase -le $MAX_PHASES ]]; then
            set_current_phase $next_phase
            log_info "Next run will execute Phase $next_phase"
        else
            log_success "All phases completed!"
            set_current_phase "COMPLETE"
        fi

        return 0
    else
        local exit_code=$?
        log_error "Phase $phase failed with exit code $exit_code"
        log_error "Check log file for details: $log_file"
        return 1
    fi
}

# Show status
show_status() {
    local phase=$(get_current_phase)

    echo ""
    echo "=================================="
    echo "  supwngo Implementation Status"
    echo "=================================="
    echo ""

    if [[ "$phase" == "COMPLETE" ]]; then
        echo -e "${GREEN}All phases completed!${NC}"
    else
        echo -e "Current Phase: ${YELLOW}$phase${NC} of $MAX_PHASES"
        echo ""
        echo "Phase Overview:"
        for i in $(seq 1 $MAX_PHASES); do
            if [[ $i -lt $phase ]]; then
                echo -e "  Phase $i: ${GREEN}Completed${NC}"
            elif [[ $i -eq $phase ]]; then
                echo -e "  Phase $i: ${YELLOW}Next${NC}"
            else
                echo -e "  Phase $i: ${BLUE}Pending${NC}"
            fi
        done
    fi

    echo ""
    echo "Log directory: $LOG_DIR"
    echo "State file: $STATE_FILE"
    echo ""
}

# Main
main() {
    case "${1:-}" in
        --status)
            show_status
            ;;
        --reset)
            set_current_phase 1
            log_success "Reset to Phase 1"
            ;;
        --phase)
            if [[ -z "${2:-}" ]]; then
                log_error "Please specify phase number"
                exit 1
            fi
            check_claude
            run_phase "$2"
            ;;
        --help|-h)
            echo "Usage: $0 [--status|--reset|--phase N|--help]"
            echo ""
            echo "Options:"
            echo "  --status    Show current implementation status"
            echo "  --reset     Reset to Phase 1"
            echo "  --phase N   Run specific phase N"
            echo "  --help      Show this help"
            echo ""
            echo "Without options, runs the next pending phase."
            ;;
        "")
            check_claude
            local phase=$(get_current_phase)

            if [[ "$phase" == "COMPLETE" ]]; then
                log_success "All phases already completed. Use --reset to start over."
                exit 0
            fi

            run_phase "$phase"
            ;;
        *)
            log_error "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
}

main "$@"
