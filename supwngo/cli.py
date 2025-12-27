#!/usr/bin/env python3
"""
SupwnGo - Automated Binary Exploitation Framework

CLI interface using Click for command-line interaction.
"""

import json
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from supwngo import __version__

console = Console()


def print_banner():
    """Print SupwnGo banner."""
    banner = """
    ╔═══════════════════════════════════════════════════════════╗
    ║   ____                            ____                    ║
    ║  / ___| _   _ _ ____      ___ __ / ___| ___               ║
    ║  \\___ \\| | | | '_ \\ \\ /\\ / / '_ \\ |  _ / _ \\              ║
    ║   ___) | |_| | |_) \\ V  V /| | | | |_| | (_) |            ║
    ║  |____/ \\__,_| .__/ \\_/\\_/ |_| |_|\\____|\\___/             ║
    ║              |_|                                          ║
    ║  Automated Binary Exploitation Framework                  ║
    ╚═══════════════════════════════════════════════════════════╝
    """
    console.print(banner, style="bold cyan")


@click.group()
@click.version_option(version=__version__)
@click.option("-v", "--verbose", count=True, help="Increase verbosity")
@click.pass_context
def cli(ctx, verbose):
    """SupwnGo - Automated Binary Exploitation Framework"""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose

    # Setup logging
    from supwngo.utils.logging import setup_logging
    setup_logging(verbosity=verbose)


@cli.command()
@click.argument("binary", type=click.Path(exists=True))
@click.option("-o", "--output", default="./output", help="Output directory")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
@click.pass_context
def analyze(ctx, binary, output, json_output):
    """Perform comprehensive binary analysis."""
    from supwngo.core.binary import Binary
    from supwngo.analysis.static import StaticAnalyzer
    from supwngo.analysis.protections import ProtectionAnalyzer

    console.print(f"\n[bold]Analyzing:[/bold] {binary}\n")

    # Load binary
    with console.status("Loading binary..."):
        bin_obj = Binary.load(binary)

    # Run analysis
    with console.status("Running static analysis..."):
        static = StaticAnalyzer(bin_obj)
        static_results = static.analyze()

    with console.status("Analyzing protections..."):
        prot_analyzer = ProtectionAnalyzer(bin_obj)
        prots = prot_analyzer.analyze()

    if json_output:
        results = {
            "binary": str(binary),
            "arch": bin_obj.arch,
            "bits": bin_obj.bits,
            "protections": prots.to_dict(),
            "dangerous_functions": static_results.get("dangerous_calls", []),
            "input_sources": static_results.get("input_sources", []),
        }
        console.print_json(json.dumps(results, indent=2))
    else:
        # Print checksec report
        console.print(Panel(prot_analyzer.checksec_report(), title="Protections"))

        # Print dangerous functions
        if static_results.get("dangerous_calls"):
            table = Table(title="Dangerous Function Calls")
            table.add_column("Function", style="red")
            table.add_column("Address", style="cyan")
            table.add_column("Risk", style="yellow")

            for call in static_results["dangerous_calls"][:10]:
                table.add_row(
                    call["function"],
                    call["address"],
                    call["risk"],
                )

            console.print(table)

        # Print input sources
        if static_results.get("input_sources"):
            console.print("\n[bold]Input Sources:[/bold]")
            for source in static_results["input_sources"]:
                console.print(f"  - {source['function']} ({source['type']})")

    # Save to output
    Path(output).mkdir(parents=True, exist_ok=True)
    output_file = Path(output) / f"{Path(binary).name}_analysis.json"

    with open(output_file, "w") as f:
        json.dump({
            "binary": str(binary),
            "arch": bin_obj.arch,
            "bits": bin_obj.bits,
            "protections": prots.to_dict(),
            "analysis": static_results,
        }, f, indent=2, default=str)

    console.print(f"\n[green]Analysis saved to {output_file}[/green]")


@cli.command()
@click.argument("binary", type=click.Path(exists=True))
@click.option("-i", "--input-dir", required=True, help="Input corpus directory")
@click.option("-o", "--output-dir", default="./fuzz_output", help="Output directory")
@click.option("-t", "--timeout", default=3600, help="Fuzzing timeout in seconds")
@click.option("-j", "--cores", default=4, help="Number of fuzzing cores")
@click.option("-Q", "--qemu", is_flag=True, help="Use QEMU mode")
@click.option("--afl/--honggfuzz", default=True, help="Fuzzer to use")
@click.pass_context
def fuzz(ctx, binary, input_dir, output_dir, timeout, cores, qemu, afl):
    """Launch fuzzing campaign with crash collection."""
    console.print(f"\n[bold]Fuzzing:[/bold] {binary}\n")

    from supwngo.core.binary import Binary
    from supwngo.fuzzing.afl import AFLFuzzer, AFLConfig

    # Load binary
    bin_obj = Binary.load(binary)

    if afl:
        from supwngo.fuzzing.afl import AFLFuzzer, AFLConfig

        config = AFLConfig(
            binary_path=binary,
            qemu_mode=qemu,
        )

        fuzzer = AFLFuzzer(bin_obj, config)
        fuzzer.setup(input_dir, output_dir, timeout=1000, qemu_mode=qemu)

        console.print(f"[cyan]Starting AFL++ fuzzing for {timeout}s...[/cyan]")

        def progress_callback(stats):
            console.print(
                f"  Execs: {stats.execs_done:,} | "
                f"Crashes: {stats.crashes_total} | "
                f"Coverage: {stats.bitmap_cvg}%",
                end="\r",
            )

        results = fuzzer.run_campaign(timeout, progress_callback)

        console.print("\n")
        console.print(Panel(f"""
Fuzzing Complete
================
Duration: {results['duration']:.1f}s
Executions: {results['execs_total']:,}
Crashes: {results['crashes']}
Paths: {results['paths_found']}
Coverage: {results['coverage']}%
""", title="Results"))

        if results["crash_files"]:
            console.print("\n[bold red]Crashes found:[/bold red]")
            for crash in results["crash_files"][:10]:
                console.print(f"  - {crash}")
    else:
        console.print("[yellow]Honggfuzz support coming soon[/yellow]")


@cli.command()
@click.argument("crash_dir", type=click.Path(exists=True))
@click.argument("binary", type=click.Path(exists=True))
@click.option("-o", "--output", default="./triage_report.json", help="Output report")
@click.option("--minimize/--no-minimize", default=True, help="Minimize crashes")
@click.pass_context
def triage(ctx, crash_dir, binary, output, minimize):
    """Triage and analyze crashes."""
    console.print(f"\n[bold]Triaging crashes from:[/bold] {crash_dir}\n")

    from supwngo.core.binary import Binary
    from supwngo.fuzzing.crash_triage import CrashTriager

    bin_obj = Binary.load(binary)
    triager = CrashTriager(bin_obj)

    with console.status("Analyzing crashes..."):
        result = triager.triage_directory(crash_dir, minimize=minimize)

    # Print report
    console.print(triager.generate_report(result))

    # Save report
    report = {
        "total": result.total_crashes,
        "unique": result.unique_crashes,
        "exploitable": result.exploitable,
        "probably_exploitable": result.probably_exploitable,
        "crashes": [
            {
                "hash": c.crash_hash,
                "type": c.crash_type.name,
                "address": hex(c.crash_address),
                "signal": c.signal,
                "exploitability": c.exploitability.name,
                "pc_control": c.pc_control,
            }
            for c in result.get_best_crashes(20)
        ],
    }

    with open(output, "w") as f:
        json.dump(report, f, indent=2)

    console.print(f"\n[green]Report saved to {output}[/green]")


@cli.command()
@click.argument("binary", type=click.Path(exists=True))
@click.option("-c", "--crash", type=click.Path(exists=True), help="Crash input file")
@click.option("-r", "--remote", help="Remote target (host:port)")
@click.option("-l", "--libc", type=click.Path(exists=True), help="Target libc")
@click.option("-o", "--output", default="./exploit.py", help="Output exploit script")
@click.option("--auto", is_flag=True, help="Attempt automatic exploitation")
@click.pass_context
def exploit(ctx, binary, crash, remote, libc, output, auto):
    """Generate exploit for vulnerable binary."""
    console.print(f"\n[bold]Generating exploit for:[/bold] {binary}\n")

    from supwngo.core.binary import Binary
    from supwngo.core.context import ExploitContext
    from supwngo.vulns.stack_bof import StackBufferOverflowDetector
    from supwngo.exploit.generator import ExploitGenerator

    # Load binary
    bin_obj = Binary.load(binary)

    # Create context
    context = ExploitContext.from_binary(bin_obj)

    if remote:
        host, port = remote.split(":")
        context.set_remote(host, int(port))

    if libc:
        context.set_libc(libc)

    # Detect vulnerability
    vuln = None

    if crash:
        from supwngo.fuzzing.crash_triage import CrashTriager, CrashCase

        console.print("[cyan]Analyzing crash...[/cyan]")
        triager = CrashTriager(bin_obj)
        crash_data = Path(crash).read_bytes()
        vuln_crash = triager.analyze_crash(crash_data)

        if vuln_crash:
            console.print(f"  Signal: {vuln_crash.signal}")
            console.print(f"  Address: 0x{vuln_crash.crash_address:x}")
            console.print(f"  PC Control: {vuln_crash.pc_control}")
            console.print(f"  Exploitability: {vuln_crash.exploitability.name}")

            # Convert to vulnerability
            from supwngo.vulns.detector import Vulnerability, VulnType, VulnSeverity
            vuln = Vulnerability(
                vuln_type=VulnType.STACK_BUFFER_OVERFLOW,
                severity=VulnSeverity.CRITICAL if vuln_crash.pc_control else VulnSeverity.HIGH,
                address=vuln_crash.crash_address,
                detection_method="crash",
                controllable_input=crash_data,
                crash=vuln_crash,
            )
    else:
        # Try to detect vulnerability automatically
        console.print("[cyan]Detecting vulnerabilities...[/cyan]")

        # Check for canary bypass first (needed for protected binaries)
        from supwngo.vulns.canary_bypass import CanaryBypassDetector

        if bin_obj.protections.canary:
            canary_detector = CanaryBypassDetector(bin_obj)
            canary_vulns = canary_detector.detect()
            if canary_vulns:
                vuln = canary_vulns[0]
                console.print(f"  Found: [green]{vuln.description}[/green]")
                console.print(f"  Bypass type: {vuln.details.get('bypass_type', 'unknown')}")
                console.print(f"  Skip character: '{vuln.details.get('skip_character', '.')}'")
                console.print(f"  Canary index: {vuln.details.get('canary_index', 33)}")

        # Also check for stack buffer overflows
        if not vuln:
            detector = StackBufferOverflowDetector(bin_obj)
            vulns = detector.detect()

            if vulns:
                vuln = vulns[0]
                console.print(f"  Found: {vuln.vuln_type.name}")
                console.print(f"  Function: {vuln.function}")

    if not vuln:
        console.print("[yellow]No vulnerability detected by static analysis[/yellow]")
        console.print("[cyan]Trying enhanced auto-exploit with dynamic analysis...[/cyan]")

        # Try enhanced auto-exploiter which includes dynamic profiling
        from supwngo.exploit.enhanced_auto import EnhancedAutoExploiter

        exploiter = EnhancedAutoExploiter(bin_obj, libc_path=libc)
        exploiter.run()

        if exploiter.successful:
            console.print(f"\n[bold green]SUCCESS![/bold green] Technique: {exploiter.technique_used}")
            console.print(f"Payload length: {len(exploiter.final_payload)} bytes")

            # Show flag if captured
            if exploiter._captured_flag:
                console.print(f"\n[bold magenta]FLAG: {exploiter._captured_flag}[/bold magenta]")

            # Show verification status
            if exploiter.verification_level:
                from supwngo.exploit.verification import VerificationLevel
                if exploiter.verification_level == VerificationLevel.FLAG_CAPTURED:
                    console.print("[bold green]Exploitation verified by flag capture[/bold green]")
                elif exploiter.verification_level.value >= VerificationLevel.SHELL_ACCESS.value:
                    console.print("[bold green]Shell access verified[/bold green]")

            # Save exploit script
            with open(output, "w") as f:
                f.write(exploiter.exploit_script if exploiter.exploit_script else exploiter.exploit_template)

            Path(output).chmod(0o755)
            console.print(f"\n[green]Exploit saved to {output}[/green]")
        else:
            console.print("[red]No exploitable vulnerability found[/red]")
            console.print("[yellow]Saving template for manual analysis...[/yellow]")

            # Save template anyway
            with open(output, "w") as f:
                f.write(exploiter.exploit_template)
            console.print(f"[yellow]Template saved to {output}[/yellow]")
        return

    # Generate exploit
    console.print("\n[cyan]Generating exploit...[/cyan]")

    # For canary bypass vulnerabilities, use AutoExploiter
    if vuln.details.get('bypass_type') == 'SCANF_SKIP':
        from supwngo.exploit.auto import AutoExploiter

        exploiter = AutoExploiter(bin_obj, libc_path=libc)
        report = exploiter.run(techniques=["scanf_canary_bypass"])

        if report.exploit_script:
            console.print(f"  Technique: scanf canary bypass")
            console.print(f"  Script generated: {len(report.exploit_script)} bytes")

            # Save exploit script
            with open(output, "w") as f:
                f.write(report.exploit_script)

            Path(output).chmod(0o755)
            console.print(f"\n[green]Exploit saved to {output}[/green]")

            if report.successful:
                console.print("[green bold]Exploit verified working![/green bold]")
            return
        else:
            console.print("[yellow]Canary bypass detected but exploit generation failed[/yellow]")
            console.print("[yellow]Falling back to standard exploit generator[/yellow]")

    generator = ExploitGenerator(context)
    exploit_obj = generator.generate(vuln, auto_pwn=auto)

    if exploit_obj.success:
        console.print(f"  Technique: {exploit_obj.technique.name}")
        console.print(f"  Payload size: {len(exploit_obj.payload)} bytes")

        # Save exploit script
        with open(output, "w") as f:
            f.write(exploit_obj.script)

        Path(output).chmod(0o755)

        console.print(f"\n[green]Exploit saved to {output}[/green]")

        # Also save raw payload
        payload_file = Path(output).with_suffix(".bin")
        payload_file.write_bytes(exploit_obj.payload)
        console.print(f"[green]Payload saved to {payload_file}[/green]")
    else:
        console.print("[yellow]Standard exploit generation failed, trying enhanced auto-exploit...[/yellow]")

        # Fall back to enhanced auto-exploiter
        from supwngo.exploit.enhanced_auto import EnhancedAutoExploiter

        exploiter = EnhancedAutoExploiter(bin_obj, libc_path=libc)
        exploiter.run()

        if exploiter.successful:
            console.print(f"\n[bold green]SUCCESS![/bold green] Technique: {exploiter.technique_used}")
            console.print(f"Payload length: {len(exploiter.final_payload)} bytes")

            # Show flag if captured
            if exploiter._captured_flag:
                console.print(f"\n[bold magenta]FLAG: {exploiter._captured_flag}[/bold magenta]")

            # Show verification status
            if exploiter.verification_level:
                from supwngo.exploit.verification import VerificationLevel
                if exploiter.verification_level == VerificationLevel.FLAG_CAPTURED:
                    console.print("[bold green]Exploitation verified by flag capture[/bold green]")
                elif exploiter.verification_level.value >= VerificationLevel.SHELL_ACCESS.value:
                    console.print("[bold green]Shell access verified[/bold green]")

            # Save exploit script
            with open(output, "w") as f:
                f.write(exploiter.exploit_script if exploiter.exploit_script else exploiter.exploit_template)

            Path(output).chmod(0o755)
            console.print(f"\n[green]Exploit saved to {output}[/green]")
        else:
            console.print("[red]All exploit generation methods failed[/red]")
            console.print("[yellow]Saving template for manual completion...[/yellow]")

            # Save template anyway
            with open(output, "w") as f:
                f.write(exploiter.exploit_template)
            console.print(f"[yellow]Template saved to {output}[/yellow]")


@cli.command()
@click.argument("binary", type=click.Path(exists=True))
@click.option("-l", "--libc", type=click.Path(exists=True), help="Libc for ret2libc")
@click.option("--chain", type=click.Choice(["shell", "execve", "mprotect"]), default="shell")
@click.option("-o", "--output", help="Output file for ROP chain")
@click.pass_context
def rop(ctx, binary, libc, chain, output):
    """Find ROP gadgets and generate common chains."""
    console.print(f"\n[bold]ROP Analysis:[/bold] {binary}\n")

    from supwngo.core.binary import Binary
    from supwngo.exploit.rop.gadgets import GadgetFinder
    from supwngo.exploit.rop.chain import ROPChainBuilder

    bin_obj = Binary.load(binary)

    # Find gadgets
    console.print("[cyan]Finding gadgets...[/cyan]")
    finder = GadgetFinder(bin_obj)
    gadgets = finder.find_gadgets()

    console.print(f"  Found {len(gadgets)} gadgets")

    # Print useful gadgets
    table = Table(title="Useful Gadgets")
    table.add_column("Type", style="cyan")
    table.add_column("Address", style="green")
    table.add_column("Instructions", style="white")

    useful = [
        ("pop rdi", finder.find_pop_reg("rdi")),
        ("pop rsi", finder.find_pop_reg("rsi")),
        ("pop rdx", finder.find_pop_reg("rdx")),
        ("pop rax", finder.find_pop_reg("rax")),
        ("syscall", finder.find_syscall()),
        ("ret", finder.find_ret()),
        ("leave; ret", finder.find_leave_ret()),
    ]

    for name, gadget in useful:
        if gadget:
            table.add_row(name, f"0x{gadget.address:x}", gadget.instructions)

    console.print(table)

    # Build chain
    if chain:
        console.print(f"\n[cyan]Building {chain} chain...[/cyan]")
        builder = ROPChainBuilder(bin_obj, libc)

        chain_bytes = None
        if chain == "shell" and libc:
            chain_bytes = builder.build_ret2libc_chain()
        elif chain == "execve":
            chain_bytes = builder.build_execve_chain()
        elif chain == "mprotect":
            chain_bytes = builder.build_mprotect_chain(0x400000, 0x1000)

        if chain_bytes:
            console.print(f"  Chain length: {len(chain_bytes)} bytes")

            if output:
                Path(output).write_bytes(chain_bytes)
                console.print(f"  [green]Saved to {output}[/green]")
            else:
                console.print(f"  Hex: {chain_bytes.hex()}")


@cli.command()
@click.argument("binary", type=click.Path(exists=True))
@click.option("-t", "--timeout", default=300, help="Exploration timeout")
@click.option("--find-crashes", is_flag=True, help="Find crash paths")
@click.pass_context
def symbolic(ctx, binary, timeout, find_crashes):
    """Run symbolic execution analysis."""
    console.print(f"\n[bold]Symbolic Execution:[/bold] {binary}\n")

    from supwngo.core.binary import Binary
    from supwngo.symbolic.angr_engine import AngrEngine
    from supwngo.symbolic.path_finder import PathFinder

    bin_obj = Binary.load(binary)

    console.print("[cyan]Initializing angr...[/cyan]")
    engine = AngrEngine(bin_obj)

    if find_crashes:
        console.print("[cyan]Finding unconstrained states...[/cyan]")
        finder = PathFinder(bin_obj, engine)

        with console.status("Exploring..."):
            states = finder.find_unconstrained_states(timeout=timeout)

        if states:
            console.print(f"\n[green]Found {len(states)} unconstrained states![/green]")

            for i, state in enumerate(states[:5]):
                console.print(f"\n  State {i + 1}:")
                console.print(f"    Controlled registers: {state.controlled_regs}")

                # Try to generate input
                if state.state:
                    input_data = engine.concretize_state(state.state)
                    if input_data:
                        console.print(f"    Input: {input_data[:50].hex()}...")
        else:
            console.print("[yellow]No unconstrained states found[/yellow]")


@cli.command()
@click.option("--puts", type=str, help="Leaked puts address (hex)")
@click.option("--printf", type=str, help="Leaked printf address (hex)")
@click.option("--system", type=str, help="Leaked system address (hex)")
@click.pass_context
def libc_id(ctx, puts, printf, system):
    """Identify remote libc from leaked addresses."""
    console.print("\n[bold]Libc Identification[/bold]\n")

    from supwngo.remote.libc_db import LibcDatabase

    db = LibcDatabase()

    # Parse leaked addresses
    symbols = {}
    if puts:
        symbols["puts"] = int(puts, 16) & 0xFFF
    if printf:
        symbols["printf"] = int(printf, 16) & 0xFFF
    if system:
        symbols["system"] = int(system, 16) & 0xFFF

    if not symbols:
        console.print("[red]Provide at least one leaked address[/red]")
        return

    console.print(f"[cyan]Searching with:[/cyan]")
    for name, offset in symbols.items():
        console.print(f"  {name}: 0x{offset:03x}")

    with console.status("Querying libc database..."):
        matches = db.identify(symbols)

    if matches:
        console.print(f"\n[green]Found {len(matches)} matches:[/green]")

        table = Table()
        table.add_column("ID")
        table.add_column("Version")
        table.add_column("system")
        table.add_column("Download")

        for match in matches[:10]:
            table.add_row(
                match.id,
                match.version,
                f"0x{match.symbols.get('system', 0):x}",
                match.download_url[:50] if match.download_url else "",
            )

        console.print(table)
    else:
        console.print("[yellow]No matching libc found[/yellow]")


@cli.command()
@click.argument("binary", type=click.Path(exists=True))
@click.option("-l", "--libc", type=click.Path(exists=True), help="Target libc for ret2libc/one_gadget")
@click.option("--no-gadgets", is_flag=True, help="Skip gadget enumeration (faster)")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
@click.pass_context
def pwn(ctx, binary, libc, no_gadgets, json_output):
    """
    CTF-focused analysis with exploit strategy suggestions.

    This command performs comprehensive binary analysis and suggests
    the best exploitation strategies based on protections and available
    gadgets. Designed for CTF challenges.
    """
    from supwngo.core.binary import Binary
    from supwngo.analysis.protections import ProtectionAnalyzer
    from supwngo.analysis.static import StaticAnalyzer
    from supwngo.exploit.strategy import StrategySuggester, suggest_strategies
    from supwngo.exploit.rop.gadgets import GadgetFinder

    console.print(f"\n[bold cyan]{'=' * 60}[/bold cyan]")
    console.print(f"[bold cyan]  SupwnGo CTF Analysis: {Path(binary).name}[/bold cyan]")
    console.print(f"[bold cyan]{'=' * 60}[/bold cyan]\n")

    # Load binary
    with console.status("Loading binary..."):
        bin_obj = Binary.load(binary)

    # Protection analysis
    with console.status("Analyzing protections..."):
        prot_analyzer = ProtectionAnalyzer(bin_obj)
        prots = prot_analyzer.analyze()

    # Print checksec
    console.print(Panel(prot_analyzer.checksec_report(), title="[bold]Security Features[/bold]"))

    # Static analysis
    with console.status("Running static analysis..."):
        static = StaticAnalyzer(bin_obj)
        static_results = static.analyze()

    # Print dangerous functions
    if static_results.get("dangerous_calls"):
        table = Table(title="[bold red]Dangerous Functions[/bold red]")
        table.add_column("Function", style="red")
        table.add_column("Address", style="cyan")
        table.add_column("Risk", style="yellow")

        for call in static_results["dangerous_calls"][:15]:
            table.add_row(call["function"], call["address"], call["risk"])

        console.print(table)

    # Gadget analysis (optional but recommended)
    gadget_finder = None
    if not no_gadgets:
        with console.status("Enumerating ROP gadgets..."):
            gadget_finder = GadgetFinder(bin_obj)
            gadgets = gadget_finder.find_gadgets()

        console.print(f"\n[cyan]Found {len(gadgets)} gadgets[/cyan]")

        # Show useful gadgets
        useful_table = Table(title="[bold]Key Gadgets[/bold]")
        useful_table.add_column("Type", style="cyan")
        useful_table.add_column("Address", style="green")
        useful_table.add_column("Instructions")

        useful_checks = [
            ("pop rdi", gadget_finder.find_pop_reg("rdi")),
            ("pop rsi", gadget_finder.find_pop_reg("rsi")),
            ("pop rdx", gadget_finder.find_pop_reg("rdx")),
            ("pop rax", gadget_finder.find_pop_reg("rax")),
            ("syscall", gadget_finder.find_syscall()),
            ("leave; ret", gadget_finder.find_leave_ret()),
            ("ret", gadget_finder.find_ret()),
        ]

        for name, gadget in useful_checks:
            if gadget:
                useful_table.add_row(name, f"0x{gadget.address:x}", gadget.instructions)
            else:
                useful_table.add_row(name, "[red]NOT FOUND[/red]", "")

        console.print(useful_table)

    # One-gadget analysis (if libc provided)
    if libc:
        with console.status("Finding one-gadgets in libc..."):
            from supwngo.analysis.one_gadget import OneGadgetFinder
            og_finder = OneGadgetFinder(libc)
            one_gadgets = og_finder.find()

        if one_gadgets:
            og_table = Table(title="[bold magenta]One-Gadgets[/bold magenta]")
            og_table.add_column("Address", style="green")
            og_table.add_column("Constraints", style="yellow")

            for og in one_gadgets[:5]:
                og_table.add_row(
                    f"0x{og.address:x}",
                    ", ".join(og.constraints) if og.constraints else "None"
                )

            console.print(og_table)

    # Strategy suggestion
    console.print(f"\n[bold yellow]{'=' * 60}[/bold yellow]")
    console.print("[bold yellow]  EXPLOIT STRATEGY SUGGESTIONS[/bold yellow]")
    console.print(f"[bold yellow]{'=' * 60}[/bold yellow]\n")

    with console.status("Analyzing exploit strategies..."):
        suggester = StrategySuggester(bin_obj, gadget_finder)
        report = suggester.analyze()

    if json_output:
        console.print_json(json.dumps(report.to_dict(), indent=2))
    else:
        # Print warnings
        if report.warnings:
            console.print("[bold red]⚠️  Warnings:[/bold red]")
            for w in report.warnings:
                console.print(f"    [red]! {w}[/red]")
            console.print()

        # Print recommended strategy
        if report.recommended:
            console.print(Panel(
                str(report.recommended),
                title="[bold green]🎯 RECOMMENDED APPROACH[/bold green]",
                border_style="green"
            ))

        # Print all strategies
        console.print("\n[bold]All Viable Strategies:[/bold]")
        for i, strat in enumerate(sorted(report.strategies, key=lambda s: s.priority)):
            if strat == report.recommended:
                continue
            style = "dim" if i > 2 else ""
            console.print(f"\n[{style}]{strat}[/{style}]" if style else f"\n{strat}")

        # Print notes
        if report.notes:
            console.print("\n[bold cyan]📝 Notes:[/bold cyan]")
            for note in report.notes:
                console.print(f"    [cyan]- {note}[/cyan]")


@cli.command()
@click.argument("binary", type=click.Path(exists=True))
@click.option("-m", "--max-length", default=2048, help="Maximum pattern length")
@click.option("-i", "--input-method", type=click.Choice(["stdin", "argv", "file"]), default="stdin")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
@click.pass_context
def offset(ctx, binary, max_length, input_method, json_output):
    """
    Find buffer overflow offset automatically.

    Uses cyclic patterns and crash analysis to determine the exact
    offset needed to overwrite the return address.
    """
    from supwngo.core.binary import Binary
    from supwngo.exploit.offset_finder import OffsetFinder

    console.print(f"\n[bold]Finding buffer overflow offset:[/bold] {binary}\n")

    # Load binary to get architecture
    bin_obj = Binary.load(binary)

    finder = OffsetFinder(binary, bits=bin_obj.bits)

    with console.status(f"Testing with pattern length up to {max_length}..."):
        result = finder.find_offset(max_length, input_method)

    if json_output:
        console.print_json(json.dumps(result.to_dict(), indent=2))
    else:
        if result.success:
            console.print(Panel(f"""
[bold green]✓ Offset Found![/bold green]

Return Address Offset: [bold cyan]{result.offset}[/bold cyan] (0x{result.offset:x})
Method: {result.method}
Crash Address: {hex(result.crash_address) if result.crash_address else 'N/A'}

[bold]Payload Template:[/bold]
    padding = b'A' * {result.offset}
    payload = padding + p64(target_address)
""", title="Offset Discovery Result", border_style="green"))

            if result.rbp_offset:
                console.print(f"[cyan]Saved RBP offset: {result.rbp_offset}[/cyan]")

            if result.register_values:
                console.print("\n[bold]Register values at crash:[/bold]")
                for reg, val in sorted(result.register_values.items()):
                    console.print(f"    {reg}: 0x{val:x}")
        else:
            console.print(f"[red]✗ Failed: {result.error}[/red]")
            console.print("\n[yellow]Tips:[/yellow]")
            console.print("  - Make sure the binary crashes on overflow")
            console.print("  - Try different input methods: --input-method argv")
            console.print("  - Increase pattern length: --max-length 4096")


@cli.command()
@click.argument("libc", type=click.Path(exists=True))
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
@click.pass_context
def onegadget(ctx, libc, json_output):
    """
    Find one-gadgets (magic gadgets) in libc.

    One-gadgets are single addresses that spawn a shell with
    minimal constraints. Useful for ret2libc attacks.
    """
    from supwngo.analysis.one_gadget import OneGadgetFinder

    console.print(f"\n[bold]Finding one-gadgets in:[/bold] {libc}\n")

    finder = OneGadgetFinder(libc)

    with console.status("Analyzing libc..."):
        gadgets = finder.find()

    if not gadgets:
        console.print("[yellow]No one-gadgets found.[/yellow]")
        console.print("Tips:")
        console.print("  - Install one_gadget: gem install one_gadget")
        console.print("  - Ensure libc is a valid ELF file")
        return

    if json_output:
        console.print_json(json.dumps([g.to_dict() for g in gadgets], indent=2))
    else:
        table = Table(title=f"One-Gadgets in {Path(libc).name}")
        table.add_column("Address", style="green")
        table.add_column("Constraints", style="yellow")

        for g in sorted(gadgets, key=lambda x: len(x.constraints)):
            table.add_row(
                f"0x{g.address:x}",
                "\n".join(g.constraints) if g.constraints else "[green]None[/green]"
            )

        console.print(table)

        best = finder.get_best_gadget()
        if best:
            console.print(f"\n[bold green]Best gadget:[/bold green] 0x{best.address:x}")
            console.print(f"[dim]Constraints: {best.constraint_summary}[/dim]")


@cli.command()
@click.argument("binary", type=click.Path(exists=True))
@click.pass_context
def checksec(ctx, binary):
    """Quick security features check (like checksec.sh)."""
    from supwngo.core.binary import Binary
    from supwngo.analysis.protections import ProtectionAnalyzer

    bin_obj = Binary.load(binary)
    analyzer = ProtectionAnalyzer(bin_obj)
    prots = analyzer.analyze()

    console.print(analyzer.checksec_report())


@cli.command()
@click.argument("length", type=int)
@click.pass_context
def cyclic(ctx, length):
    """Generate cyclic pattern for offset discovery."""
    from supwngo.exploit.offset_finder import cyclic as gen_cyclic

    pattern = gen_cyclic(length)
    console.print(pattern.decode('latin-1'))


@cli.command()
@click.argument("value")
@click.pass_context
def cyclic_find(ctx, value):
    """Find offset in cyclic pattern (hex value or string)."""
    from supwngo.exploit.offset_finder import cyclic_find as find_cyclic

    # Try to parse as hex
    if value.startswith("0x"):
        val = int(value, 16)
    else:
        try:
            val = int(value, 16)
        except ValueError:
            val = value.encode('latin-1')

    offset = find_cyclic(val)

    if offset >= 0:
        console.print(f"[green]Found at offset: {offset} (0x{offset:x})[/green]")
    else:
        console.print("[red]Pattern not found[/red]")


@cli.command()
@click.argument("directory", type=click.Path(exists=True))
@click.option("-o", "--output", default="./batch_results.json", help="Output file")
@click.pass_context
def batch(ctx, directory, output):
    """Batch analyze all binaries in a directory."""
    from supwngo.core.binary import Binary
    from supwngo.analysis.protections import ProtectionAnalyzer
    from supwngo.exploit.strategy import StrategySuggester

    dir_path = Path(directory)
    results = []

    # Find all ELF files
    binaries = []
    for f in dir_path.rglob("*"):
        if f.is_file() and not f.suffix in ['.py', '.txt', '.md', '.json', '.pdf', '.zip']:
            try:
                # Quick check if it's an ELF
                with open(f, 'rb') as fp:
                    if fp.read(4) == b'\x7fELF':
                        binaries.append(f)
            except Exception:
                pass

    console.print(f"[bold]Found {len(binaries)} binaries to analyze[/bold]\n")

    for binary in binaries:
        console.print(f"[cyan]Analyzing: {binary.name}[/cyan]")
        try:
            bin_obj = Binary.load(str(binary))
            prot_analyzer = ProtectionAnalyzer(bin_obj)
            prots = prot_analyzer.analyze()

            suggester = StrategySuggester(bin_obj)
            report = suggester.analyze()

            results.append({
                "name": binary.name,
                "path": str(binary),
                "arch": bin_obj.arch,
                "bits": bin_obj.bits,
                "protections": prots.to_dict(),
                "recommended_strategy": report.recommended.approach.name if report.recommended else None,
                "all_strategies": [s.approach.name for s in report.strategies],
                "has_win_function": report.has_win_function,
            })

            # Quick summary
            strat = report.recommended.approach.name if report.recommended else "Unknown"
            console.print(f"    → [green]{strat}[/green]")

        except Exception as e:
            console.print(f"    → [red]Error: {e}[/red]")
            results.append({
                "name": binary.name,
                "path": str(binary),
                "error": str(e),
            })

    # Save results
    with open(output, "w") as f:
        json.dump(results, f, indent=2)

    console.print(f"\n[green]Results saved to {output}[/green]")

    # Summary table
    table = Table(title="Batch Analysis Summary")
    table.add_column("Binary")
    table.add_column("Arch")
    table.add_column("Recommended Strategy")

    for r in results:
        if "error" in r:
            table.add_row(r["name"], "-", f"[red]{r['error'][:30]}[/red]")
        else:
            table.add_row(
                r["name"],
                f"{r['arch']}/{r['bits']}",
                r.get("recommended_strategy", "Unknown")
            )

    console.print(table)


@cli.command()
@click.argument("binary", type=click.Path(exists=True))
@click.option("-t", "--technique", type=click.Choice(["ret2win", "shellcode", "ret2system", "srop", "all"]),
              default="all", help="Specific technique to try")
@click.option("--offset", type=int, help="Known buffer offset")
@click.option("--timeout", default=5.0, type=float, help="Timeout per attempt")
@click.option("-l", "--libc", type=click.Path(exists=True), help="Custom libc file for ret2libc")
@click.option("-o", "--output", type=click.Path(), help="Save exploit script to file")
@click.option("--run", is_flag=True, help="Try to run the exploit automatically")
@click.pass_context
def autopwn(ctx, binary, technique, offset, timeout, libc, output, run):
    """
    Attempt automatic exploitation of binary.

    Tries various exploitation techniques automatically:
    - ret2win: Return to win function
    - uaf: Use-After-Free with function pointer overwrite
    - shellcode: Direct shellcode (if NX disabled)
    - ret2system: ret2libc system() call
    - srop: Sigreturn-oriented programming

    Examples:
        supwngo autopwn ./vuln_binary
        supwngo autopwn ./vuln_binary -t ret2win --offset 40
        supwngo autopwn ./vuln_binary -o exploit.py
    """
    from supwngo.core.binary import Binary
    from supwngo.exploit.auto import AutoExploiter, auto_exploit

    console.print(f"\n[bold cyan]{'=' * 60}[/bold cyan]")
    console.print(f"[bold cyan]  AutoPwn: {Path(binary).name}[/bold cyan]")
    console.print(f"[bold cyan]{'=' * 60}[/bold cyan]\n")

    # Load binary
    with console.status("Loading binary..."):
        bin_obj = Binary.load(binary)

    # Create exploiter
    exploiter = AutoExploiter(bin_obj, timeout=timeout, libc_path=libc)

    if offset:
        exploiter._offset = offset
        console.print(f"[cyan]Using provided offset: {offset}[/cyan]")

    if libc:
        console.print(f"[cyan]Using custom libc: {libc}[/cyan]")

    # Determine techniques to try
    if technique == "all":
        techniques = ["ret2win", "formatstring", "intoverflow", "uaf", "doublefree", "shellcode", "ret2system", "srop"]
    else:
        techniques = [technique]

    console.print(f"[cyan]Techniques to try: {', '.join(techniques)}[/cyan]\n")

    # Run exploitation
    with console.status("Attempting automatic exploitation..."):
        report = exploiter.run(techniques)

    # Display results
    if report.successful:
        console.print(Panel(f"""
[bold green]✓ Exploitation Successful![/bold green]

Technique: [bold cyan]{report.technique_used}[/bold cyan]
Payload Length: {len(report.final_payload)} bytes
""", title="AutoPwn Result", border_style="green"))

        if report.final_payload:
            console.print(f"\n[bold]Payload (hex):[/bold]")
            console.print(f"  {report.final_payload[:64].hex()}...")

    else:
        console.print(Panel(f"""
[bold yellow]⚠ Automatic exploitation did not succeed[/bold yellow]

Attempts: {len(report.attempts)}
""", title="AutoPwn Result", border_style="yellow"))

    # Show all attempts
    console.print("\n[bold]Exploitation Attempts:[/bold]")
    table = Table()
    table.add_column("Technique", style="cyan")
    table.add_column("Result")
    table.add_column("Notes")

    for attempt in report.attempts:
        result_style = {
            "SUCCESS": "green",
            "PARTIAL": "yellow",
            "FAILED": "red",
            "ERROR": "red",
        }.get(attempt.result.name, "white")

        table.add_row(
            attempt.technique,
            f"[{result_style}]{attempt.result.name}[/{result_style}]",
            "; ".join(attempt.notes[:2]) if attempt.notes else "-"
        )

    console.print(table)

    # Show/save exploit script
    if report.exploit_script:
        if output:
            with open(output, "w") as f:
                f.write(report.exploit_script)
            console.print(f"\n[green]Exploit script saved to: {output}[/green]")
        else:
            console.print("\n[bold]Generated Exploit Script:[/bold]")
            console.print(Panel(
                report.exploit_script[:2000] + "..." if len(report.exploit_script) > 2000 else report.exploit_script,
                title="exploit.py",
                border_style="cyan"
            ))


@cli.command()
@click.argument("binary", type=click.Path(exists=True))
@click.option("-t", "--technique", type=click.Choice([
    "ret2win", "shellcode", "ret2system", "ret2libc", "srop", "leak", "auto"
]), default="auto", help="Exploit technique template")
@click.option("--offset", type=int, help="Known buffer offset")
@click.option("-l", "--libc", type=click.Path(exists=True), help="Custom libc file")
@click.option("-o", "--output", type=click.Path(), help="Output file (default: exploit.py)")
@click.pass_context
def template(ctx, binary, technique, offset, libc, output):
    """
    Generate pwntools exploit script tailored to binary.

    Creates a ready-to-customize exploit script based on the
    binary's characteristics and the selected technique.

    Examples:
        supwngo template ./vuln_binary -t ret2win
        supwngo template ./vuln_binary -t ret2libc -o exploit.py
        supwngo template ./vuln_binary --offset 72
    """
    from supwngo.core.binary import Binary
    from supwngo.exploit.auto import generate_exploit_script
    from supwngo.exploit.strategy import StrategySuggester

    console.print(f"\n[bold]Generating exploit template for:[/bold] {binary}\n")

    # Load binary
    with console.status("Analyzing binary..."):
        bin_obj = Binary.load(binary)

        # Get strategy suggestion for auto mode
        if technique == "auto":
            suggester = StrategySuggester(bin_obj)
            report = suggester.analyze()
            if report.recommended:
                tech_map = {
                    "RET2WIN": "ret2win",
                    "SHELLCODE": "shellcode",
                    "ROP_SYSTEM": "ret2system",
                    "SROP": "srop",
                    "ROP_EXECVE": "ret2system",
                }
                technique = tech_map.get(report.recommended.approach.name, "ret2system")
                console.print(f"[cyan]Auto-detected technique: {technique}[/cyan]")

    # Map technique names
    if technique == "ret2libc":
        technique = "ret2system"
    if technique == "leak":
        technique = "ret2system"  # Will generate leak template

    # Pass libc to script generator if provided
    if libc:
        console.print(f"[cyan]Using custom libc: {libc}[/cyan]")

    # Generate script
    with console.status("Generating exploit script..."):
        script = generate_exploit_script(bin_obj, technique, offset, libc_path=libc)

    # Determine output file
    if not output:
        output = f"exploit_{Path(binary).stem}.py"

    # Save script
    with open(output, "w") as f:
        f.write(script)

    console.print(f"[green]Exploit script saved to: {output}[/green]")

    # Show preview
    console.print("\n[bold]Script Preview:[/bold]")
    preview_lines = script.split('\n')[:30]
    console.print(Panel(
        '\n'.join(preview_lines) + "\n...",
        title=output,
        border_style="cyan"
    ))

    console.print(f"\n[bold]Next steps:[/bold]")
    console.print(f"  1. Review and customize the script")
    console.print(f"  2. Fill in TODO items (offset, addresses)")
    console.print(f"  3. Run: python {output}")


@cli.command()
@click.argument("binary", type=click.Path(exists=True))
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
@click.pass_context
def addresses(ctx, binary, json_output):
    """
    Find useful addresses for exploitation.

    Searches for:
    - /bin/sh and shell strings
    - BSS and writable regions
    - GOT/PLT entries
    - mprotect targets
    """
    from supwngo.core.binary import Binary
    from supwngo.analysis.addresses import AddressFinder

    console.print(f"\n[bold]Finding useful addresses in:[/bold] {binary}\n")

    bin_obj = Binary.load(binary)
    finder = AddressFinder(bin_obj)

    with console.status("Searching..."):
        report = finder.find_all()

    if json_output:
        console.print_json(json.dumps(report.to_dict(), indent=2))
    else:
        # Shell strings
        console.print("[bold cyan]Shell Strings:[/bold cyan]")
        if report.binsh_addr:
            console.print(f"  /bin/sh:   [green]0x{report.binsh_addr:x}[/green]")
        if report.binbash_addr:
            console.print(f"  /bin/bash: [green]0x{report.binbash_addr:x}[/green]")
        if not report.binsh_addr and not report.binbash_addr:
            console.print("  [yellow]No shell strings found in binary[/yellow]")

        # Writable regions
        console.print("\n[bold cyan]Writable Regions:[/bold cyan]")
        if report.bss_addr:
            console.print(f"  BSS:  0x{report.bss_addr:x} ({report.bss_size} bytes)")
        if report.data_addr:
            console.print(f"  Data: 0x{report.data_addr:x} ({report.data_size} bytes)")
        for region in report.writable_regions[:3]:
            if region.name not in [".bss", ".data"]:
                console.print(f"  {region}")

        # Exploitation targets
        console.print("\n[bold cyan]Exploitation Targets:[/bold cyan]")
        if report.mprotect_target:
            console.print(f"  mprotect target: [green]0x{report.mprotect_target:x}[/green]")
        if report.shellcode_target:
            console.print(f"  shellcode target: [green]0x{report.shellcode_target:x}[/green]")

        # GOT entries
        if report.got_entries:
            console.print("\n[bold cyan]GOT Entries:[/bold cyan]")
            table = Table()
            table.add_column("Function", style="cyan")
            table.add_column("GOT Address", style="green")

            for name, addr in list(report.got_entries.items())[:10]:
                table.add_row(name, f"0x{addr:x}")

            console.print(table)

        # PLT entries
        if report.plt_entries:
            console.print("\n[bold cyan]PLT Entries:[/bold cyan]")
            table = Table()
            table.add_column("Function", style="cyan")
            table.add_column("PLT Address", style="green")

            for name, addr in list(report.plt_entries.items())[:10]:
                table.add_row(name, f"0x{addr:x}")

            console.print(table)


@cli.command()
@click.argument("source", type=click.Path(exists=True))
@click.option("-t", "--tools", multiple=True,
              type=click.Choice(["builtin", "bearer", "patterns", "all"]),
              default=["all"], help="SAST tools to use")
@click.option("-o", "--output", type=click.Path(), help="Save report to file")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
@click.pass_context
def source(ctx, source, tools, output, json_output):
    """
    Analyze source code for vulnerabilities.

    Performs static analysis on C/C++ source code to detect:
    - Dangerous function usage (gets, strcpy, sprintf, etc.)
    - Buffer overflow patterns
    - Format string vulnerabilities
    - Command injection risks
    - Memory safety issues

    Optionally integrates Bearer CLI for comprehensive SAST.

    Examples:
        supwngo source ./vuln.c
        supwngo source ./src/ -t bearer
        supwngo source ./challenge.c -o report.json --json
    """
    from supwngo.analysis.source import SourceAnalyzer, Severity

    console.print(f"\n[bold]Source Code Analysis:[/bold] {source}\n")

    # Determine which tools to use
    tool_list = list(tools)
    if "all" in tool_list:
        tool_list = ["builtin", "bearer", "patterns"]

    analyzer = SourceAnalyzer(source)

    with console.status("Analyzing source code..."):
        report = analyzer.analyze(tool_list)

    if json_output:
        import json as json_module
        result = json_module.dumps(report.to_dict(), indent=2)
        if output:
            with open(output, "w") as f:
                f.write(result)
            console.print(f"[green]Report saved to: {output}[/green]")
        else:
            console.print_json(result)
    else:
        # Summary
        summary = f"""
Files Analyzed: {report.files_analyzed}
Total Vulnerabilities: {report.total_vulns}
Critical: [red]{report.critical_count}[/red]
High: [yellow]{report.high_count}[/yellow]
Tools Used: {', '.join(report.tools_used)}
"""
        console.print(Panel(summary, title="Analysis Summary"))

        # Vulnerabilities by severity
        if report.vulnerabilities:
            for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM]:
                vulns = report.get_by_severity(severity)
                if vulns:
                    style = {
                        Severity.CRITICAL: "red",
                        Severity.HIGH: "yellow",
                        Severity.MEDIUM: "cyan",
                    }.get(severity, "white")

                    table = Table(title=f"[{style}]{severity.value.upper()} Vulnerabilities[/{style}]")
                    table.add_column("File", style="cyan")
                    table.add_column("Line", style="green")
                    table.add_column("Type", style=style)
                    table.add_column("Description")

                    for vuln in vulns[:10]:  # Show top 10 per severity
                        table.add_row(
                            Path(vuln.file_path).name,
                            str(vuln.line_number),
                            vuln.vuln_type.value,
                            vuln.description[:50]
                        )

                    console.print(table)

        # Dangerous functions summary
        if report.dangerous_functions:
            console.print("\n[bold]Dangerous Function Usage:[/bold]")
            func_counts = {}
            for df in report.dangerous_functions:
                func_counts[df["function"]] = func_counts.get(df["function"], 0) + 1

            for func, count in sorted(func_counts.items(), key=lambda x: -x[1])[:10]:
                console.print(f"  {func}: {count} occurrence(s)")

        # Warnings
        if report.warnings:
            console.print("\n[yellow]Warnings:[/yellow]")
            for warning in report.warnings:
                console.print(f"  [yellow]! {warning}[/yellow]")

        # Errors
        if report.errors:
            console.print("\n[red]Errors:[/red]")
            for error in report.errors[:5]:
                console.print(f"  [red]✗ {error}[/red]")

        # Save if output specified
        if output:
            import json as json_module
            with open(output, "w") as f:
                json_module.dump(report.to_dict(), f, indent=2)
            console.print(f"\n[green]Report saved to: {output}[/green]")


@cli.command()
@click.argument("module", type=click.Path(exists=True))
@click.option("-k", "--kallsyms", type=click.Path(exists=True), help="kallsyms file for symbol resolution")
@click.option("-v", "--vmlinux", type=click.Path(exists=True), help="vmlinux for gadget finding")
@click.option("--leak-func", help="Function name for KASLR leak (e.g., timerfd_tmrproc)")
@click.option("--leak-offset", type=str, help="Offset of leak function from kernel base (hex)")
@click.option("-o", "--output", type=click.Path(), help="Output exploit C code")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
@click.pass_context
def kernel(ctx, module, kallsyms, vmlinux, leak_func, leak_offset, output, json_output):
    """
    Analyze kernel module (.ko) for vulnerabilities.

    Designed for kernel exploitation challenges like:
    - Heap OOB read/write
    - UAF via slab manipulation
    - Race conditions

    Generates exploit templates using:
    - timerfd/msg_msg/pipe_buffer spray
    - Kernel ROP chains
    - KASLR bypass techniques

    Examples:
        supwngo kernel ./vuln.ko
        supwngo kernel ./ttp.ko --leak-func timerfd_tmrproc --leak-offset 0x3370e0
        supwngo kernel ./vuln.ko -o exploit.c
    """
    from supwngo.kernel.module import KernelModule
    from supwngo.kernel.symbols import KernelSymbols
    from supwngo.kernel.slab import SlabAllocator
    from supwngo.kernel.templates import KernelExploitTemplate

    console.print(f"\n[bold cyan]{'=' * 60}[/bold cyan]")
    console.print(f"[bold cyan]  Kernel Module Analysis: {Path(module).name}[/bold cyan]")
    console.print(f"[bold cyan]{'=' * 60}[/bold cyan]\n")

    # Load and analyze module
    with console.status("Analyzing kernel module..."):
        km = KernelModule.load(module)

    # Print analysis results
    console.print(Panel(km.summary(), title="Module Analysis"))

    # Show slab targets
    if km.kmalloc_calls:
        for call in km.kmalloc_calls:
            if call.size > 0:
                targets = SlabAllocator.get_useful_structs(call.slab_name)
                spray = SlabAllocator.get_spray_methods(call.slab_name)

                console.print(f"\n[bold cyan]{call.slab_name}[/bold cyan]")
                console.print(f"  Target structures: {', '.join(targets) or 'None'}")
                console.print(f"  Spray methods: {', '.join(spray) or 'None'}")

    # If we have leak info, calculate kernel base
    symbols = None
    if leak_func and leak_offset:
        offset = int(leak_offset, 16) if leak_offset.startswith("0x") else int(leak_offset)
        # This would be used with an actual leak
        console.print(f"\n[cyan]KASLR leak configured:[/cyan]")
        console.print(f"  Function: {leak_func}")
        console.print(f"  Offset: 0x{offset:x}")

    # Load symbols if provided
    if kallsyms:
        with console.status("Loading kernel symbols..."):
            symbols = KernelSymbols.from_kallsyms(kallsyms)
            console.print(symbols.summary())

    # Generate exploit template
    if output:
        template = KernelExploitTemplate(module=km, symbols=symbols)

        # Check if this looks like tictacpwn
        is_ttp = "ttp" in module.lower() or any(
            cmd.code in [0x40087401, 0x40087402, 0x40087403, 0x40087404]
            for cmd in km.ioctl_handlers
        )

        if is_ttp:
            console.print("\n[yellow]Detected tictacpwn-like challenge![/yellow]")
            exploit_code = template.generate_tictacpwn_exploit()
        else:
            exploit_code = template.generate_full_exploit(
                target_name=km.name,
                vuln_type="heap_oob" if km.vulnerabilities else "unknown",
            )

        with open(output, "w") as f:
            f.write(exploit_code)

        console.print(f"\n[green]Exploit template saved to: {output}[/green]")

    if json_output:
        result = {
            "module": km.name,
            "ioctl_commands": [
                {"code": hex(cmd.code), "type": cmd.type_char, "nr": cmd.nr, "size": cmd.size}
                for cmd in km.ioctl_handlers
            ],
            "kmalloc_calls": [
                {"size": call.size, "slab": call.slab_name}
                for call in km.kmalloc_calls if call.size > 0
            ],
            "vulnerabilities": [
                {"type": v.type, "description": v.description}
                for v in km.vulnerabilities
            ],
        }
        console.print_json(json.dumps(result, indent=2))


@cli.command()
@click.pass_context
def version(ctx):
    """Show version information."""
    print_banner()
    console.print(f"\nVersion: {__version__}")
    console.print("Python: " + sys.version.split()[0])

    # Check dependencies
    console.print("\n[bold]Dependencies:[/bold]")
    deps = [
        ("pwntools", "pwn"),
        ("angr", "angr"),
        ("ropper", "ropper"),
        ("capstone", "capstone"),
        ("keystone", "keystone"),
        ("lief", "lief"),
    ]

    for name, module in deps:
        try:
            __import__(module)
            console.print(f"  [green]✓[/green] {name}")
        except ImportError:
            console.print(f"  [red]✗[/red] {name}")


# ============================================================================
# Phase 1: New Analysis Commands
# ============================================================================

@cli.command()
@click.argument("binary", type=click.Path(exists=True))
@click.option("-f", "--function", help="Specific function to analyze")
@click.option("--loops", is_flag=True, help="Find and analyze loops")
@click.option("--complexity", is_flag=True, help="Show complexity metrics")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
@click.pass_context
def cfg(ctx, binary, function, loops, complexity, json_output):
    """
    Build and analyze Control Flow Graph.

    Identifies basic blocks, loops, function relationships,
    and potentially dangerous patterns in the control flow.
    """
    from supwngo.core.binary import Binary
    from supwngo.analysis.cfg import CFGAnalyzer

    console.print(f"\n[bold]CFG Analysis:[/bold] {binary}\n")

    bin_obj = Binary.load(binary)
    analyzer = CFGAnalyzer(bin_obj)

    with console.status("Building control flow graph..."):
        blocks = analyzer.build_cfg()

    console.print(f"[cyan]Built CFG: {len(blocks)} basic blocks, {len(analyzer.functions)} functions[/cyan]")

    if loops:
        with console.status("Finding loops..."):
            found_loops = analyzer.find_loops()

        if found_loops:
            console.print(f"\n[bold]Loops Found: {len(found_loops)}[/bold]")
            table = Table()
            table.add_column("Header", style="cyan")
            table.add_column("Blocks", style="green")
            table.add_column("Nesting", style="yellow")

            for loop in found_loops[:20]:
                table.add_row(
                    hex(loop.header),
                    str(len(loop.blocks)),
                    str(loop.nesting_level),
                )

            console.print(table)

    if complexity:
        console.print("\n[bold]Function Complexity:[/bold]")
        table = Table()
        table.add_column("Function", style="cyan")
        table.add_column("Blocks", style="green")
        table.add_column("Complexity", style="yellow")
        table.add_column("Recursive", style="red")

        for name, func in sorted(analyzer.functions.items(),
                                  key=lambda x: x[1].cyclomatic_complexity,
                                  reverse=True)[:20]:
            metrics = analyzer.get_function_complexity(name)
            table.add_row(
                name[:30],
                str(metrics.get("blocks", 0)),
                str(metrics.get("cyclomatic_complexity", 0)),
                "Yes" if metrics.get("is_recursive") else "No",
            )

        console.print(table)

    if function:
        metrics = analyzer.get_function_complexity(function)
        if metrics:
            console.print(f"\n[bold]Function: {function}[/bold]")
            for key, val in metrics.items():
                console.print(f"  {key}: {val}")

    # Find dangerous patterns
    patterns = analyzer.find_dangerous_patterns()
    if patterns:
        console.print("\n[bold red]Dangerous Patterns:[/bold red]")
        for p in patterns[:10]:
            console.print(f"  [{p['type']}] {p.get('function', p.get('address', ''))} - {p['risk']}")

    if json_output:
        result = {
            "blocks": len(blocks),
            "functions": len(analyzer.functions),
            "loops": len(analyzer.loops) if loops else 0,
            "patterns": patterns[:20],
        }
        console.print_json(json.dumps(result, indent=2))


@cli.command()
@click.argument("binary", type=click.Path(exists=True))
@click.option("-f", "--function", help="Function to analyze (address in hex or name)")
@click.option("--taint", is_flag=True, help="Perform taint analysis")
@click.option("--integer", is_flag=True, help="Find integer vulnerabilities")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
@click.pass_context
def dataflow(ctx, binary, function, taint, integer, json_output):
    """
    Perform data flow analysis on binary.

    Tracks how user input flows through the program to identify:
    - Tainted data reaching dangerous functions
    - Integer overflow opportunities
    - Potential information leaks
    """
    from supwngo.core.binary import Binary
    from supwngo.analysis.dataflow import DataFlowAnalyzer

    console.print(f"\n[bold]Data Flow Analysis:[/bold] {binary}\n")

    bin_obj = Binary.load(binary)
    analyzer = DataFlowAnalyzer(bin_obj)

    # Determine function address
    func_addr = None
    if function:
        if function.startswith("0x"):
            func_addr = int(function, 16)
        else:
            # Look up symbol
            for name, sym in bin_obj.symbols.items():
                if name == function:
                    func_addr = sym.address
                    break
            if not func_addr:
                # Try main
                func_addr = bin_obj.symbols.get("main", {})
                if hasattr(func_addr, 'address'):
                    func_addr = func_addr.address
                else:
                    func_addr = None

    if not func_addr:
        # Use entry point or main
        func_addr = bin_obj.symbols.get("main")
        if func_addr and hasattr(func_addr, 'address'):
            func_addr = func_addr.address
        else:
            func_addr = bin_obj.elf.entry

    console.print(f"[cyan]Analyzing function at 0x{func_addr:x}[/cyan]")

    with console.status("Analyzing data flow..."):
        results = analyzer.analyze_function(func_addr)

    if results.get("tainted_paths"):
        console.print("\n[bold yellow]Taint Sources:[/bold yellow]")
        for path in results["tainted_paths"]:
            console.print(f"  {path['source']} ({path['type']}) at {path['address']}")

    if results.get("dangerous_sinks"):
        console.print("\n[bold red]Dangerous Sinks (tainted data reaches):[/bold red]")
        for sink in results["dangerous_sinks"]:
            console.print(f"  {sink['sink']} at {sink['address']}")
            if sink.get("taint_source"):
                console.print(f"    Tainted from: {sink['taint_source']}")

    if integer:
        with console.status("Analyzing integer operations..."):
            int_ops = analyzer.analyze_integer_operations(func_addr)

        if int_ops:
            console.print("\n[bold yellow]Potentially Dangerous Integer Operations:[/bold yellow]")
            for op in int_ops[:20]:
                console.print(f"  [{op['type']}] {op['address']}: {op['instruction']}")
                console.print(f"      Risk: {op['risk']}")

    if json_output:
        console.print_json(json.dumps(results, indent=2, default=str))


@cli.command()
@click.argument("binary", type=click.Path(exists=True))
@click.option("--format-strings", is_flag=True, help="Focus on format strings")
@click.option("--crypto", is_flag=True, help="Find crypto constants")
@click.option("--encoded", is_flag=True, help="Find encoded data")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
@click.pass_context
def strings_analysis(ctx, binary, format_strings, crypto, encoded, json_output):
    """
    Advanced string analysis for exploitation.

    Finds exploitable strings including:
    - Format string specifiers (%n, %s, etc.)
    - Shell commands and paths
    - Encoded/encrypted data
    - Cryptographic constants
    """
    from supwngo.core.binary import Binary
    from supwngo.analysis.strings import StringAnalyzer, StringCategory

    console.print(f"\n[bold]String Analysis:[/bold] {binary}\n")

    bin_obj = Binary.load(binary)
    analyzer = StringAnalyzer(bin_obj)

    with console.status("Analyzing strings..."):
        strings = analyzer.analyze()

    console.print(f"[cyan]Analyzed {len(strings)} interesting strings[/cyan]")

    # Summary
    categories = {}
    for s in strings:
        cat = s.category.name
        categories[cat] = categories.get(cat, 0) + 1

    console.print("\n[bold]Categories:[/bold]")
    for cat, count in sorted(categories.items(), key=lambda x: -x[1]):
        console.print(f"  {cat}: {count}")

    if format_strings:
        vulns = analyzer.find_format_string_vulns()
        if vulns:
            console.print("\n[bold red]Format String Vulnerabilities:[/bold red]")
            for v in vulns:
                console.print(f"  [{v['severity']}] {v['address']}: {v['string'][:40]}")
                console.print(f"      {v['details']}")

    if crypto:
        with console.status("Searching for crypto constants..."):
            crypto_findings = analyzer.find_crypto_constants()

        if crypto_findings:
            console.print("\n[bold cyan]Cryptographic Constants:[/bold cyan]")
            for f in crypto_findings[:20]:
                console.print(f"  {f['name']}: {f['constant']} at {f['address']}")

    if encoded:
        enc_strings = [s for s in strings if s.category == StringCategory.ENCODED_DATA]
        if enc_strings:
            console.print("\n[bold yellow]Encoded Data:[/bold yellow]")
            for s in enc_strings[:10]:
                console.print(f"  {hex(s.address)}: {s.value[:50]}")
                if s.details.get("encoding"):
                    console.print(f"      Encoding: {s.details['encoding']}")
                    if s.details.get("decoded_preview"):
                        console.print(f"      Decoded: {s.details['decoded_preview'][:30]}")

    # Exploitable strings
    exploitable = [s for s in strings if s.exploitable]
    if exploitable:
        console.print(f"\n[bold red]Exploitable Strings ({len(exploitable)}):[/bold red]")
        for s in exploitable[:10]:
            console.print(f"  [{s.exploit_type}] {hex(s.address)}: {s.value[:40]}")

    if json_output:
        result = {
            "total": len(strings),
            "categories": categories,
            "exploitable": [
                {"address": hex(s.address), "value": s.value, "type": s.exploit_type}
                for s in exploitable
            ],
        }
        console.print_json(json.dumps(result, indent=2))


@cli.command()
@click.argument("binary1", type=click.Path(exists=True))
@click.argument("binary2", type=click.Path(exists=True))
@click.option("--security-only", is_flag=True, help="Show only security-relevant changes")
@click.option("-o", "--output", type=click.Path(), help="Save diff to file")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
@click.pass_context
def diff(ctx, binary1, binary2, security_only, output, json_output):
    """
    Diff two binaries to find patches and changes.

    Useful for:
    - Finding security patches in updated binaries
    - Recovering symbols from debug builds
    - Understanding what changed between versions
    """
    from supwngo.core.binary import Binary
    from supwngo.analysis.diff import BinaryDiffer

    console.print(f"\n[bold]Binary Diff:[/bold]")
    console.print(f"  Old: {binary1}")
    console.print(f"  New: {binary2}\n")

    bin1 = Binary.load(binary1)
    bin2 = Binary.load(binary2)

    differ = BinaryDiffer(bin1, bin2)

    with console.status("Diffing binaries..."):
        results = differ.diff()

    console.print(f"[cyan]Functions in binary1: {results['functions1']}[/cyan]")
    console.print(f"[cyan]Functions in binary2: {results['functions2']}[/cyan]")
    console.print(f"[cyan]Matched: {results['matched']}[/cyan]")

    if security_only:
        patches = differ.get_security_patches()
    else:
        patches = differ.patches

    if patches:
        console.print(f"\n[bold]Changes ({len(patches)}):[/bold]")
        table = Table()
        table.add_column("Function", style="cyan")
        table.add_column("Type", style="yellow")
        table.add_column("Size Change")
        table.add_column("Security", style="red")
        table.add_column("Description")

        for p in patches[:30]:
            sec = "[red]Yes[/red]" if p.security_relevant else "No"
            table.add_row(
                p.function[:25],
                p.patch_type,
                str(p.size_change),
                sec,
                p.description[:40],
            )

        console.print(table)

    # Symbol recovery
    recovered = differ.recover_symbols()
    if recovered:
        console.print(f"\n[bold green]Recoverable Symbols: {len(recovered)}[/bold green]")
        for addr, name in list(recovered.items())[:10]:
            console.print(f"  0x{addr:x} -> {name}")

    if output:
        with open(output, "w") as f:
            json.dump(results, f, indent=2, default=str)
        console.print(f"\n[green]Diff saved to {output}[/green]")

    if json_output:
        console.print_json(json.dumps(results, indent=2, default=str))


@cli.command()
@click.argument("binary", type=click.Path(exists=True))
@click.option("-f", "--function", help="Function to decompile")
@click.option("--ghidra/--angr", default=True, help="Decompiler to use")
@click.option("-o", "--output", type=click.Path(), help="Save decompiled code")
@click.pass_context
def decompile(ctx, binary, function, ghidra, output):
    """
    Decompile binary to pseudo-C code.

    Integrates with Ghidra (if available) or falls back to angr.
    Extracts variables, function calls, and control flow.
    """
    from supwngo.core.binary import Binary
    from supwngo.analysis.decompile import Decompiler

    console.print(f"\n[bold]Decompilation:[/bold] {binary}\n")

    bin_obj = Binary.load(binary)
    decomp = Decompiler(bin_obj)

    # Show available decompilers
    available = decomp.get_available_decompilers()
    console.print(f"[cyan]Available decompilers: {', '.join(available) or 'None'}[/cyan]")

    # Determine function to decompile
    func_addr = None
    func_name = function

    if function:
        if function.startswith("0x"):
            func_addr = int(function, 16)
            func_name = None
        else:
            for name, sym in bin_obj.symbols.items():
                if name == function:
                    func_addr = sym.address
                    break

    if not func_addr and not func_name:
        func_name = "main"

    console.print(f"[cyan]Decompiling: {func_name or hex(func_addr)}[/cyan]")

    with console.status("Decompiling..."):
        result = decomp.decompile(func_name=func_name, func_addr=func_addr, use_ghidra=ghidra)

    if result:
        console.print(f"\n[bold green]Decompiled: {result.name}[/bold green]")
        console.print(f"Address: 0x{result.address:x}")
        console.print(f"Return type: {result.return_type}")

        if result.parameters:
            console.print(f"Parameters: {len(result.parameters)}")
            for p in result.parameters:
                console.print(f"  {p.type_str} {p.name}")

        if result.calls:
            console.print(f"Calls: {', '.join(result.calls[:10])}")

        console.print("\n[bold]Decompiled Code:[/bold]")
        console.print(Panel(result.code[:3000], title=result.name, border_style="cyan"))

        if output:
            with open(output, "w") as f:
                f.write(f"// Decompiled: {result.name}\n")
                f.write(f"// Address: 0x{result.address:x}\n\n")
                f.write(result.code)
            console.print(f"\n[green]Saved to {output}[/green]")

        # Check for vulnerabilities
        decomp.decompiled_functions[result.name] = result
        vulns = decomp.find_vulnerabilities_in_decompiled()
        if vulns:
            console.print("\n[bold red]Potential Vulnerabilities in Decompiled Code:[/bold red]")
            for v in vulns:
                console.print(f"  [{v['severity']}] {v['description']}")
    else:
        console.print("[red]Decompilation failed[/red]")


@cli.command()
@click.argument("binary", type=click.Path(exists=True))
@click.option("--dangerous", is_flag=True, help="Show only dangerous imports")
@click.option("--hooks", is_flag=True, help="Find hookable targets")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
@click.pass_context
def imports(ctx, binary, dangerous, hooks, json_output):
    """
    Analyze binary imports and dependencies.

    Shows:
    - Imported functions and libraries
    - Weak symbols that can be overridden
    - Lazy binding opportunities for GOT overwrite
    - Glibc version requirements
    """
    from supwngo.core.binary import Binary
    from supwngo.analysis.imports import ImportAnalyzer

    console.print(f"\n[bold]Import Analysis:[/bold] {binary}\n")

    bin_obj = Binary.load(binary)
    analyzer = ImportAnalyzer(bin_obj)

    with console.status("Analyzing imports..."):
        results = analyzer.analyze()

    console.print(f"[cyan]Imports: {len(results['imports'])}[/cyan]")
    console.print(f"[cyan]Exports: {len(results['exports'])}[/cyan]")
    console.print(f"[cyan]Dependencies: {len(results['dependencies'])}[/cyan]")

    if results.get('glibc_version'):
        console.print(f"[cyan]Min glibc: {results['glibc_version']}[/cyan]")

    # Dependencies
    if results['dependencies']:
        console.print("\n[bold]Dependencies:[/bold]")
        for name, dep in results['dependencies'].items():
            versions = ", ".join(dep.get('versions', [])[:3]) if dep.get('versions') else "any"
            console.print(f"  {name} ({versions})")

    # Dangerous imports
    if dangerous or results.get('dangerous_imports'):
        di = results.get('dangerous_imports', {})
        if di:
            console.print("\n[bold red]Dangerous Imports:[/bold red]")
            for category, funcs in di.items():
                console.print(f"  {category}: {', '.join(funcs)}")

    # Weak symbols
    if results.get('weak_symbols'):
        console.print(f"\n[bold yellow]Weak Symbols (overridable):[/bold yellow]")
        for sym in results['weak_symbols'][:10]:
            console.print(f"  {sym}")

    # Lazy bindings
    if results.get('lazy_bindings'):
        console.print(f"\n[bold cyan]Lazy Bound Functions ({len(results['lazy_bindings'])}):[/bold cyan]")
        console.print(f"  (GOT entries can be overwritten)")

    if hooks:
        targets = analyzer.find_hook_targets()
        if targets:
            console.print("\n[bold green]Hookable Targets:[/bold green]")
            for t in targets:
                console.print(f"  [{t['type']}] {t['name']}")
                if t.get('note'):
                    console.print(f"      {t['note']}")

    # Exploitation info summary
    exploit_info = analyzer.get_exploitation_info()
    console.print("\n[bold]Exploitation Summary:[/bold]")
    console.print(f"  RELRO: {exploit_info['relro_status']}")
    console.print(f"  Has system(): {'Yes' if exploit_info['has_system'] else 'No'}")
    console.print(f"  Has execve(): {'Yes' if exploit_info['has_execve'] else 'No'}")
    console.print(f"  Has mprotect(): {'Yes' if exploit_info['has_mprotect'] else 'No'}")
    console.print(f"  Hookable targets: {len(exploit_info['hookable_targets'])}")

    if json_output:
        console.print_json(json.dumps(results, indent=2, default=str))


# ============================================================================
# Phase 2: Detection Accuracy Improvements
# ============================================================================

@cli.command()
@click.argument("binary", type=click.Path(exists=True))
@click.option("--fingerprint", is_flag=True, help="Attempt libc fingerprinting from leaks")
@click.option("--chain", is_flag=True, help="Build leak chain for multi-step disclosure")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
@click.pass_context
def leaks(ctx, binary, fingerprint, chain, json_output):
    """
    Find information leak vulnerabilities.

    Detects:
    - Format string leaks (%p chains)
    - GOT/PLT leak primitives
    - Stack address disclosure
    - Heap address disclosure
    - Libc pointer leaks
    """
    from supwngo.core.binary import Binary
    from supwngo.vulns.leak_finder import LeakFinder

    console.print(f"\n[bold]Leak Detection:[/bold] {binary}\n")

    bin_obj = Binary.load(binary)
    finder = LeakFinder(bin_obj)

    with console.status("Searching for leak primitives..."):
        leaks_found = finder.analyze()

    console.print(f"[cyan]Found {len(leaks_found)} potential leak primitives[/cyan]")

    if leaks_found:
        # Group by type
        by_type = {}
        for leak in leaks_found:
            t = leak.leak_type.name
            if t not in by_type:
                by_type[t] = []
            by_type[t].append(leak)

        console.print("\n[bold]Leak Types:[/bold]")
        for leak_type, items in sorted(by_type.items(), key=lambda x: -len(x[1])):
            console.print(f"  {leak_type}: {len(items)}")

        # Show top leaks
        table = Table(title="Top Leak Primitives")
        table.add_column("Type", style="cyan")
        table.add_column("Address", style="green")
        table.add_column("Function", style="yellow")
        table.add_column("Description")
        table.add_column("Confidence")

        for leak in sorted(leaks_found, key=lambda x: -x.confidence)[:15]:
            table.add_row(
                leak.leak_type.name,
                hex(leak.address),
                leak.function,
                leak.description[:40],
                f"{leak.confidence:.1%}",
            )

        console.print(table)

        # Format string specific info
        fs_leaks = [l for l in leaks_found if "FORMAT" in l.leak_type.name]
        if fs_leaks:
            console.print("\n[bold yellow]Format String Leak Details:[/bold yellow]")
            for leak in fs_leaks[:5]:
                console.print(f"  [{hex(leak.address)}] {leak.description}")
                if leak.exploit_template:
                    console.print(f"    Template available: Yes")

    if fingerprint:
        console.print("\n[bold]Libc Fingerprinting Info:[/bold]")
        fp_info = finder.get_fingerprint_strategy()
        if fp_info:
            console.print(f"  Best leak targets: {', '.join(fp_info.get('targets', []))}")
            console.print(f"  Recommended chain length: {fp_info.get('chain_length', 0)}")
        else:
            console.print("  [yellow]No viable fingerprinting strategy found[/yellow]")

    if chain:
        leak_chain = finder.build_leak_chain()
        if leak_chain:
            console.print("\n[bold green]Leak Chain Strategy:[/bold green]")
            for i, step in enumerate(leak_chain, 1):
                console.print(f"  {i}. {step['action']}")
                console.print(f"     Target: {step['target']}")
                console.print(f"     Discloses: {step['discloses']}")
        else:
            console.print("\n[yellow]Could not build multi-step leak chain[/yellow]")

    # Summary
    console.print("\n" + finder.summary())

    if json_output:
        result = {
            "total": len(leaks_found),
            "by_type": {k: len(v) for k, v in by_type.items()} if leaks_found else {},
            "leaks": [
                {
                    "type": l.leak_type.name,
                    "address": hex(l.address),
                    "function": l.function,
                    "confidence": l.confidence,
                }
                for l in leaks_found[:30]
            ],
        }
        console.print_json(json.dumps(result, indent=2))


@cli.command()
@click.argument("binary", type=click.Path(exists=True))
@click.option("--tcache", is_flag=True, help="Focus on tcache analysis")
@click.option("--uaf", is_flag=True, help="Focus on UAF detection")
@click.option("--templates", is_flag=True, help="Generate exploit templates")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
@click.pass_context
def heap_analysis(ctx, binary, tcache, uaf, templates, json_output):
    """
    Advanced heap vulnerability analysis.

    Detects:
    - Use-After-Free (UAF)
    - Double-free vulnerabilities
    - Heap overflow / OOB write
    - Tcache poisoning opportunities
    - Fastbin dup conditions
    """
    from supwngo.core.binary import Binary
    from supwngo.vulns.heap_advanced import AdvancedHeapAnalyzer, HeapVulnType

    console.print(f"\n[bold]Advanced Heap Analysis:[/bold] {binary}\n")

    bin_obj = Binary.load(binary)
    analyzer = AdvancedHeapAnalyzer(bin_obj)

    with console.status("Analyzing heap operations..."):
        vulns = analyzer.analyze()

    console.print(f"[cyan]Allocation sites: {len(analyzer.alloc_sites)}[/cyan]")
    console.print(f"[cyan]Free sites: {len(analyzer.free_sites)}[/cyan]")
    console.print(f"[cyan]Vulnerabilities: {len(vulns)}[/cyan]")

    if vulns:
        # Group by type
        by_type = {}
        for v in vulns:
            t = v.vuln_type.name
            if t not in by_type:
                by_type[t] = []
            by_type[t].append(v)

        console.print("\n[bold]Vulnerability Types:[/bold]")
        for vtype, items in sorted(by_type.items(), key=lambda x: -len(x[1])):
            console.print(f"  {vtype}: {len(items)}")

        # Show critical vulns
        critical = [v for v in vulns if v.severity in ("CRITICAL", "HIGH")]
        if critical:
            console.print("\n[bold red]Critical/High Severity:[/bold red]")
            table = Table()
            table.add_column("Type", style="red")
            table.add_column("Address", style="green")
            table.add_column("Function", style="cyan")
            table.add_column("Description")

            for v in critical[:10]:
                table.add_row(
                    v.vuln_type.name,
                    hex(v.address),
                    v.function,
                    v.description[:50],
                )

            console.print(table)

        if tcache:
            tcache_vulns = [v for v in vulns if v.vuln_type == HeapVulnType.TCACHE_POISONING]
            if tcache_vulns:
                console.print("\n[bold yellow]Tcache Analysis:[/bold yellow]")
                for v in tcache_vulns[:5]:
                    console.print(f"  [{hex(v.address)}] {v.description}")
                    if v.chunk_sizes:
                        console.print(f"    Chunk sizes: {v.chunk_sizes}")

        if uaf:
            uaf_vulns = [v for v in vulns if v.vuln_type == HeapVulnType.USE_AFTER_FREE]
            if uaf_vulns:
                console.print("\n[bold red]Use-After-Free Analysis:[/bold red]")
                for v in uaf_vulns[:5]:
                    console.print(f"  [{hex(v.address)}] {v.description}")
                    if v.alloc_site:
                        console.print(f"    Allocated at: {hex(v.alloc_site.address)}")
                    if v.free_site:
                        console.print(f"    Freed at: {hex(v.free_site.address)}")

        if templates:
            console.print("\n[bold green]Exploit Templates:[/bold green]")
            for v in vulns[:3]:
                if v.exploit_template:
                    console.print(f"\n[{v.vuln_type.name}] Template:")
                    console.print(Panel(v.exploit_template[:800], border_style="green"))

    # Summary
    console.print("\n" + analyzer.summary())

    if json_output:
        result = {
            "alloc_sites": len(analyzer.alloc_sites),
            "free_sites": len(analyzer.free_sites),
            "vulnerabilities": len(vulns),
            "by_type": {k: len(v) for k, v in by_type.items()} if vulns else {},
            "vulns": [
                {
                    "type": v.vuln_type.name,
                    "severity": v.severity,
                    "address": hex(v.address),
                    "function": v.function,
                }
                for v in vulns[:20]
            ],
        }
        console.print_json(json.dumps(result, indent=2))


@cli.command()
@click.argument("binary", type=click.Path(exists=True))
@click.option("--allocation", is_flag=True, help="Focus on allocation size issues")
@click.option("--chains", is_flag=True, help="Show arithmetic chains")
@click.option("--templates", is_flag=True, help="Generate exploit templates")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
@click.pass_context
def integer_analysis(ctx, binary, allocation, chains, templates, json_output):
    """
    Advanced integer vulnerability analysis.

    Detects:
    - Integer overflow in calculations
    - Truncation issues (64-bit to 32-bit)
    - Signedness confusion
    - Size calculation before malloc
    - Arithmetic operation chains
    """
    from supwngo.core.binary import Binary
    from supwngo.vulns.integer_advanced import AdvancedIntegerAnalyzer, IntVulnType, IntContext

    console.print(f"\n[bold]Advanced Integer Analysis:[/bold] {binary}\n")

    bin_obj = Binary.load(binary)
    analyzer = AdvancedIntegerAnalyzer(bin_obj)

    with console.status("Analyzing integer operations..."):
        vulns = analyzer.analyze()

    console.print(f"[cyan]Arithmetic operations: {len(analyzer.operations)}[/cyan]")
    console.print(f"[cyan]Arithmetic chains: {len(analyzer.chains)}[/cyan]")
    console.print(f"[cyan]Vulnerabilities: {len(vulns)}[/cyan]")

    if vulns:
        # Group by type
        by_type = {}
        for v in vulns:
            t = v.vuln_type.name
            if t not in by_type:
                by_type[t] = []
            by_type[t].append(v)

        console.print("\n[bold]Vulnerability Types:[/bold]")
        for vtype, items in sorted(by_type.items(), key=lambda x: -len(x[1])):
            console.print(f"  {vtype}: {len(items)}")

        # Show high-confidence vulns
        high_conf = sorted(vulns, key=lambda x: -x.confidence)[:10]
        if high_conf:
            console.print("\n[bold yellow]High Confidence Issues:[/bold yellow]")
            table = Table()
            table.add_column("Type", style="yellow")
            table.add_column("Address", style="green")
            table.add_column("Context", style="cyan")
            table.add_column("Confidence")
            table.add_column("Description")

            for v in high_conf:
                table.add_row(
                    v.vuln_type.name,
                    hex(v.address),
                    v.context.name,
                    f"{v.confidence:.0%}",
                    v.description[:40],
                )

            console.print(table)

        if allocation:
            alloc_vulns = [v for v in vulns if v.context == IntContext.ALLOCATION_SIZE]
            if alloc_vulns:
                console.print("\n[bold red]Allocation Size Issues:[/bold red]")
                for v in alloc_vulns[:5]:
                    console.print(f"  [{hex(v.address)}] {v.description}")
                    console.print(f"    Leads to memory corruption: {v.leads_to_memory_corruption}")

        if chains:
            console.print("\n[bold cyan]Arithmetic Chains:[/bold cyan]")
            for chain in analyzer.chains[:5]:
                console.print(f"  Source: {chain.source}")
                console.print(f"  Operations: {len(chain.operations)}")
                console.print(f"  Can overflow: {chain.can_overflow}")
                console.print(f"  Can underflow: {chain.can_underflow}")
                console.print()

        if templates:
            console.print("\n[bold green]Exploit Templates:[/bold green]")
            for v in vulns[:2]:
                if v.exploit_template:
                    console.print(f"\n[{v.vuln_type.name}] Template:")
                    console.print(Panel(v.exploit_template[:800], border_style="green"))

    # Critical vulns that lead to memory corruption
    critical = analyzer.get_critical_vulns()
    if critical:
        console.print(f"\n[bold red]Critical (leads to memory corruption): {len(critical)}[/bold red]")

    # Summary
    console.print("\n" + analyzer.summary())

    if json_output:
        result = {
            "operations": len(analyzer.operations),
            "chains": len(analyzer.chains),
            "vulnerabilities": len(vulns),
            "by_type": {k: len(v) for k, v in by_type.items()} if vulns else {},
            "critical": len(critical) if critical else 0,
        }
        console.print_json(json.dumps(result, indent=2))


@cli.command()
@click.argument("binary", type=click.Path(exists=True))
@click.option("--toctou", is_flag=True, help="Focus on TOCTOU vulnerabilities")
@click.option("--signals", is_flag=True, help="Analyze signal handlers")
@click.option("--thread-unsafe", is_flag=True, help="Find thread-unsafe calls")
@click.option("--templates", is_flag=True, help="Generate exploit templates")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
@click.pass_context
def race_analysis(ctx, binary, toctou, signals, thread_unsafe, templates, json_output):
    """
    Advanced race condition analysis.

    Detects:
    - TOCTOU file operation races
    - Signal handler re-entrancy issues
    - Thread-unsafe function usage
    - Double-fetch vulnerabilities
    - Missing atomic operations
    """
    from supwngo.core.binary import Binary
    from supwngo.vulns.race_advanced import AdvancedRaceAnalyzer, AdvancedRaceType

    console.print(f"\n[bold]Advanced Race Condition Analysis:[/bold] {binary}\n")

    bin_obj = Binary.load(binary)
    analyzer = AdvancedRaceAnalyzer(bin_obj)

    with console.status("Analyzing for race conditions..."):
        vulns = analyzer.analyze()

    console.print(f"[cyan]Signal handlers: {len(analyzer.signal_handlers)}[/cyan]")
    console.print(f"[cyan]Thread-unsafe calls: {len(analyzer.thread_unsafe_calls)}[/cyan]")
    console.print(f"[cyan]Race vulnerabilities: {len(vulns)}[/cyan]")

    if vulns:
        # Group by type
        by_type = {}
        for v in vulns:
            t = v.race_type.name
            if t not in by_type:
                by_type[t] = []
            by_type[t].append(v)

        console.print("\n[bold]Race Condition Types:[/bold]")
        for rtype, items in sorted(by_type.items(), key=lambda x: -len(x[1])):
            console.print(f"  {rtype}: {len(items)}")

        # Show high severity
        high_sev = analyzer.get_high_severity()
        if high_sev:
            console.print("\n[bold red]High Severity Race Conditions:[/bold red]")
            table = Table()
            table.add_column("Type", style="red")
            table.add_column("Address", style="green")
            table.add_column("Function", style="cyan")
            table.add_column("Description")

            for v in high_sev[:10]:
                table.add_row(
                    v.race_type.name,
                    hex(v.address),
                    v.function,
                    v.description[:45],
                )

            console.print(table)

        if toctou:
            toctou_vulns = [v for v in vulns if v.race_type == AdvancedRaceType.FILE_TOCTOU]
            if toctou_vulns:
                console.print("\n[bold yellow]TOCTOU Vulnerabilities:[/bold yellow]")
                for v in toctou_vulns[:5]:
                    console.print(f"  [{hex(v.address)}] {v.description}")
                    if v.window:
                        console.print(f"    Window: {v.window.start_op} -> {v.window.end_op}")
                        console.print(f"    Instructions in window: {v.window.window_size}")

        if signals:
            if analyzer.signal_handlers:
                console.print("\n[bold cyan]Signal Handlers:[/bold cyan]")
                for sh in analyzer.signal_handlers[:5]:
                    console.print(f"  Handler at {hex(sh.handler_addr)}")
                    console.print(f"    Reentrant: {sh.is_reentrant}")
                    if sh.async_unsafe_calls:
                        console.print(f"    Async-unsafe calls: {', '.join(sh.async_unsafe_calls[:5])}")

        if thread_unsafe:
            if analyzer.thread_unsafe_calls:
                console.print("\n[bold yellow]Thread-Unsafe Function Calls:[/bold yellow]")
                table = Table()
                table.add_column("Function", style="red")
                table.add_column("Caller", style="cyan")
                table.add_column("Reason")
                table.add_column("Safe Alternative", style="green")

                for call in analyzer.thread_unsafe_calls[:15]:
                    table.add_row(
                        call.function,
                        call.caller,
                        call.reason[:30],
                        call.safe_alternative or "-",
                    )

                console.print(table)

        if templates:
            console.print("\n[bold green]Exploit Templates:[/bold green]")
            for v in vulns[:2]:
                if v.exploit_template:
                    console.print(f"\n[{v.race_type.name}] Template:")
                    console.print(Panel(v.exploit_template[:800], border_style="green"))

    # Summary
    console.print("\n" + analyzer.summary())

    if json_output:
        result = {
            "signal_handlers": len(analyzer.signal_handlers),
            "thread_unsafe_calls": len(analyzer.thread_unsafe_calls),
            "vulnerabilities": len(vulns),
            "by_type": {k: len(v) for k, v in by_type.items()} if vulns else {},
            "high_severity": len(analyzer.get_high_severity()),
        }
        console.print_json(json.dumps(result, indent=2))


@cli.command()
@click.argument("binary", type=click.Path(exists=True))
@click.option("-o", "--output", type=click.Path(), help="Output exploit script to file")
@click.option("--timeout", default=5.0, help="Timeout for each attempt (seconds)")
@click.option("--libc", type=click.Path(exists=True), help="Path to libc for ret2libc")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
@click.pass_context
def autopwn(ctx, binary, output, timeout, libc, json_output):
    """
    Enhanced auto-exploitation - try multiple techniques automatically.

    Techniques tried (in order):
    1. Variable overwrite (magic value comparison bypass)
    2. ret2win (if win function found)
    3. Direct shellcode (if NX disabled)
    4. Negative size bypass (signed/unsigned comparison)
    5. Stack shellcode (if stack leak available)
    6. Format string exploitation
    7. ret2libc

    Always generates a template even if full exploit fails.
    """
    from supwngo.core.binary import Binary
    from supwngo.exploit.enhanced_auto import EnhancedAutoExploiter

    console.print(f"\n[bold]Enhanced Auto-Exploit:[/bold] {binary}\n")

    with console.status("Loading binary..."):
        bin_obj = Binary.load(binary)

    with console.status("Running auto-exploitation..."):
        exploiter = EnhancedAutoExploiter(
            bin_obj,
            timeout=timeout,
            libc_path=libc,
        )
        exploiter.run()

    if json_output:
        result = {
            "binary": str(binary),
            "success": exploiter.successful,
            "verified": exploiter.verification_level.name if exploiter.verification_level else "NONE",
            "flag": exploiter._captured_flag,
            "technique": exploiter.technique_used,
            "payload_length": len(exploiter.final_payload),
            "attempts": exploiter.attempts,
            "profile": {
                "has_menu": exploiter.profile.has_menu,
                "has_alarm": exploiter.profile.has_alarm,
                "leaked_addresses": {k: hex(v) for k, v in exploiter.profile.leaked_addresses.items()},
            },
        }
        console.print_json(json.dumps(result, indent=2))
    else:
        console.print(exploiter.summary())

        if exploiter.successful:
            console.print(f"\n[bold green]SUCCESS![/bold green] Technique: {exploiter.technique_used}")
            console.print(f"Payload length: {len(exploiter.final_payload)} bytes")

            # Show flag prominently if captured
            if exploiter._captured_flag:
                console.print(f"\n[bold magenta]FLAG: {exploiter._captured_flag}[/bold magenta]")

            # Show verification status
            if exploiter.verification_level:
                from supwngo.exploit.verification import VerificationLevel
                if exploiter.verification_level == VerificationLevel.SHELL_ACCESS:
                    console.print("[bold green]Shell access verified via file creation[/bold green]")
                elif exploiter.verification_level == VerificationLevel.FULL_CONTROL:
                    console.print("[bold green]Full shell control verified[/bold green]")
                elif exploiter.verification_level == VerificationLevel.FLAG_CAPTURED:
                    console.print("[bold green]Exploitation verified by flag capture[/bold green]")

            if output:
                with open(output, 'w') as f:
                    f.write(exploiter.exploit_script)
                console.print(f"[green]Exploit script saved to: {output}[/green]")
            else:
                console.print("\n[bold]Generated Exploit Script:[/bold]")
                console.print(exploiter.exploit_script)
        else:
            console.print("\n[yellow]Full exploitation failed. Generated template:[/yellow]")
            if output:
                with open(output, 'w') as f:
                    f.write(exploiter.exploit_template)
                console.print(f"[yellow]Template saved to: {output}[/yellow]")
            else:
                # Show first part of template
                lines = exploiter.exploit_template.split('\n')[:50]
                console.print('\n'.join(lines))
                if len(exploiter.exploit_template.split('\n')) > 50:
                    console.print("... (truncated)")


def main():
    """Main entry point."""
    cli(obj={})


if __name__ == "__main__":
    main()
