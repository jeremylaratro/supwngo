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
        detector = StackBufferOverflowDetector(bin_obj)
        vulns = detector.detect()

        if vulns:
            vuln = vulns[0]
            console.print(f"  Found: {vuln.vuln_type.name}")
            console.print(f"  Function: {vuln.function}")

    if not vuln:
        console.print("[red]No exploitable vulnerability found[/red]")
        return

    # Generate exploit
    console.print("\n[cyan]Generating exploit...[/cyan]")
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
        console.print("[red]Exploit generation failed[/red]")


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
        techniques = ["ret2win", "shellcode", "ret2system", "srop"]
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


def main():
    """Main entry point."""
    cli(obj={})


if __name__ == "__main__":
    main()
