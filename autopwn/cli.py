#!/usr/bin/env python3
"""
AutoPwn - Automated Binary Exploitation Framework

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

from autopwn import __version__

console = Console()


def print_banner():
    """Print AutoPwn banner."""
    banner = """
    ╔═══════════════════════════════════════════════════════════╗
    ║     _         _        ____                               ║
    ║    / \\  _   _| |_ ___ |  _ \\__      ___ __                ║
    ║   / _ \\| | | | __/ _ \\| |_) \\ \\ /\\ / / '_ \\               ║
    ║  / ___ \\ |_| | || (_) |  __/ \\ V  V /| | | |              ║
    ║ /_/   \\_\\__,_|\\__\\___/|_|     \\_/\\_/ |_| |_|              ║
    ║                                                           ║
    ║  Automated Binary Exploitation Framework                  ║
    ╚═══════════════════════════════════════════════════════════╝
    """
    console.print(banner, style="bold cyan")


@click.group()
@click.version_option(version=__version__)
@click.option("-v", "--verbose", count=True, help="Increase verbosity")
@click.pass_context
def cli(ctx, verbose):
    """AutoPwn - Automated Binary Exploitation Framework"""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose

    # Setup logging
    from autopwn.utils.logging import setup_logging
    setup_logging(verbosity=verbose)


@cli.command()
@click.argument("binary", type=click.Path(exists=True))
@click.option("-o", "--output", default="./output", help="Output directory")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
@click.pass_context
def analyze(ctx, binary, output, json_output):
    """Perform comprehensive binary analysis."""
    from autopwn.core.binary import Binary
    from autopwn.analysis.static import StaticAnalyzer
    from autopwn.analysis.protections import ProtectionAnalyzer

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

    from autopwn.core.binary import Binary
    from autopwn.fuzzing.afl import AFLFuzzer, AFLConfig

    # Load binary
    bin_obj = Binary.load(binary)

    if afl:
        from autopwn.fuzzing.afl import AFLFuzzer, AFLConfig

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

    from autopwn.core.binary import Binary
    from autopwn.fuzzing.crash_triage import CrashTriager

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

    from autopwn.core.binary import Binary
    from autopwn.core.context import ExploitContext
    from autopwn.vulns.stack_bof import StackBufferOverflowDetector
    from autopwn.exploit.generator import ExploitGenerator

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
        from autopwn.fuzzing.crash_triage import CrashTriager, CrashCase

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
            from autopwn.vulns.detector import Vulnerability, VulnType, VulnSeverity
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

    from autopwn.core.binary import Binary
    from autopwn.exploit.rop.gadgets import GadgetFinder
    from autopwn.exploit.rop.chain import ROPChainBuilder

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

    from autopwn.core.binary import Binary
    from autopwn.symbolic.angr_engine import AngrEngine
    from autopwn.symbolic.path_finder import PathFinder

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

    from autopwn.remote.libc_db import LibcDatabase

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
