#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

"""
VulnX - Main Entry Point
CMS Detector, Vulnerability Scanner & Exploitation Framework
Author: Anouar Ben Saad
Maintained: Community Edition
License: GPL-3.0
"""

import sys
import argparse
import warnings
import signal
import os
import re
import socket
import time
import platform
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime

# Third-party imports
import requests

# Internal modules
from modules.detector import CMS
from modules.dorks.engine import Dork
from modules.dorks.helpers import DorkManual
from modules.cli.cli import CLI
from common.colors import (
    red, green, bg, G, R, W, Y, B, C, M,
    good, bad, run, info, end, que, bannerblue2
)
from common.requestUp import random_UserAgent
from common.uriParser import parsing_url as hostd
from common.banner import banner

# ============================================================================
# Constants & Configuration
# ============================================================================

VERSION = "2.1.0"
AUTHOR = "Anouar Ben Saad"
REPO_URL = "https://github.com/anouarbensaad/vulnx"
DOCS_URL = "https://github.com/anouarbensaad/vulnx/wiki"

DEFAULT_HEADERS = {
    'User-Agent': random_UserAgent(),
    'Content-type': '*/*',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Connection': 'keep-alive',
}

# Suppress unnecessary warnings
warnings.filterwarnings(action="ignore", message=".*was already imported", category=UserWarning)
warnings.filterwarnings(action="ignore", category=DeprecationWarning)
warnings.filterwarnings('ignore')  # Disable SSL warnings


# ============================================================================
# Signal Handler
# ============================================================================

def signal_handler(sig: int, frame: Any) -> None:
    """Handle Ctrl+C gracefully with proper cleanup."""
    print(f"\n\n{W}╔══════════════════════════════════════════════════════════════╗{end}")
    print(f"{W}║{Y}  SIGNAL {sig} RECEIVED - INITIATING GRACEFUL SHUTDOWN    {W}║{end}")
    print(f"{W}╚══════════════════════════════════════════════════════════════╝{end}")
    print(f"{info}Cleaning up resources...{end}")
    time.sleep(0.5)
    print(f"{good}Cleanup complete. Exiting safely.{end}")
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)


# ============================================================================
# Interactive Mode - Enhanced Information Display
# ============================================================================

def show_interactive_welcome() -> None:
    """Display comprehensive welcome message for interactive mode."""
    terminal_width = 80
    border = "═" * terminal_width
    
    print(f"\n{Y}{border}{end}")
    print(f"{C}║{W}  VULNX INTERACTIVE MODE v{VERSION}{' ' * (terminal_width - 36)}{C}║{end}")
    print(f"{C}║{W}  Intelligent Bot Auto Shell Injector & CMS Scanner{' ' * (terminal_width - 50)}{C}║{end}")
    print(f"{C}{border}{end}")
    
    # System Information
    print(f"\n{B}┌─ System Information{end}")
    print(f"{B}│{W}  OS           : {platform.system()} {platform.release()}{end}")
    print(f"{B}│{W}  Python       : {platform.python_version()}{end}")
    print(f"{B}│{W}  Time         : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{end}")
    print(f"{B}└───────────────────────────────────────────────────────────────{end}")
    
    # Quick Start Guide
    print(f"\n{G}┌─ Quick Start Guide{end}")
    print(f"{G}│{W}  Basic Scan    : {C}scan <url>{end}")
    print(f"{G}│{W}  Full Scan     : {C}scan <url> --all{end}")
    print(f"{G}│{W}  CMS Info      : {C}scan <url> --cms{end}")
    print(f"{G}│{W}  Subdomains    : {C}scan <url> -d{end}")
    print(f"{G}│{W}  Exploits      : {C}scan <url> -e{end}")
    print(f"{G}│{W}  Port Scan     : {C}scan <url> -p 100{end}")
    print(f"{G}│{W}  Dorks Search  : {C}dorks <cms_name> [pages]{end}")
    print(f"{G}│{W}  Help          : {C}help{end}")
    print(f"{G}│{W}  Exit          : {C}exit, quit, atau Ctrl+C{end}")
    print(f"{G}└───────────────────────────────────────────────────────────────{end}")
    
    # Available CMS for dorks
    print(f"\n{M}┌─ Available CMS for Dorks{end}")
    cms_list = ['wordpress', 'joomla', 'drupal', 'prestashop', 'opencart', 'magento', 'lokomedia']
    for i, cms in enumerate(cms_list, 1):
        print(f"{M}│{W}  {i:2}. {cms:12} {M}│{end}")
    print(f"{M}└───────────────────────────────────────────────────────────────{end}")
    
    # Example Commands
    print(f"\n{Y}┌─ Example Commands{end}")
    examples = [
        ("scan example.com --cms -w", "Basic CMS & web info"),
        ("scan example.com --all", "Complete scan (all features)"),
        ("scan example.com -e --cms -d -w", "Full reconnaissance"),
        ("dorks wordpress 5", "Search WordPress sites (5 pages)"),
        ("dorks all 3", "Search all CMS (3 pages each)"),
        ("help -v", "Show verbose help"),
    ]
    for cmd, desc in examples:
        print(f"{Y}│{W}  {C}{cmd:30}{W}  # {desc}{end}")
    print(f"{Y}└───────────────────────────────────────────────────────────────{end}")
    
    print(f"\n{G}💡 Tip:{W} Type {C}help{W} for all available commands or {C}help <command>{W} for specific help.{end}")
    print(f"{G}📚 Documentation: {C}{DOCS_URL}{end}")
    print(f"{G}🐛 Report issues: {C}{REPO_URL}/issues{end}\n")


def show_interactive_help(command: Optional[str] = None) -> None:
    """
    Display detailed help for interactive mode.
    
    Args:
        command: Specific command to get help for, or None for general help
    """
    if command:
        # Command-specific help
        help_map = {
            'scan': {
                'desc': 'Scan a target URL with various options',
                'syntax': 'scan <url> [options]',
                'options': [
                    ('--cms', 'Gather CMS information (themes, plugins, users, version)'),
                    ('-w, --web-info', 'Gather web server information (headers, IP, server)'),
                    ('-d, --domain-info', 'Enumerate subdomains for the target'),
                    ('-e, --exploit', 'Search for vulnerabilities and run exploits'),
                    ('--dns', 'Dump DNS records (MX, NS, TXT, etc.)'),
                    ('-p, --ports <num>', 'Scan common ports (specify number)'),
                    ('-t, --timeout <sec>', 'HTTP request timeout in seconds'),
                    ('--threads <num>', 'Number of threads for concurrent scanning'),
                    ('-o, --output <dir>', 'Directory to save results'),
                    ('--all', 'Enable all scanning features'),
                    ('--verbose', 'Enable verbose output'),
                ],
                'examples': [
                    ('scan example.com --cms -w', 'Basic scan with CMS and web info'),
                    ('scan example.com --all', 'Full scan with all features enabled'),
                    ('scan example.com -e --cms -d -w', 'Comprehensive reconnaissance scan'),
                    ('scan example.com -p 100 --threads 10', 'Port scan with 10 threads'),
                    ('scan example.com --dns --verbose', 'DNS dump with verbose output'),
                ]
            },
            'dorks': {
                'desc': 'Search for URLs using dorks',
                'syntax': 'dorks <cms_name> [pages]',
                'cms_options': ['wordpress', 'joomla', 'drupal', 'prestashop', 'opencart', 'magento', 'lokomedia', 'all'],
                'examples': [
                    ('dorks wordpress 3', 'Search WordPress sites (3 pages)'),
                    ('dorks joomla 5', 'Search Joomla sites (5 pages)'),
                    ('dorks all 2', 'Search all CMS types (2 pages each)'),
                ]
            },
            'help': {
                'desc': 'Display help information',
                'syntax': 'help [command]',
                'examples': [
                    ('help', 'Show general help'),
                    ('help scan', 'Show detailed scan help'),
                    ('help dorks', 'Show detailed dorks help'),
                ]
            },
            'exit': {
                'desc': 'Exit interactive mode',
                'syntax': 'exit | quit',
                'examples': [
                    ('exit', 'Exit the interactive mode'),
                    ('quit', 'Alternative exit command'),
                ]
            },
            'clear': {
                'desc': 'Clear the terminal screen',
                'syntax': 'clear | cls',
                'examples': [
                    ('clear', 'Clear screen (Unix/Linux)'),
                    ('cls', 'Clear screen (Windows)'),
                ]
            }
        }
        
        if command in help_map:
            info = help_map[command]
            print(f"\n{Y}┌─ Command: {C}{command}{end}")
            print(f"{Y}│{W}  Description: {info['desc']}{end}")
            print(f"{Y}│{W}  Syntax: {C}{info['syntax']}{end}")
            
            if 'options' in info:
                print(f"{Y}│{W}  Options:{end}")
                for opt, desc in info['options']:
                    print(f"{Y}│{W}    {C}{opt:20}{W}  {desc}{end}")
            
            if 'cms_options' in info:
                print(f"{Y}│{W}  Available CMS:{end}")
                for cms in info['cms_options']:
                    print(f"{Y}│{W}    {C}{cms}{end}")
            
            if 'examples' in info:
                print(f"{Y}│{W}  Examples:{end}")
                for cmd, desc in info['examples']:
                    print(f"{Y}│{W}    {C}{cmd:35}{W}  # {desc}{end}")
            print(f"{Y}└───────────────────────────────────────────────────────────────{end}")
        else:
            print(f"{bad}Unknown command: {command}{end}")
            print(f"{info}Type 'help' for available commands.{end}")
    else:
        # General help
        print(f"\n{Y}┌─ Interactive Mode Help{end}")
        print(f"{Y}│{W}  Available Commands:{end}")
        commands = [
            ('scan', 'Scan a target URL'),
            ('dorks', 'Search for URLs using dorks'),
            ('help', 'Display help information'),
            ('clear', 'Clear the terminal screen'),
            ('exit', 'Exit interactive mode'),
            ('quit', 'Exit interactive mode'),
            ('version', 'Show version information'),
            ('about', 'Show information about VulnX'),
        ]
        for cmd, desc in commands:
            print(f"{Y}│{W}    {C}{cmd:10}{W}  {desc}{end}")
        print(f"{Y}│{end}")
        print(f"{Y}│{W}  For detailed help on a specific command:{end}")
        print(f"{Y}│{W}    {C}help <command>{end}")
        print(f"{Y}│{W}    Example: {C}help scan{end}")
        print(f"{Y}└───────────────────────────────────────────────────────────────{end}")


def parse_interactive_command(cmd: str) -> Tuple[str, List[str]]:
    """
    Parse an interactive command string.
    
    Args:
        cmd: Raw command string
        
    Returns:
        Tuple of (command_name, arguments_list)
    """
    parts = cmd.strip().split()
    if not parts:
        return '', []
    return parts[0].lower(), parts[1:]


def show_interactive_version() -> None:
    """Display version information."""
    print(f"\n{Y}┌─ VulnX Version Information{end}")
    print(f"{Y}│{W}  Version      : {C}{VERSION}{end}")
    print(f"{Y}│{W}  Author       : {C}{AUTHOR}{end}")
    print(f"{Y}│{W}  Repository   : {C}{REPO_URL}{end}")
    print(f"{Y}│{W}  Documentation: {C}{DOCS_URL}{end}")
    print(f"{Y}│{W}  Python       : {C}{platform.python_version()}{end}")
    print(f"{Y}│{W}  OS           : {C}{platform.system()} {platform.release()}{end}")
    print(f"{Y}└───────────────────────────────────────────────────────────────{end}")


def show_interactive_about() -> None:
    """Display about information."""
    print(f"\n{Y}┌─ About VulnX{end}")
    print(f"{Y}│{W}  VulnX is an intelligent bot auto shell injector that{end}")
    print(f"{Y}│{W}  detects vulnerabilities in multiple types of CMS.{end}")
    print(f"{Y}│{W}  {end}")
    print(f"{Y}│{W}  Features:{end}")
    features = [
        "CMS Detection (WordPress, Joomla, Drupal, PrestaShop, etc.)",
        "Vulnerability Scanning & Exploitation",
        "Subdomain Enumeration",
        "DNS Information Gathering",
        "Web Server Information Gathering",
        "Port Scanning",
        "Dork Searching",
        "Multi-threading Support",
    ]
    for feat in features:
        print(f"{Y}│{W}    • {C}{feat}{end}")
    print(f"{Y}│{W}  {end}")
    print(f"{Y}│{W}  License: GPL-3.0{end}")
    print(f"{Y}│{W}  Copyright © 2020-2024 {AUTHOR}{end}")
    print(f"{Y}└───────────────────────────────────────────────────────────────{end}")


def process_interactive_command(cmd: str, headers: Dict[str, str], args: argparse.Namespace) -> bool:
    """
    Process an interactive command.
    
    Args:
        cmd: Raw command string
        headers: HTTP headers to use
        args: Current arguments object
        
    Returns:
        bool: True if should continue, False if should exit
    """
    if not cmd or cmd.isspace():
        return True
    
    command, cmd_args = parse_interactive_command(cmd)
    
    # Handle exit commands
    if command in ['exit', 'quit', 'q']:
        print(f"{good}Exiting interactive mode...{end}")
        return False
    
    # Handle clear command
    if command in ['clear', 'cls']:
        os.system('clear' if os.name == 'posix' else 'cls')
        show_interactive_welcome()
        return True
    
    # Handle help command
    if command == 'help':
        if cmd_args:
            show_interactive_help(cmd_args[0])
        else:
            show_interactive_help()
        return True
    
    # Handle version command
    if command == 'version':
        show_interactive_version()
        return True
    
    # Handle about command
    if command == 'about':
        show_interactive_about()
        return True
    
    # Handle scan command
    if command == 'scan':
        if not cmd_args:
            print(f"{bad}Error: URL required for scan command{end}")
            print(f"{info}Usage: scan <url> [options]{end}")
            return True
        
        # Build arguments for scan
        url = cmd_args[0]
        scan_args = cmd_args[1:]
        
        # Parse scan options
        temp_args = argparse.Namespace(
            url=url,
            input_file=None,
            dorks=None,
            numberpage=1,
            dorkslist=None,
            exploit='--exploit' in scan_args or '--all' in scan_args or '-e' in scan_args,
            cms='--cms' in scan_args or '--all' in scan_args,
            webinfo='--web-info' in scan_args or '-w' in scan_args or '--all' in scan_args,
            subdomains='--domain-info' in scan_args or '-d' in scan_args or '--all' in scan_args,
            dnsdump='--dns' in scan_args or '--all' in scan_args,
            scanports=None,
            output=None,
            timeout=args.timeout,
            threads=args.threads,
            cli=False,
            verbose='--verbose' in scan_args or '-v' in scan_args,
            quiet=False
        )
        
        # Parse port scan option
        for i, arg in enumerate(scan_args):
            if arg in ['-p', '--ports'] and i + 1 < len(scan_args):
                try:
                    temp_args.scanports = int(scan_args[i + 1])
                except ValueError:
                    print(f"{bad}Error: Invalid port number{end}")
                    return True
        
        # Parse output option
        for i, arg in enumerate(scan_args):
            if arg in ['-o', '--output'] and i + 1 < len(scan_args):
                temp_args.output = scan_args[i + 1]
        
        # Parse timeout option
        for i, arg in enumerate(scan_args):
            if arg in ['-t', '--timeout'] and i + 1 < len(scan_args):
                try:
                    temp_args.timeout = float(scan_args[i + 1])
                except ValueError:
                    print(f"{bad}Error: Invalid timeout value{end}")
                    return True
        
        # Parse threads option
        for i, arg in enumerate(scan_args):
            if arg == '--threads' and i + 1 < len(scan_args):
                try:
                    temp_args.threads = int(scan_args[i + 1])
                except ValueError:
                    print(f"{bad}Error: Invalid threads value{end}")
                    return True
        
        # Run the scan
        print(f"\n{run}Starting scan for: {C}{url}{end}\n")
        run_detection(url, temp_args, headers)
        return True
    
    # Handle dorks command
    if command == 'dorks':
        if not cmd_args:
            print(f"{bad}Error: CMS name required for dorks command{end}")
            print(f"{info}Usage: dorks <cms_name> [pages]{end}")
            print(f"{info}Available: wordpress, joomla, drupal, prestashop, opencart, magento, lokomedia, all{end}")
            return True
        
        cms = cmd_args[0]
        pages = 1
        if len(cmd_args) > 1:
            try:
                pages = int(cmd_args[1])
            except ValueError:
                print(f"{bad}Error: Invalid page number{end}")
                return True
        
        # Build arguments for dork search
        temp_args = argparse.Namespace(
            url=None,
            input_file=None,
            dorks=cms,
            numberpage=pages,
            dorkslist=None,
            exploit=False,
            cms=False,
            webinfo=False,
            subdomains=False,
            dnsdump=False,
            scanports=None,
            output=None,
            timeout=args.timeout,
            threads=args.threads,
            cli=False,
            verbose=False,
            quiet=False
        )
        
        print(f"\n{run}Searching dorks for: {C}{cms}{W} ({pages} pages){end}\n")
        run_dork_search(temp_args, headers)
        return True
    
    # Unknown command
    print(f"{bad}Unknown command: {command}{end}")
    print(f"{info}Type 'help' for available commands.{end}")
    return True


def enhanced_interactive_mode(headers: Dict[str, str], args: argparse.Namespace) -> None:
    """
    Enhanced interactive CLI mode with comprehensive information.
    
    Args:
        headers: HTTP headers to use
        args: Parsed command-line arguments
    """
    try:
        # Show welcome information
        show_interactive_welcome()
        
        # Interactive loop
        while True:
            try:
                # Get user input with prompt
                prompt = f"{G}vulnx{end} {C}❯{end} "
                cmd = input(prompt).strip()
                
                # Process command
                should_continue = process_interactive_command(cmd, headers, args)
                if not should_continue:
                    break
                
            except KeyboardInterrupt:
                print(f"\n{W}Interrupted. Type 'exit' to quit.{end}")
                continue
            except EOFError:
                print(f"\n{good}Exiting...{end}")
                break
            except Exception as e:
                print(f"{bad}Error processing command: {str(e)}{end}")
                if args.verbose:
                    import traceback
                    traceback.print_exc()
    
    except Exception as e:
        print(f"{bad}Interactive mode error: {str(e)}{end}")
        if args.verbose:
            import traceback
            traceback.print_exc()


# ============================================================================
# Original Functions (Preserved and Enhanced)
# ============================================================================

def parser_error(errmsg: str) -> None:
    """Display error message and exit."""
    print(f"Usage: python {sys.argv[0]} [Options] -h for help")
    print(f"{R}Error: {errmsg}{W}")
    sys.exit(1)


def parse_args() -> argparse.Namespace:
    """
    Parse command-line arguments.
    
    Returns:
        argparse.Namespace: Parsed arguments object
    """
    parser = argparse.ArgumentParser(
        prog="vulnx",
        description="VulnX - Intelligent Bot Auto Shell Injector & CMS Vulnerability Scanner",
        epilog=f"\tExample: \r\npython {sys.argv[0]} -u example.com",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.error = parser_error
    parser._optionals.title = "\nOPTIONS"
    
    # Target specification
    target_group = parser.add_argument_group("Target Specification")
    target_group.add_argument(
        '-u', '--url', 
        dest='url',
        help="Target URL to scan (e.g., https://example.com)"
    )
    target_group.add_argument(
        '-i', '--input', 
        dest='input_file',
        help="File containing list of domains/URLs to scan (one per line)"
    )
    
    # Dork-related options
    dork_group = parser.add_argument_group("Dork Options")
    dork_group.add_argument(
        '-D', '--dorks', 
        dest='dorks',
        type=str,
        help="Search for URLs using dorks (e.g., 'wordpress', 'joomla')"
    )
    dork_group.add_argument(
        '-n', '--number-pages',
        dest='numberpage',
        type=int,
        default=1,
        help="Number of search engine pages to query (default: 1)"
    )
    dork_group.add_argument(
        '-l', '--dork-list',
        dest='dorkslist',
        choices=['wordpress', 'prestashop', 'joomla', 'lokomedia', 'drupal', 'all'],
        help="List available dorks for a specific CMS or 'all'"
    )
    
    # Scan features
    scan_group = parser.add_argument_group("Scan Features")
    scan_group.add_argument(
        '-e', '--exploit',
        dest='exploit',
        action='store_true',
        help="Search for vulnerabilities and run exploits"
    )
    scan_group.add_argument(
        '--cms',
        dest='cms',
        action='store_true',
        help="Gather CMS information (themes, plugins, users, version, etc.)"
    )
    scan_group.add_argument(
        '-w', '--web-info',
        dest='webinfo',
        action='store_true',
        help="Gather web server information (headers, IP, server, etc.)"
    )
    scan_group.add_argument(
        '-d', '--domain-info',
        dest='subdomains',
        action='store_true',
        help="Enumerate subdomains for the target domain"
    )
    scan_group.add_argument(
        '--dns',
        dest='dnsdump',
        action='store_true',
        help="Dump DNS records (MX, NS, TXT, etc.)"
    )
    scan_group.add_argument(
        '-p', '--ports',
        dest='scanports',
        type=int,
        help="Perform port scanning (specify number of common ports to scan)"
    )
    
    # Output & behavior
    output_group = parser.add_argument_group("Output & Behavior")
    output_group.add_argument(
        '-o', '--output',
        dest='output',
        help="Directory to save output results"
    )
    output_group.add_argument(
        '-t', '--timeout',
        dest='timeout',
        type=float,
        default=10.0,
        help="HTTP request timeout in seconds (default: 10)"
    )
    output_group.add_argument(
        '--threads',
        dest='threads',
        type=int,
        default=5,
        help="Number of threads for concurrent scanning (default: 5)"
    )
    output_group.add_argument(
        '--it',
        dest='cli',
        action='store_true',
        help="Launch interactive CLI mode"
    )
    output_group.add_argument(
        '--verbose',
        dest='verbose',
        action='store_true',
        help="Enable verbose output"
    )
    output_group.add_argument(
        '--quiet',
        dest='quiet',
        action='store_true',
        help="Suppress non-essential output"
    )
    
    return parser.parse_args()


def normalize_url(url: str) -> str:
    """
    Normalize URL by ensuring it has a scheme.
    
    Args:
        url: Input URL or domain
        
    Returns:
        Normalized URL with https:// scheme
    """
    url = url.strip()
    if not url:
        return url
        
    if url.startswith(('http://', 'https://')):
        return url
    return f'https://{url}'


def run_detection(url: str, args: argparse.Namespace, headers: Dict[str, str]) -> None:
    """
    Run CMS detection and scanning on a target URL.
    
    Args:
        url: Target URL
        args: Parsed command-line arguments
        headers: HTTP headers to use
    """
    normalized_url = normalize_url(url)
    if args.verbose:
        print(f"{info}Scanning: {normalized_url}{end}")
    
    try:
        instance = CMS(
            normalized_url,
            headers=headers,
            exploit=args.exploit,
            domain=args.subdomains,
            webinfo=args.webinfo,
            serveros=True,
            cmsinfo=args.cms,
            dnsdump=args.dnsdump,
            port=args.scanports,
            timeout=args.timeout,
            threads=args.threads,
            output_dir=args.output,
            verbose=args.verbose
        )
        instance.instanciate()
    except Exception as e:
        if not args.quiet:
            print(f"{bad}Error scanning {normalized_url}: {str(e)}{end}")
        if args.verbose:
            import traceback
            traceback.print_exc()


def run_dork_search(args: argparse.Namespace, headers: Dict[str, str]) -> None:
    """
    Execute dork-based URL search.
    
    Args:
        args: Parsed command-line arguments
        headers: HTTP headers to use
    """
    if args.dorks:
        try:
            if args.verbose:
                print(f"{info}Searching dorks for: {args.dorks}{end}")
            engine = Dork(
                exploit=args.dorks,
                headers=headers,
                pages=args.numberpage
            )
            engine.search()
        except Exception as e:
            print(f"{bad}Dork search failed: {str(e)}{end}")
            if args.verbose:
                import traceback
                traceback.print_exc()


def show_dork_list(args: argparse.Namespace) -> None:
    """
    Display available dorks list.
    
    Args:
        args: Parsed command-line arguments
    """
    if args.dorkslist:
        try:
            manual = DorkManual(select=args.dorkslist)
            manual.list()
        except Exception as e:
            print(f"{bad}Failed to list dorks: {str(e)}{end}")


def run_interactive_mode(args: argparse.Namespace, headers: Dict[str, str]) -> None:
    """
    Launch interactive CLI mode with enhanced features.
    
    Args:
        args: Parsed command-line arguments
        headers: HTTP headers to use
    """
    if args.cli:
        try:
            # Use enhanced interactive mode
            enhanced_interactive_mode(headers, args)
        except Exception as e:
            print(f"{bad}Interactive mode failed: {str(e)}{end}")
            if args.verbose:
                import traceback
                traceback.print_exc()


def scan_from_file(input_file: str, args: argparse.Namespace, headers: Dict[str, str]) -> None:
    """
    Scan multiple targets from an input file.
    
    Args:
        input_file: Path to file containing targets
        args: Parsed command-line arguments
        headers: HTTP headers to use
    """
    if not os.path.exists(input_file):
        print(f"{bad}Input file not found: {input_file}{end}")
        return
    
    try:
        with open(input_file, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
        
        if not urls:
            print(f"{bad}No URLs found in input file{end}")
            return
        
        if args.verbose:
            print(f"{info}Loaded {len(urls)} targets from {input_file}{end}")
        
        for idx, url in enumerate(urls, 1):
            if not args.quiet:
                print(f"\n{run}[{idx}/{len(urls)}] Processing: {url}{end}")
            run_detection(url, args, headers)
            
    except Exception as e:
        print(f"{bad}Error reading input file: {str(e)}{end}")
        if args.verbose:
            import traceback
            traceback.print_exc()


# ============================================================================
# Main Entry Point
# ============================================================================

def main() -> None:
    """Main entry point for VulnX."""
    # Display banner
    banner()
    
    # Parse arguments
    args = parse_args()
    
    # Configure headers with custom timeout if provided
    headers = DEFAULT_HEADERS.copy()
    if hasattr(args, 'timeout'):
        headers['timeout'] = args.timeout
    
    # Mode: No arguments -> interactive mode
    if len(sys.argv) == 1:
        print(f"{info}No arguments provided. Starting enhanced interactive mode...{end}\n")
        args.cli = True
    
    # Execute dork functions
    show_dork_list(args)
    run_dork_search(args, headers)
    
    # Launch interactive mode
    run_interactive_mode(args, headers)
    
    # Process single URL target
    if args.url:
        run_detection(args.url, args, headers)
    
    # Process multiple targets from file
    if args.input_file:
        scan_from_file(args.input_file, args, headers)
    
    # Check if any action was performed
    if not any([args.url, args.input_file, args.dorks, args.dorkslist, args.cli]):
        if not args.quiet:
            print(f"{info}No action specified. Use -h for help.{end}")
            print(f"{info}Example: vulnx -u https://example.com --cms -w -d{end}")
            print(f"{info}Or start interactive mode with: vulnx --it{end}")


if __name__ == "__main__":
    main()
