"""
src/guide.py - Information guide for Argon Client
"""
import os
from .helpers import clear_screen, set_terminal_title
from .tui import console, render_info_panel, wait_for_enter, ACCENT, CYAN
from rich.panel import Panel
from rich.text import Text
from rich import box


FAQ_ITEMS = [
    ("What is I2P?",
     "I2P (Invisible Internet Project) is an anonymous overlay network that allows\n"
     "secure communication and hidden services. It uses garlic routing for privacy."),

    ("What is this client for?",
     "Argon lets you exchange anonymous messages using PGP encryption over I2P.\n"
     "All traffic is routed through encrypted tunnels for maximum anonymity."),

    ("Why should I use this?",
     "Privacy is a human right. I2P lets you communicate and browse anonymously,\n"
     "reducing tracking, surveillance, and exposure of your data."),

    ("Is I2P secure?",
     "I2P provides strong anonymization with garlic routing. By default, traffic\n"
     "is not end-to-end encrypted outside tunnels — that's why Argon adds PGP on top."),

    ("How does encryption work?",
     "We use PGP encryption on top of I2P tunnels. Messages remain confidential\n"
     "even if a relay node is compromised. Your keys never leave your machine."),

    ("Are my keys safe?",
     "Private keys are NEVER stored in cleartext. They are encrypted with Argon2\n"
     "before saving. The password is not stored — keep it safe.\n"
     "⚠  Keys are decrypted in RAM during active sessions. Close the client after use."),

    ("Can this be used for illegal activities?",
     "Absolutely not. This client is for privacy, security, and research purposes\n"
     "only. Misuse is strictly prohibited."),
]

I2P_FAQ = [
    ("What is tunnel creation success rate?",
     "Indicates how often your tunnels are successfully built. A low rate\n"
     "can impact connectivity and joining hidden services."),

    ("What does 'Firewalled' mean?",
     "Your I2P node cannot accept incoming connections directly. You can still\n"
     "communicate, but performance may be reduced."),

    ("Client vs Transit tunnels?",
     "Client tunnels carry YOUR traffic. Transit tunnels relay other users'\n"
     "traffic, contributing to the network's health."),

    ("What are SAM, I2CP, BOB?",
     "SAM: API for applications to interact with I2P.\n"
     "I2CP: Protocol for routers and clients.\n"
     "BOB: Simple chat protocol. Argon uses SAM."),

    ("How to monitor network health?",
     "Use the I2P Health option in the main menu to monitor uptime,\n"
     "tunnel success, bandwidth, and transit tunnels."),
]


def guide():
    """Display the information guide with rich formatting"""
    try:
        clear_screen()
        set_terminal_title("Argon · Guide")

        console.print()

        # General FAQ
        content_lines = []
        for q, a in FAQ_ITEMS:
            content_lines.append(f"[bold {CYAN}]● {q}[/]")
            content_lines.append(f"  [dim]{a}[/dim]")
            content_lines.append("")

        render_info_panel("General Information", "\n".join(content_lines))

        console.print()

        # I2P specific
        i2p_lines = []
        for q, a in I2P_FAQ:
            i2p_lines.append(f"[bold {CYAN}]● {q}[/]")
            i2p_lines.append(f"  [dim]{a}[/dim]")
            i2p_lines.append("")

        render_info_panel("I2P Network", "\n".join(i2p_lines))

        wait_for_enter()

    except KeyboardInterrupt:
        return
