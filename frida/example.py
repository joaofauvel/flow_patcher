"""Frida loader — attaches to Flow and injects the ObjC bridge + hook script."""

import importlib.util
import os
import sys

import frida


def on_message(message, data):
    if message["type"] == "send":
        print(message["payload"])
    else:
        print(message)


def load_bridge(lang):
    """Load the Frida ObjC/Java bridge and wrap it as a globalThis property."""
    frida_tools_path = os.path.dirname(importlib.util.find_spec("frida_tools").origin)
    bridge_file = os.path.join(frida_tools_path, "bridges", f"{lang.lower()}.js")
    with open(bridge_file, encoding="utf-8") as f:
        bridge_src = f.read()
    return (
        "(function() { "
        + bridge_src
        + '; Object.defineProperty(globalThis, "'
        + lang
        + '", { value: bridge }); })();\n'
    )


session = frida.attach("Flow")

with open("script.js") as f:
    source = f.read()

# Prepend the ObjC bridge (language name is CASE SENSITIVE)
source = load_bridge("ObjC") + source

script = session.create_script(source)
script.on("message", on_message)
script.load()

print("[*] Script loaded. Let it run for a few seconds to finish scanning...")
sys.stdin.read()
