"""Process trampoline: replaces the gunicorn process with the Go binary.

The workflow command is 'gunicorn ... main:app' which imports this module.
At import time, os.execvp replaces the process image with dns-tool-server,
so gunicorn never actually starts — the Go binary takes over immediately.
"""
import os

os.execvp("./dns-tool-server", ["./dns-tool-server"])
