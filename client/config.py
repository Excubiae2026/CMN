import os
import sys
from dotenv import load_dotenv

def resource_path(relative_path):
    """Get absolute path to resource (for PyInstaller compatibility)."""
    if hasattr(sys, "_MEIPASS"):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

# Load environment
load_dotenv(resource_path(".env"))

# Discord + BSC Config
TOKEN = os.getenv("DISCORD_TOKEN")
CHANNEL_ID = int(os.getenv("CHANNEL_ID") or 0)
GUILD_ID = int(os.getenv("GUILD_ID") or 0)
BSC_RPC = os.getenv("BSC_RPC") or "https://data-seed-prebsc-1-s1.binance.org:8545/"

UPDATES_URL = "https://raw.githubusercontent.com/Excubiae2026/CMN/refs/heads/main/updates.txt"
