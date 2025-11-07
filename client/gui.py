import json
import os
import time
import requests
import re
import logging
from html import escape as html_escape
from datetime import datetime, timezone
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit,
    QLineEdit, QPushButton, QInputDialog, QMessageBox, QFileDialog,
    QTabWidget
)
from PyQt6.QtCore import QTimer, Qt
from PyQt6.QtGui import QColor, QTextCharFormat, QTextCursor
import asyncio

from config import UPDATES_URL, BSC_RPC
from crypto_utils import load_private_key_from_hex, derive_pubhex_from_private, derive_eth_key_from_ed25519, sign_message_hex
from discord_node import DiscordNodeThread
from bsc_wallet import BSCWallet

# --------------------------------------------------
# Version Info
# --------------------------------------------------
LOCAL_VERSION = "1.4"
VERSION_URL = "https://raw.githubusercontent.com/Excubiae2026/CMN/refs/heads/main/version.txt"

# --------------------------------------------------
# Reward Settings
# --------------------------------------------------
COINS_PER_30_DAYS = 1
HOURLY_REWARD = COINS_PER_30_DAYS / 30 / 24  # ~0.0013889 per hour
DAILY_STAKE_PERCENT = 3.57  # daily staking %

# --------------------------------------------------
# Logger for input validation
# --------------------------------------------------
logging.basicConfig(filename="cmn_input_validation.log", level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")

SAFE_INPUT_RE = re.compile(r"^[\w\s\.\-\,\_\@\:\;\!\?\(\)\'\"#\$%\^\&\*\+\=\/\\\[\]\{\}<>–—…◎\u00A0-\uFFFF]+$", re.UNICODE)
SUSPICIOUS_PATTERNS = [
    r"(?i)\b(select|insert|update|delete|drop|alter|truncate|exec|union|--)\b",
    r"(?i)or\s+1=1",
    r"['\"].*;.*--",
    r";\s*shutdown\b",
]

def is_input_safe(text: str) -> (bool, str):
    if not text or text.strip() == "":
        return False, "Empty message"
    if len(text) > 5000:
        return False, "Message too long"
    if not SAFE_INPUT_RE.match(text):
        return False, "Message contains disallowed characters"
    for pat in SUSPICIOUS_PATTERNS:
        if re.search(pat, text):
            return False, "Message looks suspicious (contains SQL-like content)"
    return True, ""

# --------------------------------------------------
# Uptime Tracker
# --------------------------------------------------
class NodeUptime:
    def __init__(self):
        self.online_since = None

    def start(self):
        self.online_since = time.time()

    def get_uptime_seconds(self):
        if not self.online_since:
            return 0
        now = time.time()
        uptime = now - self.online_since
        self.online_since = now
        return uptime

# --------------------------------------------------
# Node GUI
# --------------------------------------------------
class NodeGUI(QWidget):
    LEDGER_FILE = "ledger.json"

    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"CryptoMesh v{LOCAL_VERSION} - Alpha")
        self.setGeometry(200, 100, 850, 900)
        self.setStyleSheet("""
            QWidget { background-color: #101015; color: #EEE; font-family: Consolas; }
            QLineEdit, QTextEdit { background-color: #1b1b22; color: #DDD; border-radius: 6px; padding: 6px; }
            QPushButton { background-color: #2a2a38; border: 1px solid #3a3a48; border-radius: 6px; padding: 6px; }
            QPushButton:hover { background-color: #383850; }
            QLabel { color: #CCC; }
            QTabWidget::pane { border: 1px solid #333; border-radius: 6px; }
        """)

        self.layout = QVBoxLayout(self)
        self.label = QLabel("🔐 Enter or load your node private key to connect")
        self.layout.addWidget(self.label)

        # ------------------------ Controls
        control_box = QHBoxLayout()
        self.load_key_btn = QPushButton("Paste Private Key")
        self.load_key_btn.clicked.connect(self.prompt_private_key)
        control_box.addWidget(self.load_key_btn)

        self.load_file_btn = QPushButton("Load From File")
        self.load_file_btn.clicked.connect(self.load_key_from_file)
        control_box.addWidget(self.load_file_btn)
        self.layout.addLayout(control_box)

        # ------------------------ Tabs
        self.tabs = QTabWidget()
        self.log_tab = QTextEdit(); self.log_tab.setReadOnly(True)
        self.broadcast_tab = QTextEdit(); self.broadcast_tab.setReadOnly(True)
        self.announcements_tab = QTextEdit(); self.announcements_tab.setReadOnly(True)
        self.wallet_tab = QTextEdit(); self.wallet_tab.setReadOnly(True)
        self.coin_dashboard_tab = QTextEdit(); self.coin_dashboard_tab.setReadOnly(True)
        self.about_tab = QTextEdit(); self.about_tab.setReadOnly(True)
        self.active_nodes_tab = QTextEdit(); self.active_nodes_tab.setReadOnly(True)

        self.tabs.addTab(self.log_tab, "📜 Log")
        self.tabs.addTab(self.broadcast_tab, "📡 Broadcasts")
        self.tabs.addTab(self.announcements_tab, "📰 Updates")
        self.tabs.addTab(self.wallet_tab, "💰 Wallet")
        self.tabs.addTab(self.coin_dashboard_tab, "🪙 Coin Dashboard")
        self.tabs.addTab(self.about_tab, "ℹ️ About")
        self.tabs.addTab(self.active_nodes_tab, "🟢 Active Nodes")
        self.layout.addWidget(self.tabs)

        # ------------------------ Messaging section
        msg_layout = QHBoxLayout()
        self.target_input = QLineEdit(); self.target_input.setPlaceholderText("Target peer pubkey (Optional)")
        msg_layout.addWidget(self.target_input, 40)
        self.msg_input = QLineEdit(); self.msg_input.setPlaceholderText("Enter message to send...")
        msg_layout.addWidget(self.msg_input, 50)
        self.send_btn = QPushButton("Send"); self.send_btn.setEnabled(False)
        self.send_btn.clicked.connect(self.send_message)
        msg_layout.addWidget(self.send_btn, 10)
        self.layout.addLayout(msg_layout)

        # ------------------------ Status
        self.status_label = QLabel("🕒 Status: Not connected")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setStyleSheet("color: #888; font-size: 11pt; margin-top: 10px;")
        self.layout.addWidget(self.status_label)

        # ------------------------ Node variables
        self.node_thread = None
        self.wallet = None
        self.uptime = NodeUptime()
        self.total_coins = 0.0

        # ------------------------ Auto-update system
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.fetch_announcements)
        self.update_timer.start(600000)
        self.fetch_announcements()

        # Version check
        QTimer.singleShot(2000, self.check_version)
        self.populate_about_tab()

        # ------------------------ Ledger reward timer
        self.reward_timer = QTimer()
        self.reward_timer.timeout.connect(self.send_uptime_reward)
        self.reward_timer.start(3600 * 1000)

    # ------------------------ About Tab
    def populate_about_tab(self, latest_version=None):
        GITHUB_ABOUT_URL = "https://raw.githubusercontent.com/Excubiae2026/CMN/refs/heads/main/about.txt"
        try:
            res = requests.get(GITHUB_ABOUT_URL, timeout=5)
            github_about = res.text if res.ok else "⚠️ Failed to fetch About info from GitHub."
        except Exception as e:
            github_about = f"⚠️ Error fetching About info: {e}"

        version_info = f"\n\n<b>Crypto Mesh Node v{LOCAL_VERSION} - Alpha</b><br>"
        if latest_version and latest_version != LOCAL_VERSION:
            version_info += f"<b>⚠️ New version available:</b> {latest_version}<br>Update via GitHub.<br><br>"
        else:
            version_info += f"<b>Version:</b> Up to date ({LOCAL_VERSION})<br><br>"

        self.about_tab.setHtml(f"{github_about}<br>{version_info}<b>Developed by:</b> CryptoMesh Labs 🧠")

    # ------------------------ Version check
    def check_version(self):
        try:
            res = requests.get(VERSION_URL, timeout=5)
            latest_version = res.text.strip()
            if latest_version != LOCAL_VERSION:
                QMessageBox.information(self, "Update Available", f"A new version ({latest_version}) is available!\nYou are running v{LOCAL_VERSION}.")
                self.populate_about_tab(latest_version)
            else:
                self.populate_about_tab()
                self._safe_display(f"✅ You are running the latest version (v{LOCAL_VERSION})", self.log_tab, QColor("#7CFC00"))
        except Exception as e:
            self._safe_display(f"⚠️ Version check failed: {e}", self.log_tab, QColor("#f55"))

    # ------------------------ Announcements
    def fetch_announcements(self):
        try:
            res = requests.get(UPDATES_URL, timeout=10)
            self.announcements_tab.setPlainText(res.text if res.ok else f"HTTP {res.status_code}")
        except Exception as e:
            self.announcements_tab.setPlainText(f"⚠️ {e}")

    # ------------------------ Key Handling
    def prompt_private_key(self):
        priv_hex, ok = QInputDialog.getText(self, "Private Key", "Enter private key hex:")
        if ok and priv_hex:
            self.start_node(priv_hex.strip())

    def load_key_from_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open Key File", "", "Key Files (*.txt *.key *.*)")
        if not path: return
        with open(path) as f:
            self.start_node(f.read().strip())

    # ------------------------ Start Node
    def start_node(self, priv_hex: str):
        try:
            private_key = load_private_key_from_hex(priv_hex)
        except Exception as e:
            QMessageBox.critical(self, "Invalid Key", str(e))
            return

        pubhex = derive_pubhex_from_private(private_key)
        eth_priv, address = derive_eth_key_from_ed25519(priv_hex)

        self.label.setText(f"✅ Connected as Peer: {pubhex}")
        self.status_label.setText("🟢 Node Online")
        self.status_label.setStyleSheet("color: #4cff4c; font-size: 11pt;")

        self.wallet = BSCWallet(BSC_RPC, eth_priv)
        self.wallet_address = address
        self.wallet_priv = eth_priv
        self.show_wallet_priv = False
        self.update_wallet_tab()

        # Start node thread
        self.node_thread = DiscordNodeThread(private_key)
        self.node_thread.new_message.connect(self.append_log)
        self.node_thread.new_broadcast.connect(self.append_broadcast)
        self.node_thread.active_peers_updated.connect(self.update_active_nodes)
        self.node_thread.coin_dashboard_updated.connect(self.update_coin_dashboard)
        self.node_thread.start()

        self.send_btn.setEnabled(True)
        self.uptime.start()

    # ------------------------ Wallet tab
    def update_wallet_tab(self):
        priv_display = self.wallet_priv if self.show_wallet_priv else "🔒 Hidden"
        self.wallet_tab.setPlainText(f"💰 BSC Address: {self.wallet_address}\n🔑 Private key: {priv_display}\n🪙 Coins: {self.total_coins:.6f}")
        if not hasattr(self, "show_priv_btn"):
            self.show_priv_btn = QPushButton("Show/Hide Private Key")
            self.show_priv_btn.clicked.connect(self.toggle_wallet_priv)
            self.layout.addWidget(self.show_priv_btn)

    def toggle_wallet_priv(self):
        self.show_wallet_priv = not self.show_wallet_priv
        self.update_wallet_tab()

    # ------------------------ Enhanced Coin Dashboard ------------------------
    def update_coin_dashboard(self, dashboard_text=None):
        """Visually enhanced coin dashboard with stats and emoji indicators."""
        uptime_hours = round(self.uptime.get_uptime_seconds() / 3600, 2)
        total = getattr(self, "total_coins", 0.0)
        stake_rate = DAILY_STAKE_PERCENT
        hourly = HOURLY_REWARD

        # Load recent ledger if exists
        ledger_data = []
        if os.path.exists(self.LEDGER_FILE):
            try:
                with open(self.LEDGER_FILE, "r", encoding="utf-8") as f:
                    ledger_data = json.load(f)
            except Exception:
                ledger_data = []

        recent_rewards = ledger_data[-5:] if ledger_data else []
        recent_html = ""
        for entry in recent_rewards:
            ts = entry.get("timestamp", "")[-8:]
            rtype = entry.get("type", "")
            reward = entry.get("reward", 0)
            coin_after = entry.get("total_coins_after", 0)
            icon = "🪙" if rtype == "uptime_reward" else "💎"
            recent_html += f"{icon} <b>{rtype}</b> +{reward:.6f} | Total: {coin_after:.6f} ({ts})<br>"

        # Coin visuals
        coin_bar = self._generate_coin_bar(total)
        trend_icon = "📈" if total > 0 else "⚫"
        uptime_icon = "🕒" if uptime_hours > 0 else "⏳"

        # Main Dashboard HTML
        html = f"""
        <div style="font-family:Consolas; font-size:11pt; color:#EEE;">
            <h2>🪙 CryptoMesh Coin Dashboard</h2>
            <b>{trend_icon} Total Coins:</b> <span style="color:#FFD700;">{total:.6f}</span><br>
            <b>{uptime_icon} Uptime Hours:</b> {uptime_hours:.2f}h<br>
            <b>⚡ Hourly Reward:</b> {hourly:.6f}<br>
            <b>💎 Daily Stake Rate:</b> {stake_rate:.2f}%<br><br>
            <div style="background:#222; border-radius:6px; padding:4px;">
                <b>Progress:</b><br>
                <span style="color:#0f0;">{coin_bar}</span>
            </div>
            <br>
            <h4>📜 Recent Rewards</h4>
            <div style="background:#1c1c24; border-radius:6px; padding:6px;">{recent_html or 'No rewards yet.'}</div>
        </div>
        """
        self.coin_dashboard_tab.setHtml(html)

    def _generate_coin_bar(self, total_coins):
        """Create a progress-style bar visualization."""
        max_coins = 10  # scale limit for visual representation
        filled = min(int(total_coins), max_coins)
        bar = "🟩" * filled + "⬛" * (max_coins - filled)
        return f"[{bar}] {total_coins:.2f}/10"

    # ------------------------ Active Nodes tab
    def update_active_nodes(self, peers_list):
        display_text = "\n".join(peers_list) if peers_list else "No active peers."
        self.active_nodes_tab.setPlainText(display_text)
        self._safe_display(f"📌 Active nodes list updated ({len(peers_list)})", self.log_tab, QColor("#00ff99"))

    # ------------------------ Logs
    def append_log(self, msg: str):
        self._safe_display(msg, self.log_tab, QColor("#69d2ff"))

    def append_broadcast(self, data):
        try:
            parsed = json.loads(data) if isinstance(data, str) else data
            if parsed and "message" in parsed and isinstance(parsed["message"], dict):
                text = parsed["message"].get("text")
                sender = parsed.get("sender_pub", "")[:10]
                if text: self._safe_display(f"<{sender}> {text}", self.broadcast_tab, QColor("#ffc107"))
                return
            self._safe_display(str(data), self.broadcast_tab, QColor("#888"))
        except Exception as e:
            self._safe_display(f"[parse error] {e}", self.broadcast_tab, QColor("#f55"))

    # ------------------------ Safe display
    def _safe_display(self, msg: str, tab: QTextEdit, color: QColor):
        now = datetime.now().strftime("%H:%M:%S")
        fmt = QTextCharFormat()
        fmt.setForeground(color)
        cursor = tab.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.insertText(f"[{now}] {msg}\n", fmt)
        tab.ensureCursorVisible()

    # ------------------------ Sending Messages
    def send_message(self):
        if not self.node_thread:
            QMessageBox.warning(self, "Not Connected", "Start node first.")
            return

        text = self.msg_input.text().strip()
        target = self.target_input.text().strip() or None
        if not text:
            return

        safe, reason = is_input_safe(text)
        if not safe:
            logging.warning("Blocked message: %s -- reason: %s", text[:200], reason)
            QMessageBox.warning(self, "Message Blocked", f"Your message was blocked: {reason}")
            return

        safe_text = html_escape(text)
        self.node_thread.send_message(safe_text, target)
        self.msg_input.clear()
        self._safe_display("✉️ Message queued for sending.", self.log_tab, QColor("#cce5ff"))

    # ------------------------ Hourly Reward
    def send_uptime_reward(self):
        if self.node_thread:
            self.node_thread.send_uptime_reward()
            self.total_coins = self.node_thread.total_coins  # keep wallet tab in sync
            self.update_wallet_tab()
