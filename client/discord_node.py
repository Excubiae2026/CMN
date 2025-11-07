import asyncio
import discord
import json
import os
import hashlib
from datetime import datetime, timezone
from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtGui import QColor
from crypto_keys import derive_pubhex_from_private, sign_message_hex
# optional: verify_message_hex may exist in crypto_keys; we try to import it
try:
    from crypto_keys import verify_message_hex
    HAVE_VERIFY = True
except Exception:
    HAVE_VERIFY = False

from config import TOKEN, CHANNEL_ID
from cryptography.fernet import Fernet

# Encrypted blockchain on-disk
BLOCKCHAIN_FILE = "blockchain.json.enc"
BLOCKCHAIN_KEY_FILE = "blockchain.key"

# Reward params
HOURLY_REWARD = 0.01
DAILY_STAKE_PERCENT = 3.57

# Announcement intervals (seconds)
ANNOUNCE_INTERVAL = 300        # every 5 minutes announce chain head
CHECK_PEER_INTERVAL = 20      # check peer announcements frequently
REQUEST_TIMEOUT = 20          # wait for full chain response window


def get_or_create_key():
    if os.path.exists(BLOCKCHAIN_KEY_FILE):
        with open(BLOCKCHAIN_KEY_FILE, "rb") as f:
            return f.read()
    key = Fernet.generate_key()
    with open(BLOCKCHAIN_KEY_FILE, "wb") as f:
        f.write(key)
    return key


class DiscordNodeThread(QThread):
    new_message = pyqtSignal(str)
    new_broadcast = pyqtSignal(str)
    pubkey_ready = pyqtSignal(str)
    active_peers_updated = pyqtSignal(list)
    coin_dashboard_updated = pyqtSignal(str)

    def __init__(self, private_key):
        super().__init__()
        self.private_key = private_key
        self.pubkey = derive_pubhex_from_private(private_key)
        self.loop = asyncio.new_event_loop()

        # track seen discord messages to avoid duplicates
        self.seen_messages = set()

        # peers and last seen
        self.all_active_peers = set([self.pubkey])
        self.peer_last_seen = {self.pubkey: datetime.now(timezone.utc).timestamp()}

        # blockchain / coin bookkeeping
        self.total_coins = 0.0
        self.total_uptime_rewards = 0.0
        self.last_uptime_reward = 0.0
        self.last_staking_reward = 0.0

        # P2P chain metadata from peers {pubkey: {"length": int, "head": str, "seen": ts}}
        self.peer_announcements = {}

        # encryption cipher for local chain storage
        self.cipher = Fernet(get_or_create_key())

        intents = discord.Intents.default()
        intents.messages = True
        intents.guilds = True
        intents.members = True
        intents.message_content = True

        self.client = discord.Client(intents=intents)
        self.client.event(self.on_ready)
        self.client.event(self.on_message)

        # in-memory chain cache (load at init)
        self.chain = self._load_chain()
        if self.chain:
            # try to restore coin balance from chain if valid
            self._recompute_state_from_chain()

    # ---------------------------
    # Discord event loops
    # ---------------------------
    def run(self):
        asyncio.set_event_loop(self.loop)
        try:
            self.loop.run_until_complete(self.client.start(TOKEN))
        except Exception as e:
            self.new_message.emit(f"❌ Discord client stopped: {e}")

    async def on_ready(self):
        self.new_message.emit(f"✅ Node connected to HUB")
        self.pubkey_ready.emit(self.pubkey)
        await self.send_key_advert()

        # If local chain is empty, request one from peers
        if not self.chain:
            self.new_message.emit("🪙 No local blockchain found — requesting latest chain from peers...")
            await self._request_initial_chain()
        else:
            self.new_message.emit(f"⛓️ Loaded local chain (height {len(self.chain)})")

        # start background tasks
        self.loop.create_task(self.poll_history_loop())
        self.loop.create_task(self.send_online_signal_loop())
        self.loop.create_task(self.hourly_reward_loop())
        self.loop.create_task(self.staking_reward_loop())
        self.loop.create_task(self.chain_announce_loop())
        self.loop.create_task(self.peer_check_loop())

    async def _request_initial_chain(self):
        """Try to fetch an existing blockchain from peers before creating a new one."""
        channel = self.client.get_channel(CHANNEL_ID)
        if not channel:
            self.new_message.emit("⚠️ Cannot request initial chain — no hub channel.")
            return

        # Send a broadcast chain request (target=None)
        payload = {
            "type": "request_chain",
            "sender_pub": self.pubkey,
            "target_pub": None,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        payload["signature"] = sign_message_hex(self.private_key, payload)
        await channel.send(json.dumps(payload))
        self.new_message.emit("📡 Broadcasted request for current blockchain...")

        # Wait up to REQUEST_TIMEOUT seconds for a full_chain response
        waited = 0
        while waited < REQUEST_TIMEOUT:
            await asyncio.sleep(2)
            waited += 2
            if self.chain:
                self.new_message.emit(f"✅ Blockchain synced from peers (height {len(self.chain)})")
                return

        # If still no chain received
        self.new_message.emit("⚠️ No peers responded with a chain — starting a fresh one.")
        self.chain = []
        self._save_chain(self.chain)

    async def send_key_advert(self):
        channel = self.client.get_channel(CHANNEL_ID)
        if not channel:
            self.new_message.emit("⚠️ Could not find channel to advertise key.")
            return
        advert_msg = {
            "type": "key_advert",
            "sender_pub": self.pubkey,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        payload = {**advert_msg, "signature": sign_message_hex(self.private_key, advert_msg)}
        await channel.send(json.dumps(payload))
        self.new_message.emit("🔑 Sent signed key advertisement to hub")

    async def send_online_signal_loop(self):
        await asyncio.sleep(5)
        channel = self.client.get_channel(CHANNEL_ID)
        if not channel:
            self.new_message.emit("⚠️ Could not find channel to send heartbeat.")
            return
        while True:
            try:
                now_ts = datetime.now(timezone.utc).timestamp()
                # prune inactive peers (5 minutes)
                inactive = [pub for pub, last in self.peer_last_seen.items() if now_ts - last > 300]
                for pub in inactive:
                    self.all_active_peers.discard(pub)
                    self.peer_last_seen.pop(pub, None)

                # always include self
                self.all_active_peers.add(self.pubkey)
                self.peer_last_seen[self.pubkey] = now_ts

                payload = {
                    "type": "active_peers",
                    "sender_pub": self.pubkey,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "peers": list(self.all_active_peers)
                }
                payload["signature"] = sign_message_hex(self.private_key, payload)
                await channel.send(json.dumps(payload))
                self.new_message.emit(
                    f"💚 Sent heartbeat with {len(self.all_active_peers)} active peers (removed {len(inactive)} inactive)"
                )
            except Exception as e:
                self.new_message.emit(f"❌ Failed to send heartbeat: {e}")
            await asyncio.sleep(300)

    async def poll_history_loop(self):
        channel = self.client.get_channel(CHANNEL_ID)
        if not channel:
            self.new_message.emit("⚠️ Could not find channel to fetch history.")
            return
        while True:
            try:
                async for msg in channel.history(limit=50):
                    if msg.id in self.seen_messages:
                        continue
                    self.seen_messages.add(msg.id)
                    try:
                        payload = json.loads(msg.content)
                    except Exception:
                        continue
                    await self.process_payload(payload)
                await asyncio.sleep(5)
            except Exception as e:
                self.new_message.emit(f"❌ Error fetching history: {e}")
                await asyncio.sleep(5)

    async def on_message(self, message):
        # real-time incoming message handler
        if message.author == self.client.user or message.channel.id != CHANNEL_ID:
            return
        if message.id in self.seen_messages:
            return
        self.seen_messages.add(message.id)
        try:
            payload = json.loads(message.content)
        except Exception:
            return
        await self.process_payload(payload)

    # ---------------------------
    # Payload handling & P2P chain messages
    # ---------------------------
    async def process_payload(self, payload):
        msg_type = payload.get("type")
        sender_pub = payload.get("sender_pub", "unknown")
        # update peer last seen
        self.peer_last_seen[sender_pub] = datetime.now(timezone.utc).timestamp()

        # Handle chain announcements from peers
        if msg_type == "chain_announcement":
            length = int(payload.get("length", 0))
            head = payload.get("head", "")
            # store announcement with timestamp
            self.peer_announcements[sender_pub] = {"length": length, "head": head, "seen": datetime.now(timezone.utc).timestamp()}
            self.new_message.emit(f"🔔 Chain announcement from {sender_pub[:10]}: len={length}, head={head[:8]}")
            return

        # Another node requests our full chain
        if msg_type == "request_chain":
            target = payload.get("target_pub")
            requester = sender_pub
            if target == self.pubkey or target in [None, "null"]:
                # respond with full chain (signed blocks are already in chain)
                await self._send_full_chain(target_pub=requester)
            return

        # Full chain being sent to a requesting node (targeted)
        if msg_type == "full_chain":
            target = payload.get("target_pub")
            if target != self.pubkey:
                return
            sender = sender_pub
            chain = payload.get("chain")
            if not isinstance(chain, list):
                self.new_message.emit(f"⚠️ Received invalid chain format from {sender[:10]}")
                return
            # verify chain (hash links + block hashes)
            if self._validate_chain(chain):
                # verify all block signatures if possible
                sig_ok = self._verify_chain_signatures(chain)
                if not sig_ok:
                    self.new_message.emit(f"⚠️ Signature verification failed for chain from {sender[:10]}; rejecting")
                    return
                # adopt chain if longer than ours
                if len(chain) > len(self.chain):
                    self.chain = chain
                    self._save_chain(self.chain)
                    self._recompute_state_from_chain()
                    self._update_dashboard(f"✅ Adopted longer chain from {sender[:10]} (len={len(chain)})")
                else:
                    self.new_message.emit(f"ℹ️ Received chain from {sender[:10]} not longer than local chain (got {len(chain)}, local {len(self.chain)})")
            else:
                self.new_message.emit(f"⚠️ Invalid chain received from {sender[:10]}; rejected")
            return

        # Other existing message types (active_peers, encrypted_msg, etc.)
        if msg_type == "active_peers":
            peers = payload.get("peers", [])
            now_ts = datetime.now(timezone.utc).timestamp()
            for p in peers:
                self.peer_last_seen[p] = now_ts
            before = len(self.all_active_peers)
            self.all_active_peers.update(peers)
            after = len(self.all_active_peers)
            self.active_peers_updated.emit(list(self.all_active_peers))
            self.new_message.emit(f"🌐 Active peers updated ({after} total, +{after - before} new)")
            return

        if msg_type == "encrypted_msg":
            text = payload.get("message", {}).get("text", "")
            target_pub = payload.get("target_pub")
            if not target_pub or target_pub.lower() in ["null", "broadcast"]:
                self.new_broadcast.emit(json.dumps(payload, indent=2))
                self.new_message.emit(f"[{sender_pub[:10]}] {text}")
            elif target_pub == self.pubkey:
                self.new_broadcast.emit(json.dumps(payload, indent=2))
                self.new_message.emit(f"🔒 [{sender_pub[:10]} -> you] {text}")
            else:
                self.new_message.emit(f"🔐 Encrypted message from {sender_pub[:10]}")
            return

    # ---------------------------
    # Chain storage: encrypted local file
    # ---------------------------
    def _load_chain(self):
        if not os.path.exists(BLOCKCHAIN_FILE):
            return []
        try:
            with open(BLOCKCHAIN_FILE, "rb") as f:
                enc = f.read()
            dec = self.cipher.decrypt(enc).decode("utf-8")
            chain = json.loads(dec)
            if self._validate_chain(chain):
                return chain
            else:
                self.new_message.emit("⚠️ Local blockchain failed validation at load; discarding.")
                return []
        except Exception as e:
            self.new_message.emit(f"⚠️ Failed to load local blockchain: {e}")
            return []

    def _save_chain(self, chain):
        try:
            data = json.dumps(chain, indent=4).encode("utf-8")
            enc = self.cipher.encrypt(data)
            with open(BLOCKCHAIN_FILE, "wb") as f:
                f.write(enc)
        except Exception as e:
            self.new_message.emit(f"❌ Failed to save blockchain: {e}")

    # ---------------------------
    # Block utilities: hashing & validation
    # ---------------------------
    def _hash_block(self, block_dict):
        # hash block content deterministically (without the 'hash' field)
        block_copy = dict(block_dict)
        block_copy.pop("hash", None)
        # ensure sorted keys for deterministic hash
        block_string = json.dumps(block_copy, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        return hashlib.sha256(block_string).hexdigest()

    def _get_chain_head(self):
        if not self.chain:
            return "0" * 64
        return self.chain[-1]["hash"]

    def _validate_chain(self, chain):
        if not chain:
            return True
        # verify structural linking and hash integrity
        for i in range(len(chain)):
            block = chain[i]
            # check index coherence
            if block.get("index") != i + 1:
                return False
            # verify prev_hash
            if i == 0:
                expected_prev = "0" * 64
            else:
                expected_prev = chain[i - 1]["hash"]
            if block.get("prev_hash") != expected_prev:
                return False
            # verify stored hash matches computed
            stored_hash = block.get("hash")
            if not stored_hash:
                return False
            computed = self._hash_block(block)
            if computed != stored_hash:
                return False
        return True

    def _verify_block_signature(self, block):
        """Verify a block's signature if verify_message_hex is available.

        Block must contain fields 'signature' and the public key that signed it (we assume the block was signed by the node that generated it).
        We expect the block to have been signed by its creator pubkey — we'll try to verify against that pubkey if present.
        """
        if not HAVE_VERIFY:
            # can't verify signatures; return True but emit warning
            return True
        sig = block.get("signature")
        if not sig:
            return False
        # Many verify APIs expect (pubkey, message, signature) or (signature, message, pubkey).
        # We'll try both common variants; adapt if your verify API differs.
        block_copy = dict(block)
        block_copy.pop("hash", None)
        signature_ok = False
        for attempt in range(2):
            try:
                # attempt typical: verify_message_hex(pubhex, message_obj, signature)
                creator_pub = block.get("creator_pub") or block.get("sender_pub") or None
                if creator_pub:
                    signature_ok = verify_message_hex(creator_pub, block_copy, sig)
                else:
                    # if no explicit creator, try verify with last-known pub? skip.
                    signature_ok = False
                if signature_ok:
                    break
            except TypeError:
                # maybe verify signature order differs: verify_message_hex(signature, message_json, pubhex)
                try:
                    creator_pub = block.get("creator_pub") or block.get("sender_pub") or None
                    if creator_pub:
                        signature_ok = verify_message_hex(sig, block_copy, creator_pub)
                    else:
                        signature_ok = False
                    if signature_ok:
                        break
                except Exception:
                    signature_ok = False
            except Exception:
                signature_ok = False
        return signature_ok

    def _verify_chain_signatures(self, chain):
        if not HAVE_VERIFY:
            self.new_message.emit("⚠️ Signature verification function missing; skipping block signature checks.")
            return True
        for block in chain:
            if not self._verify_block_signature(block):
                return False
        return True

    # ---------------------------
    # Append block (local creation), sign it and broadcast announcement
    # ---------------------------
    def _create_block_and_append(self, data_type: str, reward: float):
        chain = self.chain or []
        prev_hash = self._get_chain_head()
        block = {
            "index": len(chain) + 1,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": data_type,
            "reward": reward,
            "total_coins_after": self.total_coins,
            "prev_hash": prev_hash,
            "creator_pub": self.pubkey
        }
        # sign block payload (signature over block without 'hash')
        block["signature"] = sign_message_hex(self.private_key, block)
        # compute block hash
        block["hash"] = self._hash_block(block)
        # attach and persist
        chain.append(block)
        self.chain = chain
        self._save_chain(self.chain)
        # announce chain head to peers
        asyncio.run_coroutine_threadsafe(self._broadcast_chain_announcement(), self.loop)
        return block

    # ---------------------------
    # Reward functions (use _create_block_and_append)
    # ---------------------------
    def send_uptime_reward(self):
        uptime_seconds = 3600
        reward = (uptime_seconds / 3600) * HOURLY_REWARD
        self.total_coins += reward
        self.total_uptime_rewards += reward
        self.last_uptime_reward = reward
        self._create_block_and_append("uptime_reward", reward)
        self._update_dashboard(f"🪙 +{reward:.6f} uptime")

    def send_staking_reward(self):
        if self.total_coins <= 0:
            return
        reward = self.total_coins * (DAILY_STAKE_PERCENT / 100)
        self.total_coins += reward
        self.last_staking_reward = reward
        self._create_block_and_append("staking_reward", reward)
        self._update_dashboard(f"💎 +{reward:.6f} staking")

    # ---------------------------
    # Dashboard helpers
    # ---------------------------
    def _recompute_state_from_chain(self):
        """Recompute total_coins and totals from chain (trusts the chain)."""
        total = 0.0
        uptime_total = 0.0
        last_u = 0.0
        last_s = 0.0
        for block in self.chain:
            t = block.get("type")
            r = float(block.get("reward", 0))
            total = float(block.get("total_coins_after", total + r))
            if t == "uptime_reward":
                uptime_total += r
                last_u = r
            elif t == "staking_reward":
                last_s = r
        self.total_coins = total
        self.total_uptime_rewards = uptime_total
        self.last_uptime_reward = last_u
        self.last_staking_reward = last_s

    def _update_dashboard(self, event_msg):
        dash = (
            f"🎮 CryptoMesh Blockchain Wallet 🎮\n"
            f"{event_msg}\n"
            f"💰 Total: {self.total_coins:.6f} 🪙\n"
            f"📈 Uptime Earned: {self.total_uptime_rewards:.6f}\n"
            f"⛓️ Chain height: {len(self.chain)}\n"
            f"🔒 Encrypted file: {BLOCKCHAIN_FILE}"
        )
        self.coin_dashboard_updated.emit(dash)
        self.new_message.emit(dash)

    # ---------------------------
    # P2P: announce head, broadcast, request full chain, respond with full chain
    # ---------------------------
    async def _broadcast_chain_announcement(self):
        channel = self.client.get_channel(CHANNEL_ID)
        if not channel:
            self.new_message.emit("⚠️ No hub channel to announce chain.")
            return
        payload = {
            "type": "chain_announcement",
            "sender_pub": self.pubkey,
            "length": len(self.chain),
            "head": self._get_chain_head(),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        payload["signature"] = sign_message_hex(self.private_key, payload)
        try:
            await channel.send(json.dumps(payload))
        except Exception as e:
            self.new_message.emit(f"⚠️ Failed to send chain announcement: {e}")

    async def chain_announce_loop(self):
        await asyncio.sleep(3)
        while True:
            await self._broadcast_chain_announcement()
            await asyncio.sleep(ANNOUNCE_INTERVAL)

    async def peer_check_loop(self):
        """Periodically check peer announcements and request chain if a longer head is seen."""
        await asyncio.sleep(5)
        while True:
            try:
                # pick the peer with longest announced length that is > local
                best = None
                best_len = len(self.chain)
                for pub, info in list(self.peer_announcements.items()):
                    if info.get("length", 0) > best_len:
                        best_len = info["length"]
                        best = (pub, info)
                if best:
                    pub, info = best
                    self.new_message.emit(f"🔎 Detected longer chain at {pub[:10]} (len={info['length']}). Requesting chain...")
                    await self._send_request_chain(target_pub=pub)
                    # wait short window for reply
                    await asyncio.sleep(REQUEST_TIMEOUT)
                # cleanup stale announcements (older than 10 minutes)
                now_ts = datetime.now(timezone.utc).timestamp()
                stale = [p for p, i in self.peer_announcements.items() if now_ts - i.get("seen", 0) > 600]
                for p in stale:
                    self.peer_announcements.pop(p, None)
            except Exception as e:
                self.new_message.emit(f"⚠️ peer_check_loop error: {e}")
            await asyncio.sleep(CHECK_PEER_INTERVAL)

    async def _send_request_chain(self, target_pub):
        channel = self.client.get_channel(CHANNEL_ID)
        if not channel:
            self.new_message.emit("⚠️ No hub channel to request chain.")
            return
        payload = {
            "type": "request_chain",
            "sender_pub": self.pubkey,
            "target_pub": target_pub,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        payload["signature"] = sign_message_hex(self.private_key, payload)
        try:
            await channel.send(json.dumps(payload))
        except Exception as e:
            self.new_message.emit(f"⚠️ Failed to request chain from {target_pub[:10]}: {e}")

    async def _send_full_chain(self, target_pub):
        """Send full chain as plaintext JSON signed by sender (targeted)."""
        channel = self.client.get_channel(CHANNEL_ID)
        if not channel:
            self.new_message.emit("⚠️ No hub channel to send full chain.")
            return
        # prepare a copy with signed blocks (blocks already contain signatures + hash)
        chain_copy = list(self.chain)
        payload = {
            "type": "full_chain",
            "sender_pub": self.pubkey,
            "target_pub": target_pub,
            "chain": chain_copy,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        payload["signature"] = sign_message_hex(self.private_key, payload)
        try:
            await channel.send(json.dumps(payload))
            self.new_message.emit(f"📤 Sent full chain to {target_pub[:10]}")
        except Exception as e:
            self.new_message.emit(f"⚠️ Failed to send full chain: {e}")

    # ---------------------------
    # Periodic reward loops
    # ---------------------------
    async def hourly_reward_loop(self):
        await asyncio.sleep(5)
        while True:
            try:
                self.send_uptime_reward()
            except Exception as e:
                self.new_message.emit(f"⚠️ hourly_reward_loop error: {e}")
            await asyncio.sleep(3600)

    async def staking_reward_loop(self):
        await asyncio.sleep(10)
        while True:
            try:
                self.send_staking_reward()
            except Exception as e:
                self.new_message.emit(f"⚠️ staking_reward_loop error: {e}")
            await asyncio.sleep(24 * 60 * 60)

    # ---------------------------
    # Public helper to manually request everyone's announcements (optional)
    # ---------------------------
    def ask_for_announcements(self):
        """Utility: quickly broadcast chain announcement (manual trigger)."""
        asyncio.run_coroutine_threadsafe(self._broadcast_chain_announcement(), self.loop)

    def send_message(self, text, target=None):
        """Send encrypted broadcast or P2P message."""

        async def send():
            channel = self.client.get_channel(CHANNEL_ID)
            if not channel:
                self.new_message.emit("⚠️ No channel found.")
                return

            msg_obj = {"text": text, "timestamp": datetime.now(timezone.utc).isoformat()}
            payload = {
                "type": "encrypted_msg",
                "sender_pub": self.pubkey,
                "target_pub": target,
                "message": msg_obj,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "signature": sign_message_hex(self.private_key, msg_obj)
            }

            await channel.send(json.dumps(payload))
            self.new_broadcast.emit(json.dumps(payload, indent=2))
            self.new_message.emit("✉️ Message sent.")

        asyncio.run_coroutine_threadsafe(send(), self.loop)
