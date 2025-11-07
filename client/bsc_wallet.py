from web3 import Web3
from eth_account import Account

class BSCWallet:
    def __init__(self, rpc_url: str, eth_priv_hex: str):
        self.web3 = Web3(Web3.HTTPProvider(rpc_url))
        self.eth_priv_hex = eth_priv_hex
        self.account = Account.from_key(eth_priv_hex)
        self.address = self.account.address

    def get_balance(self):
        try:
            wei_balance = self.web3.eth.get_balance(self.address)
            return self.web3.from_wei(wei_balance, "ether")
        except Exception as e:
            return f"❌ Error: {e}"

    def send_bnb(self, to_addr: str, amount_bnb: float):
        try:
            nonce = self.web3.eth.get_transaction_count(self.address)
            tx = {
                "nonce": nonce,
                "to": to_addr,
                "value": self.web3.to_wei(amount_bnb, "ether"),
                "gas": 21000,
                "gasPrice": self.web3.to_wei("5", "gwei"),
                "chainId": 97  # BSC Testnet
            }
            signed_tx = self.web3.eth.account.sign_transaction(tx, self.eth_priv_hex)
            tx_hash = self.web3.eth.send_raw_transaction(signed_tx.rawTransaction)
            return f"✅ Transaction sent: {tx_hash.hex()}"
        except Exception as e:
            return f"❌ Transaction failed: {e}"
