"""
Author: Oren Sitton
File: Dependencies\\__init__.py
Python Version: 3
"""
import logging

try:
    from Dependencies.Blockchain import Blockchain
    from Dependencies.Block import Block
    from Dependencies.SyncedArray import SyncedArray
    from Dependencies.Transaction import Transaction
    from Dependencies.SyncedDictionary import SyncedDictionary

    from Dependencies.methods import *

except ModuleNotFoundError:
    from WalletServer.Dependencies.Blockchain import Blockchain
    from WalletServer.Dependencies.Block import Block
    from WalletServer.Dependencies.SyncedArray import SyncedArray
    from WalletServer.Dependencies.Transaction import Transaction
    from WalletServer.Dependencies.SyncedDictionary import SyncedDictionary

    from WalletServer.Dependencies.methods import *
