"""
Author: Oren Sitton
File: Dependencies\\Block.py
Python Version: 3
Description: Block class, used to get blocks from MySQL Blockchain
"""
try:
    from Dependencies.Transaction import Transaction
    from Dependencies.methods import calculate_hash, fixed_length_hex
except ModuleNotFoundError:
    from WalletServer.Dependencies.Transaction import Transaction
    from WalletServer.Dependencies.methods import calculate_hash, hexify


class Block:
    """
    Block class, used to get blocks from MySQL blockchain

    Attributes
    ----------
    block_number : int

    timestamp : int
        posix timestamp of when block was created
    difficulty : int
        difficulty of the block
    nonce : int
        block's nonce
    prev_hash : str
        hash of the previous block in the blockchain
    merkle_root_hash : str
        merkle tree of the block's transactions root hash
    transactions : list
        list of the block's transactions
    self_hash : str
        hash of the block

    Methods
    -------
    __init__(block)
        initiator for Block object
    network_format()
        returns the block in the network format

    Static Methods
    --------------
    parse(message)
        returns a Block object from a network format message
    """

    def __init__(self, block):
        """
        initiator for Block object
        :param block: block from Blockchain (MySQL returns rows as tuples of all column values)
        :type block: tuple
        """
        if not isinstance(block, tuple):
            raise TypeError("Block.__init__: expected block to be of type tuple")
        self.block_number = block[1]
        self.timestamp = block[2]
        self.difficulty = block[3]
        self.nonce = int(block[4])
        self.prev_hash = block[5]
        self.merkle_root_hash = block[6]

        transaction_data = block[7]
        self.transactions = []
        if isinstance(transaction_data, str):
            transaction_data = transaction_data.split(",")
        else:
            transaction_data = transaction_data.decode().split(",")
        for t in transaction_data:
            self.transactions.append(Transaction.parse(t))
        self.self_hash = block[8]

    def __str__(self):
        """
        format the block as a readable string
        :return: formatted block string
        :rtype: str
        """
        return_string = "Block Number: {}\nTimestamp: {}\nDifficulty: {}\nNonce: {}\nPrevious Hash: {}\nMerkle Root " \
                        "Hash: {}\n".format(self.block_number, self.timestamp, self.difficulty, self.nonce,
                                            self.prev_hash, self.merkle_root_hash)

        for t in self.transactions:
            return_string += "Transaction:\n " + t.__str__() + "\n"

        return_string += "Self Hash: {}\n".format(self.self_hash)
        return return_string

    def network_format(self):
        """
        returns the Block in the network format (per the network protocol)
        :return: block in the network format
        :rtype: str
        """
        network_format = "d{}{}{}{}{}{}{}".format(fixed_length_hex(self.block_number, 6), fixed_length_hex(self.timestamp, 8),
                                                  fixed_length_hex(self.difficulty, 2), fixed_length_hex(self.nonce, 64), self.prev_hash,
                                                  self.merkle_root_hash, fixed_length_hex(len(self.transactions), 2))
        for t in self.transactions:
            if isinstance(t, str):
                t = Transaction.parse(t)
            network_format += fixed_length_hex(len(t.network_format()), 5)
            network_format += t.network_format()
        return network_format

    @staticmethod
    def parse(message):
        """
        returns a Block object from a network format message (per the network protocol)
        :param message: block message
        :type message: str
        :return: Block object from network message
        :rtype: Block
        """
        if not isinstance(message, str):
            raise TypeError("Block.from_network_format: expected message to be of type str")
        if not message[0] == 'd':
            raise ValueError()
        block_number = int(message[1:7], 16)
        timestamp = int(message[7:15], 16)
        difficulty = int(message[15:17], 16)
        nonce = int(message[17:81], 16)
        previous_block_hash = message[81:145]
        merkle_root_hash = message[145:209]
        transaction_count = int(message[209:211], 16)
        message = message[211:]
        block_transactions = []
        for x in range(transaction_count):
            transaction_length = int(message[:5], 16)
            transaction = message[5:transaction_length + 5]
            block_transactions.append(transaction)
            message = message[transaction_length + 5:]
        str_block_transactions = ""
        for t in block_transactions:
            str_block_transactions += t + ","
        str_block_transactions = str_block_transactions[:-1]
        self_hash = calculate_hash(previous_block_hash, merkle_root_hash, nonce)
        block = (
            0, block_number, timestamp, difficulty, nonce, previous_block_hash, merkle_root_hash,
            str_block_transactions,
            self_hash)
        return Block(block)


def main():
    pass


if __name__ == '__main__':
    main()
