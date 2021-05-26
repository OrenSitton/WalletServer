"""
Author: Oren Sitton
File: Block.py
Python Version: 3
"""
try:
    from Dependencies.Transaction import Transaction
    from Dependencies.methods import calculate_hash, hexify
except ModuleNotFoundError:
    try:
        from FullNode.Dependencies.Transaction import Transaction
        from FullNode.Dependencies.methods import calculate_hash, hexify

    except ModuleNotFoundError:
        raise ModuleNotFoundError


class Block:
    """
    Block class, used to get and append blocks from Blockchain

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
    from_network_format(message)
        returns a Block object from a network format message
    """

    def __init__(self, block):
        """
        initiator for Block object
        :param block: block from Blockchain
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
            self.transactions.append(Transaction.from_network_format(t))
        self.self_hash = block[8]

    def __str__(self):
        return_string = "Block Number: {}\nTimestamp: {}\nDifficulty: {}\nNonce: {}\nPrevious Hash: {}\nMerkle Root " \
                        "Hash: {}\n".format(self.block_number, self.timestamp, self.difficulty, self.nonce,
                                            self.prev_hash, self.merkle_root_hash)

        for t in self.transactions:
            return_string += "Transaction:\n " + t.__str__() + "\n"

        return_string += "Self Hash: {}\n".format(self.self_hash)
        return return_string

    def network_format(self):
        """
        returns the Block in the network format
        :return: block in the network format
        :rtype: str
        """
        network_format = "d{}{}{}{}{}{}{}".format(hexify(self.block_number, 6), hexify(self.timestamp, 8),
                                                  hexify(self.difficulty, 2), hexify(self.nonce, 64), self.prev_hash,
                                                  self.merkle_root_hash, hexify(len(self.transactions), 2))
        for t in self.transactions:
            if isinstance(t, str):
                t = Transaction.from_network_format(t)
            network_format += hexify(len(t.network_format()), 5)
            network_format += t.network_format()
        return network_format

    @staticmethod
    def from_network_format(message):
        """
        returns a Block object from a network format message
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
    print(Block.from_network_format(
        "d00000160aabee816000000000000000000000000000000000000000000000000000000000053cbe50000000000000000000000000000000000000000000000000000000000000000f5add82b07777f5c4f0aee11f21dee1a78729664339bb667021c1df7e46365e80100153e60aabea40130819f300d06092a864886f70d010101050003818d0030818902818100cd3074f8fd25a61e035854a2a6a7d8542272eac398bbd6dbecea9e841f83fe061702789c28b606ead420dc6a5845b9b79e78bba4e2df403e5d42ca455981fbf07e0beeb5bd63d4ba5695dc52a9af652543577e8f4eaf8cb1da98a1dd0b6ee09882ec38c845b6a026285489ede929c617db74bc1368eb51501688b760c76b85e70203010001000a"))
    pass


if __name__ == '__main__':
    main()
