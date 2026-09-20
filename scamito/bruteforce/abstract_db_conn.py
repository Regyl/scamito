from abc import ABC, abstractmethod

class AbstractDBConn(ABC):

    @staticmethod
    @abstractmethod
    def connect(ip: str) -> str | None:
        """

        :param ip:
        :return: found password
        """
        pass