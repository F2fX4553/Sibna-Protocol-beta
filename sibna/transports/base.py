from abc import ABC, abstractmethod
from typing import Optional

class Transport(ABC):
    """
    Abstract Base Class for Pluggable Transports.
    """
    
    @abstractmethod
    def send(self, data: bytes) -> None:
        """Send data over the transport."""
        pass

    @abstractmethod
    def recv(self) -> Optional[bytes]:
        """Receive data from the transport."""
        pass

    @abstractmethod
    def close(self) -> None:
        """Close the transport."""
        pass
