from abc import ABC, abstractmethod


class LLMProvider(ABC):

    @abstractmethod
    def complete(self, system: str, user: str) -> str:
        """Send a prompt and return the response text."""
        pass

    @abstractmethod
    def name(self) -> str:
        """Return the provider name for logging."""
        pass
