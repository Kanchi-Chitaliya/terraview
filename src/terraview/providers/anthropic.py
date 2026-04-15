import anthropic
from terraview.providers.base import LLMProvider
from terraview import config


class AnthropicProvider(LLMProvider):

    def __init__(self, model: str = None):
        self.model = model or config.DEFAULT_MODEL
        self.client = anthropic.Anthropic(api_key=config.ANTHROPIC_API_KEY)

    def complete(self, system: str, user: str) -> str:
        message = self.client.messages.create(
            model=self.model,
            max_tokens=config.MAX_TOKENS,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return message.content[0].text

    def name(self) -> str:
        return f"anthropic/{self.model}"
