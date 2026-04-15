from openai import OpenAI
from terraview.providers.base import LLMProvider
from terraview import config


class OpenAIProvider(LLMProvider):

    def __init__(self, model: str = None, base_url: str = None):
        self.model = model or config.DEFAULT_MODEL
        self.client = OpenAI(
            api_key=config.OPENAI_API_KEY,
            base_url=base_url or config.SENTINEL_BASE_URL or None,
        )

    def complete(self, system: str, user: str) -> str:
        response = self.client.chat.completions.create(
            model=self.model,
            max_tokens=config.MAX_TOKENS,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        return response.choices[0].message.content

    def name(self) -> str:
        return f"openai/{self.model}"
