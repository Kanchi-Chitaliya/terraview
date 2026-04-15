from terraview.providers.base import LLMProvider
from terraview import config


def get_provider(provider: str = None, model: str = None) -> LLMProvider:
    provider = provider or config.SENTINEL_PROVIDER

    if provider == "anthropic":
        from terraview.providers.anthropic import AnthropicProvider
        return AnthropicProvider(model=model)

    elif provider == "openai":
        from terraview.providers.openai import OpenAIProvider
        return OpenAIProvider(model=model)

    elif provider == "ollama":
        from terraview.providers.openai import OpenAIProvider
        return OpenAIProvider(
            model=model or "llama3",
            base_url="http://localhost:11434/v1",
        )

    else:
        raise ValueError(
            f"Unknown provider '{provider}'. "
            f"Choose from: anthropic, openai, ollama"
        )
