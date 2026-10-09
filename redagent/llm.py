"""Model client factory. Non-OpenAI models (Ollama) need model_info spelled out."""

from autogen_ext.models.openai import OpenAIChatCompletionClient
from autogen_core.models import ModelInfo


def make_client(cfg):
    return OpenAIChatCompletionClient(
        model=cfg.model,
        base_url=cfg.base_url,
        api_key=cfg.api_key,
        parallel_tool_calls=cfg.parallel_tool_calls,
        model_info=ModelInfo(
            vision=False, function_calling=True, json_output=False,
            family="unknown", structured_output=False,
        ),
    )
