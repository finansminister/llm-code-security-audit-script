from typing import Any

import anthropic
from google import genai
from google.genai import types
from mistralai.client import Mistral
from openai import OpenAI

from config import LLMConfig, Styles
from config import Telemetry as t

S: Any = Styles

"""
Name scheme and parameters:

[model]_api_call(client, model_id, temperature, max_tokens, prompt)

"""


def gemini_api_call(client, model_id, temperature, max_tokens, prompt):
    try:
        response = client.models.generate_content(
            model=model_id,
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=temperature,
                max_output_tokens=max_tokens,
                system_instruction=LLMConfig.SYSTEM_INSTRUCTIONS,
            ),
        )
        # Check if the model blocked the generation entirely
        if not response.candidates or not response.candidates[0].content:
            return (
                "Refusal: Gemini safety filters triggered.",
                {
                    "prompt": response.usage_metadata.prompt_token_count,
                    "completion": 0,
                    "total": response.usage_metadata.prompt_token_count,
                },
                "blocked",
            )
        content = response.text
        finish_reason = response.candidates[0].finish_reason
        used_tokens = {
            "prompt": response.usage_metadata.prompt_token_count,
            "completion": response.usage_metadata.candidates_token_count,
            "total": response.usage_metadata.total_token_count,
        }

        return content, used_tokens, finish_reason
    except Exception as e:
        log_msg = f"API Request Failed: {model_id}"
        if "401" not in str(e):
            t.log("ERROR", log_msg)
        return (
            f"ERROR: {str(e)}",
            {"prompt": 0, "completion": 0, "total": 0},
            "error",
        )


def anthropic_api_call(
    client,
    model_id,
    temperature,
    max_tokens,
    prompt,
):
    kwargs = {
        "model": model_id,
        "max_tokens": max_tokens,
        "system": LLMConfig.SYSTEM_INSTRUCTIONS,  # Use the variable here
        "messages": [{"role": "user", "content": prompt}],
    }
    if "opus-4-7" not in model_id:
        kwargs["temperature"] = temperature

    try:
        response = client.messages.create(**kwargs)

        content = response.content[0].text
        finish_reason = response.stop_reason
        used_tokens = {
            "prompt": response.usage.input_tokens,
            "completion": response.usage.output_tokens,
            "total": response.usage.input_tokens + response.usage.output_tokens,
        }
        if response.stop_reason == "content_filter":
            return (
                "Refusal: Anthropic content filter triggered.",
                used_tokens,
                "content_filter",
            )
        return content, used_tokens, finish_reason
    except Exception as e:
        log_msg = f"API Request Failed: {model_id}"
        t.log("ERROR", log_msg, error=e)
        return (
            f"ERROR: {str(e)}",
            {"prompt": 0, "completion": 0, "total": 0},
            "error",
        )


def mistral_api_call(client, model_id, temperature, max_tokens, prompt):
    try:
        response = client.chat.complete(
            model=model_id,
            messages=[
                {
                    "role": "system",
                    "content": LLMConfig.SYSTEM_INSTRUCTIONS,
                },
                {"role": "user", "content": prompt},
            ],
            temperature=temperature,
            max_tokens=max_tokens,
        )
        content = response.choices[0].message.content
        finish_reason = response.choices[0].finish_reason
        used_tokens = {
            "prompt": response.usage.prompt_tokens,
            "completion": response.usage.completion_tokens,
            "total": response.usage.total_tokens,
        }
        if finish_reason in ["content_filter", "null"]:
            return (
                f"Refusal: {model_id} refused via {finish_reason}.",
                used_tokens,
                finish_reason,
            )
        return content, used_tokens, finish_reason
    except Exception as e:
        log_msg = f"API Request Failed: {model_id}"
        t.log("ERROR", log_msg, error=e)
        return (
            f"ERROR: {str(e)}",
            {"prompt": 0, "completion": 0, "total": 0},
            "error",
        )


def meta_api_call(client, model_id, temperature, max_tokens, prompt):
    try:
        # OpenRouter usually requires these headers to help with their rankings
        extra_headers = {
            "HTTP-Referer": "https://github.com/finansminister/llm-code-security-audit",
            "X-Title": "Security Audit Research for LLM code generation",
        }

        response = client.chat.completions.create(
            extra_headers=extra_headers,
            model=model_id,
            messages=[
                {
                    "role": "system",
                    "content": LLMConfig.SYSTEM_INSTRUCTIONS,
                },
                {"role": "user", "content": prompt},
            ],
            temperature=temperature,
            max_tokens=max_tokens,
        )

        content = response.choices[0].message.content
        finish_reason = response.choices[0].finish_reason

        used_tokens = {
            "prompt": response.usage.prompt_tokens,
            "completion": response.usage.completion_tokens,
            "total": response.usage.total_tokens,
        }

        if finish_reason in ["content_filter", "null"]:
            return (
                f"Refusal: {model_id} refused via {finish_reason}.",
                used_tokens,
                finish_reason,
            )

        return content, used_tokens, finish_reason

    except Exception as e:
        log_msg = f"API Request Failed (OpenRouter): {model_id}"
        t.log("ERROR", log_msg, error=e)
        return (
            f"ERROR: {str(e)}",
            {"prompt": 0, "completion": 0, "total": 0},
            "error",
        )


def get_clients():
    return {
        "meta": OpenAI(
            base_url="https://openrouter.ai/api/v1", api_key=LLMConfig.META_KEY
        ),  # Openrouter
        "gemini": genai.Client(api_key=LLMConfig.GEMINI_KEY),
        "anthropic": anthropic.Anthropic(api_key=LLMConfig.ANTHROPIC_KEY),
        "mistral": Mistral(api_key=LLMConfig.MISTRAL_KEY),
    }
