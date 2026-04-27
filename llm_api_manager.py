import anthropic
from google import genai
from google.genai import types
from mistralai.client import Mistral

from config import LLMConfig

"""
Name Scheme:

[model]_api_call(client, model_id, temperature, tokens, prompt)

"""


def gemini_api_call(client, model_id, temperature, max_tokens, prompt):

    response = client.models.generate_content(
        model=model_id,
        contents=prompt,
        config=types.GenerateContentConfig(
            temperature=temperature,
            max_output_tokens=max_tokens,
            system_instruction=LLMConfig.SYSTEM_INSTRUCTIONS,
        ),
    )
    finish_reason = response.candidates[0].finish_reason
    used_tokens = {
        "prompt": response.usage_metadata.prompt_token_count,
        "completion": response.usage_metadata.candidates_token_count,
        "total": response.usage_metadata.total_token_count,
    }
    return response.text, used_tokens, finish_reason


def anthropic_api_call(
    client,
    model_id,
    temperature,
    max_tokens,
    prompt,
):

    response = client.messages.create(
        model=model_id,
        max_tokens=max_tokens,
        temperature=temperature,
        system=LLMConfig.SYSTEM_INSTRUCTIONS,  # Use the variable here
        messages=[{"role": "user", "content": prompt}],
    )
    finish_reason = response.stop_reason
    used_tokens = {
        "prompt": response.usage.input_tokens,
        "completion": response.usage.output_tokens,
        "total": response.usage.input_tokens + response.usage.output_tokens,
    }
    return response.content[0].text, used_tokens, finish_reason


def mistral_api_call(client, model_id, temperature, max_tokens, prompt):

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

    finish_reason = response.choices[0].finish_reason
    used_tokens = {
        "prompt": response.usage.prompt_tokens,
        "completion": response.usage.completion_tokens,
        "total": response.usage.total_tokens,
    }
    return response.choices[0].message.content, used_tokens, finish_reason


def get_clients():
    # Client inits
    return {
        "gemini": genai.Client(api_key=LLMConfig.GEMINI_KEY),
        "anthropic": anthropic.Anthropic(api_key=LLMConfig.ANTHROPIC_KEY),
        "mistral": Mistral(api_key=LLMConfig.MISTRAL_KEY),
    }
