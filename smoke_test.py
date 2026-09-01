"""Standalone connectivity check: one call to claude-sonnet-5, nothing wired
into the pipeline. Run with `python smoke_test.py` after `pip install -e ".[agents]"`.
"""

from __future__ import annotations

import os
import sys

from dotenv import load_dotenv

load_dotenv()

api_key = os.environ.get("ANTHROPIC_API_KEY")
if not api_key:
    print("ANTHROPIC_API_KEY not set (check .env)", file=sys.stderr)
    sys.exit(1)

import anthropic

client = anthropic.Anthropic(api_key=api_key)

response = client.messages.create(
    model="claude-sonnet-5",
    max_tokens=100,
    messages=[
        {
            "role": "user",
            "content": 'Reply with exactly this text and nothing else: RhinoSecure LLM online',
        }
    ],
)

print(response.content[0].text)
