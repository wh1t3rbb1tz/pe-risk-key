"""Smoke test: one minimal chat call against the Meta Model API."""

from pe_risk_key.providers import SPARK_MODEL, ModelClient

client = ModelClient("claim_extraction", model=SPARK_MODEL)
response = client.chat([{"role": "user", "content": "Reply with exactly: OK"}])
print(response.choices[0].message.content)
print("model:", response.model)
print("usage:", response.usage)
