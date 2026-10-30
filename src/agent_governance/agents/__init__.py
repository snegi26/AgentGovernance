# SPDX-License-Identifier: Apache-2.0
"""Agent side of the boundary: code that runs in an agent process.

Agents reach the governance service only over HTTP, holding their own key and nothing else.
Nothing here may import the runtime, the gateway pipeline or any service that holds a signing
key; ``lint-imports`` enforces that, and the verdict packages may not import this one.
"""
