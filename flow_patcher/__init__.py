"""
flow_patcher — Unlock Pro features in the Flow app.

Injects a runtime hook dylib that:
- Forces isProSubscriptionActive = YES via NSUserDefaults swizzling
- Injects a fake Lifetime entitlement into RevenueCat's purchaserInfo cache
- Enables CoreData history tracking (prevents read-only mode)
- Blocks Firebase analytics and telemetry
- Forces clean shutdown to avoid gRPC hangs
"""

__all__ = ["inject_dylib", "main"]

from flow_patcher.cli import main
from flow_patcher.inject import inject_dylib
