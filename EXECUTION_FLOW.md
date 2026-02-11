# Execution Flow

How the patched Flow.app behaves from launch to shutdown.

## 1. Launch: dylib constructor

```
Process starts
  → dyld loads FlowPatch.dylib (injected LC_LOAD_DYLIB)
  → __attribute__((constructor)) patch_init() runs BEFORE main()
```

`patch_init()` does the following in order:

1. **Registers termination handler** — `NSApplicationWillTerminateNotification` observer
   that calls `_exit(0)` after 100ms (bypasses gRPC 10s hang from Firestore)
2. **Registers deferred analytics hooks** — `NSApplicationDidFinishLaunchingNotification`
   observer that installs Firebase/GDT no-ops after all frameworks load
3. **Swizzles NSUserDefaults** — hooks `boolForKey:`, `objectForKey:`, `setBool:forKey:`,
   `setObject:forKey:`, `removeObjectForKey:`
4. **Hooks RevenueCat** — `RCEntitlementInfo.isActive` → always `YES`
5. **Hooks CoreData** — `NSPersistentContainer.loadPersistentStoresWithCompletionHandler:`
   → injects `NSPersistentHistoryTrackingKey`
6. **Preemptive write** — `setBool:YES forKey:isProSubscriptionActive`

## 2. App initialization

```
main() starts
  → NSApplication setup
  → FIRApp.configure() runs (Firestore init — NOT blocked)
  → NSApplicationDidFinishLaunchingNotification fires
    → installAnalyticsHooks() runs (no-ops FIRAnalytics, GDTCORTransport, etc.)
```

## 3. RevenueCat subscription check

The SDK determines subscription status through two phases:

### Phase A: cached data (synchronous)

```
SDK reads cached purchaserInfo from NSUserDefaults
  → objectForKey: "com.revenuecat.userdefaults.purchaserInfo.$anonID"
  → HOOK intercepts: injects pro entitlement + Lifetime subscription into JSON
  → SDK parses patched JSON → sees active "pro" entitlement
  → SDK constructs RCCustomerInfo with pro = active
  → App receives customerInfo → isPro=YES → loads pro settings from UserDefaults
  → Settings load correctly (flow.durationInMinutes, sessionCount, etc.)
```

### Phase B: network refresh (async)

```
SDK makes HTTPS request to api.revenuecat.com/v1/subscribers/...
  → Server returns real subscriber data (no pro entitlement)
  → SDK calls setObject:forKey: to cache the new data
  → HOOK intercepts: injects pro entitlement before writing to cache
  → SDK re-reads the cached data for the new RCCustomerInfo
  → objectForKey: intercepted again → pro injected
  → App receives updated customerInfo → still isPro=YES → no reset
```

### Entitlement flow

```
RCEntitlementInfo.isActive
  → HOOK returns YES unconditionally
  → Any code path checking entitlement.isActive sees pro = active
```

## 4. UserDefaults behavior

| Method | Pro key behavior | purchaserInfo behavior | Other keys |
|--------|-----------------|----------------------|------------|
| `boolForKey:` | Returns `YES` | N/A | Pass-through |
| `objectForKey:` | Pass-through | Injects pro entitlement | Pass-through |
| `setBool:forKey:` | Forces `YES` | N/A | Pass-through |
| `setObject:forKey:` | Forces `@YES` | Injects pro entitlement | Pass-through |
| `removeObjectForKey:` | Blocked (no-op) | N/A | Pass-through |

## 5. CoreData

```
NSPersistentContainer.loadPersistentStoresWithCompletionHandler:
  → HOOK adds NSPersistentHistoryTrackingKey = YES
  → HOOK adds NSPersistentStoreRemoteChangeNotificationPostOptionKey = YES
  → Calls original implementation
```

Without this, CoreData enters read-only mode because the original App Store
version used CloudKit history tracking (via `NSPersistentCloudKitContainer`),
and the unsandboxed copy loses the CloudKit entitlement.

## 6. Analytics

Deferred to `NSApplicationDidFinishLaunchingNotification` because Firebase
classes aren't registered until `FIRApp.configure()` runs. Cannot block
`FIRApp.configure` itself — Firestore depends on it.

Hooked entry points (all replaced with no-ops):

| Class | Methods |
|-------|---------|
| `FIRAnalytics` | `logEventWithName:parameters:`, `setUserPropertyString:forName:`, `setScreenName:screenClass:`, `setAnalyticsCollectionEnabled:` |
| `FIRAnalyticsConfiguration` | `setAnalyticsCollectionEnabled:`, `postNotificationForConsentUpdate:` |
| `FIRHeartbeatLogger` | `log:`, `flushHeartbeatsIntoPayload` |
| `GDTCORTransport` | `sendDataEvent:onComplete:`, `sendTelemetryEvent:onComplete:` |
| `GDTCORFlatFileStorage` | `storeEvent:onComplete:` |

Not all hooks resolve at runtime — only classes present in the binary match.
The log shows "Blocked N analytics entry points" for the count that succeeded.

## 7. Shutdown

```
User presses Cmd+Q
  → NSApplicationWillTerminateNotification fires
  → App's own handler saves state (timer countdown, phase, remaining seconds)
  → Our handler fires too: dispatch_after(100ms) { synchronize; _exit(0); }
  → 100ms elapses → UserDefaults flushed → process killed
  → gRPC never gets to its timeout
```

The 100ms delay is critical: it lets the app's own termination handlers run
and save state before we force-kill. Without it, timer state was lost on restart.
