//
//  FlowPatch.dylib — Runtime hooks for Flow.app
//
//  Hooks:
//  1. UserDefaults: force isProSubscriptionActive = YES
//  2. RevenueCat: inject fake Lifetime entitlement into purchaserInfo cache
//     on both reads (objectForKey:) and writes (setObject:forKey:)
//  3. CoreData: enable history tracking to prevent read-only mode
//  4. Firebase: disable analytics and telemetry (deferred until app launch)
//  5. Clean shutdown: let app save state, then force exit to avoid gRPC hang
//

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <CoreData/CoreData.h>

#define LOG(fmt, ...) NSLog(@"[FlowPatch] " fmt, ##__VA_ARGS__)

static NSString * const PRO_KEY = @"isProSubscriptionActive";

static IMP orig_boolForKey;
static IMP orig_objectForKey;
static IMP orig_setBoolForKey;
static IMP orig_setObjectForKey;
static IMP orig_removeObjectForKey;
static IMP orig_loadStores;

// ─── RevenueCat: inject pro entitlement into cached subscriber JSON ─────────

static NSData *injectProEntitlement(NSData *data) {
    if (!data || ![data isKindOfClass:[NSData class]]) return data;

    NSError *err = nil;
    NSMutableDictionary *json = [NSJSONSerialization JSONObjectWithData:data
        options:NSJSONReadingMutableContainers error:&err];
    if (!json || err) return data;

    NSMutableDictionary *subscriber = json[@"subscriber"];
    if (!subscriber) return data;

    if (!subscriber[@"entitlements"])
        subscriber[@"entitlements"] = [NSMutableDictionary new];
    subscriber[@"entitlements"][@"pro"] = @{
        @"expires_date":        [NSNull null],
        @"product_identifier":  @"design.yugen.Flow.Lifetime",
        @"purchase_date":       @"2024-01-01T00:00:00Z",
    };

    if (!subscriber[@"subscriptions"])
        subscriber[@"subscriptions"] = [NSMutableDictionary new];
    subscriber[@"subscriptions"][@"design.yugen.Flow.Lifetime"] = @{
        @"billing_issues_detected_at": [NSNull null],
        @"expires_date":               [NSNull null],
        @"is_sandbox":                 @NO,
        @"original_purchase_date":     @"2024-01-01T00:00:00Z",
        @"period_type":                @"normal",
        @"purchase_date":              @"2024-01-01T00:00:00Z",
        @"store":                      @"app_store",
        @"unsubscribe_detected_at":    [NSNull null],
    };

    NSData *modified = [NSJSONSerialization dataWithJSONObject:json options:0 error:&err];
    return modified ?: data;
}

// ─── UserDefaults hooks ─────────────────────────────────────────────────────

static BOOL hooked_boolForKey(id self, SEL _cmd, NSString *key) {
    if ([key isEqualToString:PRO_KEY]) return YES;
    return ((BOOL(*)(id, SEL, id))orig_boolForKey)(self, _cmd, key);
}

// Intercept reads of purchaserInfo — inject pro entitlement before the SDK
// parses it, so the very first subscription check sees an active subscription.
static id hooked_objectForKey(id self, SEL _cmd, NSString *key) {
    id value = ((id(*)(id, SEL, id))orig_objectForKey)(self, _cmd, key);
    if (value && [key isKindOfClass:[NSString class]] &&
        [key containsString:@"purchaserInfo"] &&
        [value isKindOfClass:[NSData class]]) {
        return injectProEntitlement(value);
    }
    return value;
}

static void hooked_setBoolForKey(id self, SEL _cmd, BOOL value, NSString *key) {
    if ([key isEqualToString:PRO_KEY]) value = YES;
    ((void(*)(id, SEL, BOOL, id))orig_setBoolForKey)(self, _cmd, value, key);
}

static void hooked_setObjectForKey(id self, SEL _cmd, id value, NSString *key) {
    if ([key isEqualToString:PRO_KEY]) {
        value = @YES;
    } else if ([key containsString:@"purchaserInfo"] && [value isKindOfClass:[NSData class]]) {
        value = injectProEntitlement(value);
    }
    ((void(*)(id, SEL, id, id))orig_setObjectForKey)(self, _cmd, value, key);
}

static void hooked_removeObjectForKey(id self, SEL _cmd, NSString *key) {
    if ([key isEqualToString:PRO_KEY]) return;
    ((void(*)(id, SEL, id))orig_removeObjectForKey)(self, _cmd, key);
}

// ─── RevenueCat entitlement hook ────────────────────────────────────────────

// No orig IMP saved — intentionally irreversible one-way override.
static BOOL hooked_isActive(id self, SEL _cmd) { return YES; }

// ─── Analytics: no-op stub ──────────────────────────────────────────────────

// No orig IMP saved — intentionally irreversible; these are pure blockers.
static void hooked_noop(id self, SEL _cmd, ...) {}

// ─── CoreData: enable history tracking to prevent read-only mode ────────────

static void hooked_loadStores(id self, SEL _cmd,
        void (^completion)(NSPersistentStoreDescription *, NSError *)) {
    for (NSPersistentStoreDescription *desc in
            [(NSPersistentContainer *)self persistentStoreDescriptions]) {
        [desc setOption:@YES forKey:NSPersistentHistoryTrackingKey];
        [desc setOption:@YES forKey:NSPersistentStoreRemoteChangeNotificationPostOptionKey];
    }
    ((void(*)(id, SEL, id))orig_loadStores)(self, _cmd, completion);
}

// ─── Helper: swizzle a method if class and selector exist ───────────────────

// Returns int (0 or 1) rather than BOOL so callers can sum results to count
// how many hooks were successfully installed.
static int hookMethod(const char *className, const char *selName, IMP replacement,
                      BOOL classMethod) {
    Class cls = NSClassFromString(@(className));
    if (!cls) return 0;
    SEL sel = sel_registerName(selName);
    Method m = classMethod
        ? class_getClassMethod(cls, sel)
        : class_getInstanceMethod(cls, sel);
    if (!m) return 0;
    method_setImplementation(m, replacement);
    return 1;
}

// ─── Deferred: install analytics hooks after all frameworks are loaded ──────

static void installAnalyticsHooks(void) {
    int blocked = 0;
    // Firebase event logging
    blocked += hookMethod("FIRAnalytics",              "logEventWithName:parameters:",        (IMP)hooked_noop,  YES);
    blocked += hookMethod("FIRAnalytics",              "setUserPropertyString:forName:",       (IMP)hooked_noop,  YES);
    blocked += hookMethod("FIRAnalytics",              "setScreenName:screenClass:",           (IMP)hooked_noop,  YES);
    blocked += hookMethod("FIRAnalytics",              "setAnalyticsCollectionEnabled:",       (IMP)hooked_noop,  YES);
    // Firebase analytics configuration
    blocked += hookMethod("FIRAnalyticsConfiguration", "setAnalyticsCollectionEnabled:",       (IMP)hooked_noop,  NO);
    blocked += hookMethod("FIRAnalyticsConfiguration", "postNotificationForConsentUpdate:",    (IMP)hooked_noop,  NO);
    // Heartbeat (usage telemetry)
    blocked += hookMethod("FIRHeartbeatLogger",        "log:",                                (IMP)hooked_noop,  NO);
    blocked += hookMethod("FIRHeartbeatLogger",        "flushHeartbeatsIntoPayload",           (IMP)hooked_noop,  NO);
    // Google Data Transport (gRPC telemetry)
    blocked += hookMethod("GDTCORTransport",           "sendDataEvent:onComplete:",            (IMP)hooked_noop,  NO);
    blocked += hookMethod("GDTCORTransport",           "sendTelemetryEvent:onComplete:",       (IMP)hooked_noop,  NO);
    blocked += hookMethod("GDTCORFlatFileStorage",     "storeEvent:onComplete:",               (IMP)hooked_noop,  NO);
    if (blocked) LOG(@"Blocked %d analytics entry points", blocked);
}

// ─── Constructor ────────────────────────────────────────────────────────────

__attribute__((constructor))
static void patch_init(void) {
    LOG(@"=== FlowPatch loaded ===");

    // On termination: let the app save its state (timer, phase, etc.),
    // then force exit after 100ms to avoid the gRPC 10-second hang.
    [[NSNotificationCenter defaultCenter]
        addObserverForName:@"NSApplicationWillTerminateNotification"
        object:nil queue:nil usingBlock:^(NSNotification *n) {
            dispatch_after(
                dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.1 * NSEC_PER_SEC)),
                dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
                    [[NSUserDefaults standardUserDefaults] synchronize];
                    _exit(0);
                });
        }];

    // Defer analytics hooks until after FIRApp.configure has run
    [[NSNotificationCenter defaultCenter]
        addObserverForName:@"NSApplicationDidFinishLaunchingNotification"
        object:nil queue:nil usingBlock:^(NSNotification *n) {
            installAnalyticsHooks();
        }];

    // ── UserDefaults ──
    Class defaults = [NSUserDefaults class];
    Method m;

#define SWIZZLE(sel, hook, orig) \
    m = class_getInstanceMethod(defaults, @selector(sel)); \
    orig = method_getImplementation(m); \
    method_setImplementation(m, (IMP)hook);

    SWIZZLE(boolForKey:,         hooked_boolForKey,        orig_boolForKey);
    SWIZZLE(objectForKey:,       hooked_objectForKey,      orig_objectForKey);
    SWIZZLE(setBool:forKey:,     hooked_setBoolForKey,     orig_setBoolForKey);
    SWIZZLE(setObject:forKey:,   hooked_setObjectForKey,   orig_setObjectForKey);
    SWIZZLE(removeObjectForKey:, hooked_removeObjectForKey, orig_removeObjectForKey);
#undef SWIZZLE

    // ── RevenueCat ──
    hookMethod("RCEntitlementInfo", "isActive", (IMP)hooked_isActive, NO);

    // ── CoreData ──
    Class container = [NSPersistentContainer class];
    m = class_getInstanceMethod(container,
            @selector(loadPersistentStoresWithCompletionHandler:));
    if (m) {
        orig_loadStores = method_getImplementation(m);
        method_setImplementation(m, (IMP)hooked_loadStores);
    }
    Class ckContainer = NSClassFromString(@"NSPersistentCloudKitContainer");
    if (ckContainer && ckContainer != container) {
        m = class_getInstanceMethod(ckContainer,
                @selector(loadPersistentStoresWithCompletionHandler:));
        if (m) method_setImplementation(m, (IMP)hooked_loadStores);
    }

    // ── Preemptive pro write ──
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    ((void(*)(id, SEL, BOOL, id))orig_setBoolForKey)(
        ud, @selector(setBool:forKey:), YES, PRO_KEY);

    LOG(@"=== Hooks active ===");
}
