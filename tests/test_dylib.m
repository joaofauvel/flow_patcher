//
//  test_dylib.m — Test harness for FlowPatch.dylib
//
//  Loads the dylib via dlopen, then verifies each hook against real
//  NSUserDefaults / NSJSONSerialization. Prints TAP-style output.
//
//  Usage: clang -framework Foundation -o test_dylib test_dylib.m && ./test_dylib libpath
//

#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <objc/runtime.h>

static int pass_count = 0;
static int fail_count = 0;
static int test_num = 0;

#define OK(cond, desc) do { \
    test_num++; \
    if (cond) { pass_count++; printf("ok %d - %s\n", test_num, desc); } \
    else { fail_count++; printf("not ok %d - %s\n", test_num, desc); } \
} while(0)

static NSString * const PRO_KEY = @"isProSubscriptionActive";

// Sample RevenueCat subscriber JSON (no entitlements)
static NSData *sampleSubscriberJSON(void) {
    NSDictionary *json = @{
        @"request_date": @"2024-06-01T00:00:00Z",
        @"subscriber": @{
            @"first_seen": @"2024-01-01T00:00:00Z",
            @"entitlements": @{},
            @"subscriptions": @{},
            @"non_subscriptions": @{},
        },
    };
    return [NSJSONSerialization dataWithJSONObject:json options:0 error:nil];
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc < 2) {
            fprintf(stderr, "Usage: %s <path-to-FlowPatch.dylib>\n", argv[0]);
            return 2;
        }

        // Use an isolated suite so we don't pollute real prefs
        NSString *suite = @"com.test.flowpatch.harness";
        NSUserDefaults *ud = [[NSUserDefaults alloc] initWithSuiteName:suite];
        [ud removePersistentDomainForName:suite];  // clean slate

        // ── Pre-load baseline ──
        [ud setBool:NO forKey:PRO_KEY];
        [ud synchronize];
        BOOL preBool = [ud boolForKey:PRO_KEY];
        OK(preBool == NO, "baseline: boolForKey returns NO before dylib load");

        // ── Load dylib ──
        void *handle = dlopen(argv[1], RTLD_NOW);
        OK(handle != NULL, "dlopen succeeds");
        if (!handle) {
            printf("# dlopen error: %s\n", dlerror());
            printf("1..%d\n", test_num);
            return 1;
        }

        // ── boolForKey: always returns YES for pro key ──
        BOOL result = [ud boolForKey:PRO_KEY];
        OK(result == YES, "boolForKey: returns YES for isProSubscriptionActive");

        // Non-pro key should pass through normally
        [ud setBool:NO forKey:@"some.other.key"];
        OK([ud boolForKey:@"some.other.key"] == NO,
           "boolForKey: passes through for non-pro keys");

        // ── setBool:forKey: forces YES ──
        [ud setBool:NO forKey:PRO_KEY];
        // The hook should have forced it to YES
        id raw = [ud objectForKey:PRO_KEY];
        // objectForKey hook won't modify this (not purchaserInfo),
        // so we read the actual stored value
        OK([raw boolValue] == YES,
           "setBool:forKey: forces YES even when NO is written");

        // ── setObject:forKey: with purchaserInfo ──
        NSData *emptySubscriber = sampleSubscriberJSON();
        NSString *cacheKey = @"com.revenuecat.userdefaults.purchaserInfo.test123";
        [ud setObject:emptySubscriber forKey:cacheKey];

        NSData *stored = [[NSUserDefaults alloc] initWithSuiteName:suite]
            ? [ud objectForKey:cacheKey] : nil;
        // The objectForKey hook should also inject pro on read
        if (stored && [stored isKindOfClass:[NSData class]]) {
            NSDictionary *json = [NSJSONSerialization JSONObjectWithData:stored
                options:0 error:nil];
            NSDictionary *ents = json[@"subscriber"][@"entitlements"];
            OK(ents[@"pro"] != nil,
               "purchaserInfo read: has injected pro entitlement");

            NSDictionary *subs = json[@"subscriber"][@"subscriptions"];
            OK(subs[@"design.yugen.Flow.Lifetime"] != nil,
               "purchaserInfo read: has Lifetime subscription");

            // Verify entitlement shape
            NSDictionary *proEnt = ents[@"pro"];
            OK([proEnt[@"product_identifier"]
                isEqualToString:@"design.yugen.Flow.Lifetime"],
               "pro entitlement: product_identifier is correct");
            OK(proEnt[@"expires_date"] == [NSNull null],
               "pro entitlement: expires_date is null (lifetime)");
        } else {
            OK(NO, "purchaserInfo read: returned NSData");
            OK(NO, "purchaserInfo read: skipping sub-checks");
            OK(NO, "purchaserInfo read: skipping sub-checks");
            OK(NO, "purchaserInfo read: skipping sub-checks");
        }

        // ── removeObjectForKey: blocks pro key ──
        [ud removeObjectForKey:PRO_KEY];
        OK([ud boolForKey:PRO_KEY] == YES,
           "removeObjectForKey: blocked for pro key (still YES)");

        // Non-pro keys should be removable
        [ud setObject:@"test" forKey:@"temp.key"];
        [ud removeObjectForKey:@"temp.key"];
        OK([ud objectForKey:@"temp.key"] == nil,
           "removeObjectForKey: allowed for non-pro keys");

        // ── objectForKey: passes through for normal keys ──
        [ud setObject:@42 forKey:@"normal.integer"];
        id val = [ud objectForKey:@"normal.integer"];
        OK([val integerValue] == 42,
           "objectForKey: passes through for normal keys");

        // ── Cleanup ──
        [ud removePersistentDomainForName:suite];

        printf("1..%d\n", test_num);
        printf("# %d passed, %d failed\n", pass_count, fail_count);

        dlclose(handle);
        return fail_count > 0 ? 1 : 0;
    }
}
