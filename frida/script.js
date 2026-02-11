
console.log("--- Frida ---");

function setupFinalHooks() {
    var mainModule = Process.getModuleByName("Flow");

    // We'll target the two high-level roots that manage the subscription state.
    // If we patch these, the whole app should stay Pro.
    // NOTE: These offsets are specific to the Flow binary as of v1.x (App Store).
    // They will change on any app update — re-run diag.js to find new offsets.
    var roots = [
        { off: 0x36274, name: "Root Manager A" },
        { off: 0xea9f4, name: "Root Manager B" }
    ];

    roots.forEach(function (r) {
        var addr = mainModule.base.add(r.off);
        try {
            // Attempt to hook the start. If ea9f4 fails, we'll try ea9f8.
            Interceptor.attach(addr, {
                onLeave: function (retval) {
                    if (retval.toInt32() === 0 || retval.toInt32() === 1) {
                        console.log("[Root] " + r.name + " (Flow!" + r.off.toString(16) + ") returned " + retval.toInt32() + " -> Forcing Pro");
                        retval.replace(ptr("0x1"));
                    }
                }
            });
        } catch (e) {
            console.log("[!] Error hooking " + r.name + " at start. Trying offset +4...");
            try {
                Interceptor.attach(addr.add(4), {
                    onLeave: function (retval) {
                        retval.replace(ptr("0x1"));
                    }
                });
            } catch (e2) {
                console.log("[!!] Failed both attempts for " + r.name);
            }
        }
    });

    // 2. UserDefaults - safety net
    var NSUserDefaults = ObjC.classes.NSUserDefaults;
    if (NSUserDefaults) {
        var boolForKey = NSUserDefaults["- boolForKey:"];
        Interceptor.attach(boolForKey.implementation, {
            onEnter: function (args) {
                var key = new ObjC.Object(args[2]).toString();
                if (key === "isProSubscriptionActive") {
                    this.hit = true;
                }
            },
            onLeave: function (retval) {
                if (this.hit) {
                    retval.replace(ptr("0x1"));
                    this.hit = false;
                }
            }
        });
    }

    console.log("[*] Final Candidate Hooks active.");
    console.log("[*] TIP: If the app hangs on detach, use 'killall Flow' to reset.");
}

setTimeout(setupFinalHooks, 500);