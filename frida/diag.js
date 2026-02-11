
console.log("--- Frida Script: Patch Point Finder ---");

function findPatchPoints() {
    var mainModule = Process.getModuleByName("Flow");

    // From the stack traces, these are the return addresses after calling boolForKey:
    // (Frame #3 addresses). The actual `bl` instruction is 4 bytes before each.
    var callSites = [
        { retAddr: 0x35c9c, chain: "A" },
        { retAddr: 0x35e8c, chain: "A" },
        { retAddr: 0x37bc4, chain: "A" },
        { retAddr: 0xef2dc, chain: "B" },
        { retAddr: 0xef478, chain: "B" }
    ];

    console.log("=== Disassembly around boolForKey: call sites ===\n");

    callSites.forEach(function (cs) {
        var blAddr = mainModule.base.add(cs.retAddr - 4); // The BL is 4 bytes before the return addr
        console.log("--- Chain " + cs.chain + " | Call site at Flow!" + (cs.retAddr - 4).toString(16) + " ---");

        // Disassemble 10 instructions before and 10 after the bl
        var startAddr = blAddr.sub(10 * 4);
        for (var i = 0; i < 25; i++) {
            var addr = startAddr.add(i * 4);
            try {
                var ins = Instruction.parse(addr);
                var offset = addr.sub(mainModule.base);
                var marker = addr.equals(blAddr) ? " >>>" : "    ";
                console.log(marker + " " + offset.toString(16) + ": " + ins);
            } catch (e) { }
        }
        console.log("");
    });

    // Also find the function prologue for Controller D (0x35e58)
    console.log("=== Scanning for function prologue near 0x35e58 ===\n");
    var target = mainModule.base.add(0x35e58);
    for (var i = 256; i >= 0; i -= 4) {
        var addr = target.sub(i);
        try {
            var ins = Instruction.parse(addr);
            var offset = addr.sub(mainModule.base);
            // Look for stp x29, x30 or sub sp
            if (ins.toString().indexOf("x29, x30") !== -1 ||
                ins.toString().indexOf("sub sp") !== -1 ||
                ins.toString().indexOf("stp x2") !== -1) {
                console.log("  [PROLOGUE?] " + offset.toString(16) + ": " + ins);
            }
        } catch (e) { }
    }

    // Dump raw bytes at the file offset locations we tried to patch
    console.log("\n=== Raw bytes at patch targets ===\n");
    var targets = [
        { off: 0x35e58, name: "Controller D" },
        { off: 0x36274, name: "Root Manager A" },
        { off: 0xea9f4, name: "Root Manager B" }
    ];
    targets.forEach(function (t) {
        var addr = mainModule.base.add(t.off);
        var bytes = [];
        for (var b = 0; b < 8; b++) {
            bytes.push(("0" + addr.add(b).readU8().toString(16)).slice(-2));
        }
        var ins1 = Instruction.parse(addr);
        var ins2 = Instruction.parse(addr.add(4));
        console.log("[" + t.name + "] Flow!" + t.off.toString(16) + ": " + bytes.join(" ") + " | " + ins1 + " ; " + ins2);
    });
}

setTimeout(findPatchPoints, 500);
