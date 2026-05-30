// Example payload for `delator local --file examples/hello.js`.
// Demonstrates the whitelisted host bridge.

log("delator local: payload start");
log("env.TZ =", env.get("TZ") || "(unset)");

var sum = 0;
for (var i = 1; i <= 10; i++) {
  sum += i;
}
log("sum(1..10) =", sum);

sleep(50); // gets capped by host MaxSleep
log("delator local: payload done");

// The completion value is what `local` prints as "result:".
"hello from delator payload";
