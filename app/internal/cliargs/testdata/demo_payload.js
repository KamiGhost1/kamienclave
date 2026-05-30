// Embedded by the demo subcommand. Exercised end-to-end against an
// in-process mock licence server.

log("[demo] payload running inside delator vm");

var data = [1, 2, 3, 4, 5];
var doubled = data.map(function (x) { return x * 2; });
log("[demo] doubled:", doubled.join(","));

log("[demo] env keys:", env.keys().join(",") || "(none)");

"payload finished cleanly";
