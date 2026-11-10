import { test } from "node:test";
import assert from "node:assert/strict";
import { cookie, defang, fragmentToken, route, splitTokens } from "./text.ts";

test("splitTokens finds tokens and keeps the rest", () => {
  assert.deepEqual(splitTokens("a [[IP_INTERNAL_3]] b [[USER_12]]"), [
    { text: "a ", token: false },
    { text: "[[IP_INTERNAL_3]]", token: true },
    { text: " b ", token: false },
    { text: "[[USER_12]]", token: true },
  ]);
  assert.deepEqual(splitTokens("[[not a token]]"), [{ text: "[[not a token]]", token: false }]);
});

test("defang breaks http and https links", () => {
  assert.equal(defang("see https://c2.example.org/x and HTTP://a.example"), "see hxxps://c2.example.org/x and hxxp://a.example");
});

test("cookie, route and fragment token", () => {
  assert.equal(cookie("a=1; sudare_csrf=xyz=; b=2", "sudare_csrf"), "xyz=");
  assert.equal(cookie("a=1", "sudare_csrf"), "");
  assert.deepEqual(route("#/a/abc123"), ["a", "abc123"]);
  assert.deepEqual(route(""), []);
  assert.equal(fragmentToken("#token=abcdefghijklmnopqrst"), "abcdefghijklmnopqrst");
  assert.equal(fragmentToken("#token=short"), null);
  assert.equal(fragmentToken("#token=abcdefghijklmnop<script>"), null);
});
