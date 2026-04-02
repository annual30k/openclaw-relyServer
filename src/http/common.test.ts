import assert from "node:assert/strict";
import test from "node:test";
import { decodePathSegment, hostCommandErrorResponse, parseStringRecord } from "./common.js";

test("http common helpers parse records and decode path segments", () => {
  assert.equal(decodePathSegment("backup%2F123"), "backup/123");
  assert.equal(decodePathSegment("%E0%A4%A"), "%E0%A4%A");
  assert.deepEqual(parseStringRecord({ a: "1", b: "two" }), { a: "1", b: "two" });
  assert.equal(parseStringRecord({ a: "1", b: 2 }), undefined);
});

test("http common helpers map host command errors", () => {
  assert.deepEqual(hostCommandErrorResponse(new Error("gateway_offline: down")), {
    status: 503,
    body: { error: "gateway_offline" },
  });
  assert.deepEqual(hostCommandErrorResponse("skill_not_found"), {
    status: 404,
    body: { error: "skill_not_found" },
  });
});
