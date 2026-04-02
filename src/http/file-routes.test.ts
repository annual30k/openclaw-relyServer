import assert from "node:assert/strict";
import test from "node:test";
import { buildAttachmentContentDisposition } from "./file-routes.js";

test("attachment content disposition encodes unicode filenames safely", () => {
  const header = buildAttachmentContentDisposition("PDF内容重构与故事化记忆_副本.pdf");

  assert.match(header, /^attachment; filename=".*"; filename\*=UTF-8''.*$/);
  assert.equal(/[^\x00-\x7F]/.test(header), false);
  assert.match(header, /filename=".*\.pdf"/);
  assert.match(header, /filename\*=UTF-8''PDF%E5%86%85%E5%AE%B9%E9%87%8D%E6%9E%84%E4%B8%8E%E6%95%85%E4%BA%8B%E5%8C%96%E8%AE%B0%E5%BF%86_%E5%89%AF%E6%9C%AC\.pdf/);
});
