import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseHsts } from '../src/index.js';

test('parses a full well-formed header', () => {
  const p = parseHsts('max-age=63072000; includeSubDomains; preload');
  assert.equal(p.maxAge, 63072000);
  assert.equal(p.includeSubDomains, true);
  assert.equal(p.preload, true);
  assert.equal(p.valid, true);
});

test('parses max-age alone', () => {
  const p = parseHsts('max-age=31536000');
  assert.equal(p.maxAge, 31536000);
  assert.equal(p.includeSubDomains, false);
  assert.equal(p.preload, false);
  assert.equal(p.valid, true);
});

test('directive names are case-insensitive', () => {
  const p = parseHsts('MAX-AGE=100; INCLUDESUBDOMAINS; PRELOAD');
  assert.equal(p.maxAge, 100);
  assert.equal(p.includeSubDomains, true);
  assert.equal(p.preload, true);
  assert.equal(p.valid, true);
});

test('mixed-case directive names', () => {
  const p = parseHsts('Max-Age=5; includeSubDomains; Preload');
  assert.equal(p.maxAge, 5);
  assert.equal(p.includeSubDomains, true);
  assert.equal(p.preload, true);
});

test('tolerates whitespace around directives', () => {
  const p = parseHsts('  max-age = 7  ;  includeSubDomains  ;  preload  ');
  assert.equal(p.maxAge, 7);
  assert.equal(p.includeSubDomains, true);
  assert.equal(p.preload, true);
  assert.equal(p.valid, true);
});

test('empty string is invalid', () => {
  const p = parseHsts('');
  assert.equal(p.maxAge, null);
  assert.equal(p.includeSubDomains, false);
  assert.equal(p.preload, false);
  assert.equal(p.valid, false);
});

test('whitespace-only string is invalid', () => {
  const p = parseHsts('   \t  ');
  assert.equal(p.valid, false);
});

test('non-string input is invalid', () => {
  // @ts-expect-error — deliberately passing the wrong type.
  const p = parseHsts(12345);
  assert.equal(p.valid, false);
});

test('max-age with negative value is invalid', () => {
  const p = parseHsts('max-age=-1');
  assert.equal(p.valid, false);
  assert.equal(p.maxAge, null);
});

test('max-age with non-numeric value is invalid', () => {
  const p = parseHsts('max-age=abc');
  assert.equal(p.valid, false);
  assert.equal(p.maxAge, null);
});

test('max-age with scientific notation is invalid', () => {
  const p = parseHsts('max-age=1e3');
  assert.equal(p.valid, false);
});

test('max-age with leading plus is invalid', () => {
  // RFC 6797 grammar is 1*DIGIT, no sign prefix.
  const p = parseHsts('max-age=+1');
  assert.equal(p.valid, false);
});

test('max-age with leading zeros still parses to the correct number', () => {
  const p = parseHsts('max-age=00042');
  assert.equal(p.maxAge, 42);
  assert.equal(p.valid, true);
});

test('last max-age directive wins when duplicated', () => {
  const p = parseHsts('max-age=10; max-age=20; max-age=30');
  assert.equal(p.maxAge, 30);
  assert.equal(p.valid, true);
});

test('duplicate max-age with a malformed last entry leaves maxAge null', () => {
  // The malformed entry wins (it is the last), and we mark it invalid.
  const p = parseHsts('max-age=10; max-age=bogus');
  assert.equal(p.maxAge, null);
  assert.equal(p.valid, false);
});

test('unknown directives are ignored, not fatal', () => {
  const p = parseHsts('max-age=60; report-uri=/hsts; custom=thing');
  assert.equal(p.maxAge, 60);
  assert.equal(p.valid, true);
});

test('includeSubDomains honoured even if given a value', () => {
  // Forgiving interpretation: "includeSubDomains=true" still sets the flag.
  const p = parseHsts('max-age=60; includeSubDomains=true');
  assert.equal(p.includeSubDomains, true);
});

test('stray semicolons are tolerated', () => {
  const p = parseHsts('max-age=60;;preload;');
  assert.equal(p.maxAge, 60);
  assert.equal(p.preload, true);
  assert.equal(p.valid, true);
});

test('large max-age value does not lose precision within safe integer range', () => {
  // Stay within Number.MAX_SAFE_INTEGER to avoid float-precision concerns.
  const safe = 2 ** 53 - 1;
  const p = parseHsts('max-age=' + safe);
  assert.equal(p.maxAge, safe);
});
