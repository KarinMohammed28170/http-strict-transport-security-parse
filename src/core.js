/**
 * HSTS (HTTP Strict Transport Security) header parsing.
 *
 * A Strict-Transport-Security header has the shape:
 *   Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
 *
 * Per RFC 6797 §6.1 the directive names and the "max-age" token are
 * case-insensitive. We deliberately DO NOT treat the value of max-age as
 * case-insensitive — it is a decimal integer and must parse as one.
 *
 * Deliberately out of scope:
 *   - unknown directives are ignored, not rejected. A caching proxy on the
 *     path may append directives it understands and the spec forbids a
 *     parser from choking on extensions it does not recognise.
 *   - duplicate max-age directives: we keep the LAST one, matching RFC 6797
 *     §6.1's "last directive wins" semantics for repeated directives.
 */

/**
 * @typedef {Object} PolicyDirective
 * @property {number|null} maxAge      Seconds to remember the HSTS policy.
 *                                     null when the directive is absent or malformed.
 * @property {boolean} includeSubDomains True iff the directive appears with no value.
 * @property {boolean} preload          True iff the directive appears with no value.
 * @property {boolean} valid            False when the header is structurally invalid
 *                                     (e.g. empty, or max-age present but not a number).
 */

/**
 * Parse a Strict-Transport-Security header value into a structured policy.
 *
 * @param {string} headerValue
 * @returns {PolicyDirective}
 */
export function parseHsts(headerValue) {
  /** @type {PolicyDirective} */
  const result = {
    maxAge: null,
    includeSubDomains: false,
    preload: false,
    valid: true,
  };

  if (typeof headerValue !== 'string') {
    result.valid = false;
    return result;
  }

  // An entirely empty header is not a meaningful HSTS policy. Calling it
  // invalid lets a caller distinguish "header present but malformed" from
  // "header absent" when it already knows the absence.
  const trimmed = headerValue.trim();
  if (trimmed === '') {
    result.valid = false;
    return result;
  }

  // RFC 6797 splits on ';'. Whitespace around directives is insignificant,
  // so we trim each piece before looking at it.
  const pieces = trimmed.split(';');

  for (const piece of pieces) {
    const directive = piece.trim();
    if (directive === '') {
      // A stray semicolon ("a;;b") is harmless and explicitly tolerated.
      continue;
    }

    const eq = directive.indexOf('=');
    let namePart;
    let valuePart = '';
    if (eq === -1) {
      namePart = directive;
    } else {
      namePart = directive.slice(0, eq);
      valuePart = directive.slice(eq + 1);
    }

    const name = namePart.trim().toLowerCase();
    const value = valuePart.trim();

    if (name === 'max-age') {
      // max-age must be a non-negative integer of digits. We reject "-1",
      // "1e3", "+1", " 1 ", and any quoted form — the grammar in RFC 6797
      // §6.1 is "1*DIGIT".
      if (!/^[0-9]+$/.test(value)) {
        result.valid = false;
        result.maxAge = null;
        continue;
      }
      // Use Number rather than parseInt so that a leading-zero giant like
      // "0000000000000000000042" still parses correctly. The spec places
      // no upper bound; we trust the caller to handle unreasonable values.
      result.maxAge = Number(value);
    } else if (name === 'includesubdomains') {
      // The flag directives are defined as taking no value. If someone sends
      // "includeSubDomains=true" we still honour the flag — RFC 6797 parsers
      // are expected to be forgiving of obvious intent, and rejecting would
      // be more dangerous than accepting.
      result.includeSubDomains = true;
    } else if (name === 'preload') {
      result.preload = true;
    }
    // Unknown directives are ignored by design (see module docstring).
  }

  return result;
}
