/**
 * Everything the agent sends is text from outside this extension. Two rules, and neither needs the agent to be honest:
 * text that is only read is stripped of what a terminal or a UI could obey, and text a person must judge (a diff) has
 * hidden characters written out as visible escapes, never removed, so it cannot read differently from what is written.
 */

const OSC = /\u001b\][\s\S]*?(?:\u0007|\u001b\\|$)/g;
const CSI = /\u001b\[[0-?]*[ -/]*[@-~]/g;
const OTHER_ESCAPE = /\u001b[\s\S]?/g;
const C1_OSC = /\u009d[\s\S]*?(?:\u0007|\u009c|$)/g;
const CONTROL = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g;
const BIDI = /[‎‏؜‪-‮⁦-⁩]/g;
const ZERO_WIDTH = /[​-‍⁠﻿]/g;
const TAG_CHARACTERS = /[\u{e0000}-\u{e007f}]/gu;
const HIDDEN = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f‎‏؜‪-‮⁦-⁩​-‍⁠﻿]|[\u{e0000}-\u{e007f}]/gu;

/** For text that is only read: terminal escapes, control characters and invisible marks are removed. */
export function sanitize(text: string): string {
  return text
    .replace(OSC, '')
    .replace(C1_OSC, '')
    .replace(CSI, '')
    .replace(OTHER_ESCAPE, '')
    .replace(CONTROL, '')
    .replace(BIDI, '')
    .replace(ZERO_WIDTH, '')
    .replace(TAG_CHARACTERS, '');
}

/** For text a person judges: nothing is removed; a hidden character becomes a visible `\u{...}` escape. */
export function revealHidden(text: string): string {
  return text.replace(HIDDEN, (char) => '\\u{' + (char.codePointAt(0) ?? 0).toString(16) + '}');
}

/** At most `max` characters, and whether anything was cut. */
export function cap(text: string, max: number): { text: string; cut: boolean } {
  return text.length > max ? { text: text.slice(0, max), cut: true } : { text, cut: false };
}
