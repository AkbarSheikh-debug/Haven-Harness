const OSC = /\u001b\][\s\S]*?(?:\u0007|\u001b\\|$)/g;
const CSI = /\u001b\[[0-?]*[ -/]*[@-~]/g;
const OTHER_ESCAPE = /\u001b[\s\S]?/g;
const C1_OSC = /\u009d[\s\S]*?(?:\u0007|\u009c|$)/g;
const CONTROL = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g;
const BIDI = /[‎‏؜‪-‮⁦-⁩]/g;
const ZERO_WIDTH = /[​-‍⁠﻿]/g;
const TAG_CHARACTERS = /[\u{e0000}-\u{e007f}]/gu;

/**
 * Model text and tool output are attacker-reachable, and a terminal obeys what it is
 * sent: OSC 52 writes the clipboard, OSC 8 hides a link's target, and a carriage return
 * or bidi mark can make an approval read as something else. Every door prints through this.
 */
export function sanitizeForDisplay(text: string): string {
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

const HIDDEN = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u200e\u200f\u061c\u202a-\u202e\u2066-\u2069\u200b-\u200d\u2060\ufeff]|[\u{e0000}-\u{e007f}]/gu;

/**
 * For text a person must judge before saying yes, such as a file diff in an editor. Nothing is removed (stripping would
 * show them text that differs from what runs); a control, bidi, zero-width or tag character is written out as a visible
 * `\u{...}` escape. Newlines, tabs and carriage returns stay so the text can still be compared line by line.
 */
export function revealHidden(text: string): string {
  return text.replace(HIDDEN, (char) => '\\u{' + (char.codePointAt(0) ?? 0).toString(16) + '}');
}
