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
