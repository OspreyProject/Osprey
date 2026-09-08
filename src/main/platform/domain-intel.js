/*
 * Copyright (C) 2024-2026 Osprey Project LLC and contributors (https://osprey.ac)
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
'use strict';

/**
 * Pure, fully local domain intelligence: lookalike detection (bounded edit distance and
 * keyboard adjacency against protected domains), homograph detection (a practical UTS #39
 * confusable skeleton covering Latin, Cyrillic, Greek, and common digit and symbol
 * confusables), mixed-script labels, and a DGA-shape heuristic. Nothing here touches the
 * network; every function is deterministic on its inputs. Signals feed the navigation
 * pipeline: a protected-domain hit may block directly under block mode, everything else is
 * recorded to the local event log as a signal.
 */
globalThis.OspreyDomainIntel = (() => {
    // Confusable characters mapped to their Latin skeleton form (practical subset).
    const confusables = Object.freeze(Object.assign(Object.create(null), {
        '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p', '\u0441': 'c',
        '\u0443': 'y', '\u0445': 'x', '\u0456': 'i', '\u0458': 'j', '\u04bb': 'h',
        '\u0455': 's', '\u0491': 'r', '\u04cf': 'l', '\u051b': 'q', '\u051d': 'w', '\u0501': 'd',
        '\u03b1': 'a', '\u03bf': 'o', '\u03c1': 'p', '\u03c5': 'u', '\u03bd': 'v',
        '\u03ba': 'k', '\u03b9': 'i',
        '0': 'o', '1': 'l', '3': 'e', '5': 's', '7': 't',
        'vv': 'w', 'rn': 'm', 'cl': 'd',
    }));

    const multiConfusables = Object.freeze(['vv', 'rn', 'cl']);

    // QWERTY adjacency for the keyboard-slip distance discount.
    const adjacent = Object.freeze(Object.assign(Object.create(null), {
        q: 'wa', w: 'qes', e: 'wrd', r: 'etf', t: 'ryg', y: 'tuh', u: 'yij', i: 'uok',
        o: 'ipl', p: 'ol', a: 'qsz', s: 'awdx', d: 'sefc', f: 'drgv', g: 'fthb',
        h: 'gyjn', j: 'hukm', k: 'jil', l: 'kop', z: 'asx', x: 'zsdc', c: 'xdfv',
        v: 'cfgb', b: 'vghn', n: 'bhjm', m: 'njk',
    }));

    const skeleton = value => {
        let out = String(value || '').toLowerCase();

        for (const pair of multiConfusables) {
            out = out.split(pair).join(confusables[pair]);
        }

        let result = '';

        for (const ch of out) {
            result += confusables[ch] || ch;
        }
        return result;
    };

    const editDistance = (a, b, cap) => {
        if (Math.abs(a.length - b.length) > cap) {
            return cap + 1;
        }

        let prev2 = null;
        let prev = Array.from({length: b.length + 1}, (_ignored, i) => i);

        for (let i = 1; i <= a.length; i++) {
            const row = [i];
            let best = i;

            for (let j = 1; j <= b.length; j++) {
                let cost = a[i - 1] === b[j - 1] ? 0 : 1;

                if (cost === 1 && adjacent[a[i - 1]]?.includes(b[j - 1])) {
                    cost = 0.5;
                }
                row[j] = Math.min(prev[j] + 1, row[j - 1] + 1, prev[j - 1] + cost);

                // Damerau adjacent transposition: swapping two neighbors is one typo.
                if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
                    row[j] = Math.min(row[j], prev2[j - 2] + 1);
                }

                if (row[j] < best) {
                    best = row[j];
                }
            }

            if (best > cap) {
                return cap + 1;
            }
            prev2 = prev;
            prev = row;
        }
        return prev[b.length];
    };

    const registrable = hostname => {
        const labels = String(hostname || '').toLowerCase().replace(/\.$/, '').split('.');

        if (labels.length <= 2) {
            return labels.join('.');
        }

        // Two-label public suffixes (co.uk style) keep three labels; everything else two.
        const last2 = labels.slice(-2).join('.');
        const twoLevel = /^(co|com|org|net|ac|gov|edu)\.[a-z]{2}$/.test(last2);
        return labels.slice(twoLevel ? -3 : -2).join('.');
    };

    const hasMixedScript = label => {
        const latin = /[a-z]/.test(label);
        const cyrillic = /[\u0400-\u04ff]/.test(label);
        const greek = /[\u0370-\u03ff]/.test(label);
        return (latin && cyrillic) || (latin && greek) || (cyrillic && greek);
    };

    const decodePunycodeLabel = input => {
        // RFC 3492 decoding for one label without the xn-- prefix.
        const output = [];
        let n = 128;
        let i = 0;
        let bias = 72;
        const basic = input.lastIndexOf('-');

        for (let k = 0; k < basic; k++) {
            output.push(input.codePointAt(k));
        }

        let index = basic > 0 ? basic + 1 : 0;

        while (index < input.length) {
            const oldi = i;
            let w = 1;

            for (let k = 36; ; k += 36) {
                const code = input.codePointAt(index++);
                const digit = code >= 97 ? code - 97 : code >= 48 && code <= 57 ? code - 22 : 99;

                if (digit >= 36) {
                    return null;
                }

                i += digit * w;
                const t = k <= bias ? 1 : k >= bias + 26 ? 26 : k - bias;

                if (digit < t) {
                    break;
                }

                w *= 36 - t;
            }

            const len = output.length + 1;
            let delta = i - oldi;
            delta = oldi === 0 ? Math.floor(delta / 700) : Math.floor(delta / 2);
            delta += Math.floor(delta / len);
            let k2 = 0;

            while (delta > 455) {
                delta = Math.floor(delta / 35);
                k2 += 36;
            }

            bias = k2 + Math.floor(36 * delta / (delta + 38));
            n += Math.floor(i / len);
            i %= len;
            output.splice(i, 0, n);
            i++;
        }
        return String.fromCodePoint(...output);
    };

    const decodeHost = hostname => {
        const lower = String(hostname || '').toLowerCase();
        return lower.split('.').map(label => {
            if (!label.startsWith('xn--')) {
                return label;
            }

            const decoded = decodePunycodeLabel(label.slice(4));
            return decoded === null ? label : decoded;
        }).join('.');
    };

    /**
     * Shannon-entropy and shape heuristic for DGA-looking hostnames; a score from 0 to 1.
     */
    const dgaScore = hostname => {
        const label = registrable(hostname).split('.')[0] || '';

        if (label.length < 8) {
            return 0;
        }

        const counts = Object.create(null);

        for (const ch of label) {
            counts[ch] = (counts[ch] || 0) + 1;
        }

        let entropy = 0;

        for (const ch in counts) {
            const p = counts[ch] / label.length;
            entropy -= p * Math.log2(p);
        }

        const digits = (label.match(/[0-9]/g) || []).length / label.length;
        const vowels = (label.match(/[aeiou]/g) || []).length / label.length;
        const consonantRun = (new RegExp(/[bcdfghjklmnpqrstvwxz]{5,}/).exec(label) || [''])[0].length;

        let score = 0;
        score += entropy > 3.4 ? 0.4 : entropy > 3.0 ? 0.2 : 0;
        score += digits > 0.3 ? 0.2 : 0;
        score += vowels < 0.15 ? 0.2 : 0;
        score += consonantRun >= 5 ? 0.2 : 0;
        return Math.min(1, score);
    };

    /**
     * Analyzes a hostname against the protected-domain list. Returns null when nothing is
     * noteworthy, or {kind, target, detail} where kind is 'protected_lookalike' (blockable
     * under block mode), 'mixed_script', or 'dga'.
     */
    const analyze = (hostname, protectedDomains) => {
        const decoded = decodeHost(hostname);
        const host = registrable(decoded);
        const hostSkeleton = skeleton(host);
        const list = Array.isArray(protectedDomains) ? protectedDomains : [];

        for (const raw of list) {
            const target = registrable(String(raw || '').toLowerCase());

            if (!target) {
                continue;
            }

            if (target === host) {
                return null; // The protected domain itself is never a lookalike.
            }

            const targetSkeleton = skeleton(target);

            if (hostSkeleton === targetSkeleton) {
                return {kind: 'protected_lookalike', target, detail: 'homograph'};
            }

            const base = host.split('.')[0];
            const targetBase = target.split('.')[0];
            const cap = targetBase.length >= 9 ? 2 : 1;

            if (base !== targetBase && editDistance(skeleton(base), skeleton(targetBase), cap) <= cap) {
                return {kind: 'protected_lookalike', target, detail: 'edit_distance'};
            }
        }

        for (const label of decoded.split('.')) {
            if (hasMixedScript(label)) {
                return {kind: 'mixed_script', target: '', detail: label};
            }
        }

        const score = dgaScore(decoded);
        return score >= 0.6 ? {kind: 'dga', target: '', detail: String(score)} : null;
    };

    return Object.freeze({
        analyze,
        skeleton,
        editDistance,
        registrable,
        dgaScore,
    });
})();
