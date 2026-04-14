/*
 * Osprey - a browser extension that protects you from malicious websites.
 * Copyright (C) 2026 Osprey Project (https://github.com/OspreyProject)
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
"use strict";

globalThis.OspreyProtectionResult = (() => {
    const definitions = Object.freeze([
        {key: 'KNOWN_SAFE', value: 'known_safe', messageKey: 'knownSafe'},
        {key: 'FAILED', value: 'failed', messageKey: 'failed'},
        {key: 'WAITING', value: 'waiting', messageKey: 'waiting'},
        {key: 'ALLOWED', value: 'allowed', messageKey: 'allowed'},
        {key: 'MALICIOUS', value: 'malicious', messageKey: 'malicious', blocking: true},
        {key: 'PHISHING', value: 'phishing', messageKey: 'phishing', blocking: true},
        {key: 'ADULT_CONTENT', value: 'adult_content', messageKey: 'adultContent', blocking: true},
    ]);

    const resultTypes = Object.freeze(Object.fromEntries(definitions.map(item => [item.key, item.value])));
    const messageKeys = Object.freeze(Object.fromEntries(definitions.map(item => [item.value, item.messageKey])));
    const blockingResults = new Set(definitions.filter(item => item.blocking).map(item => item.value));
    const validValues = new Set(definitions.map(item => item.value));

    const legacyMap = Object.freeze({
        '0': resultTypes.KNOWN_SAFE,
        '1': resultTypes.FAILED,
        '2': resultTypes.WAITING,
        '3': resultTypes.ALLOWED,
        '4': resultTypes.MALICIOUS,
        '5': resultTypes.PHISHING,
        '6': resultTypes.ADULT_CONTENT,
    });

    const resultAliases = Object.freeze({
        known_safe: resultTypes.KNOWN_SAFE,
        safe: resultTypes.KNOWN_SAFE,
        allowed: resultTypes.ALLOWED,
        malicious: resultTypes.MALICIOUS,
        phishing: resultTypes.PHISHING,
        adult_content: resultTypes.ADULT_CONTENT,
        adult: resultTypes.ADULT_CONTENT,
        failed: resultTypes.FAILED,
    });

    const normalize = value => {
        if (value == null || value === '') {
            return resultTypes.FAILED;
        }

        if (typeof value !== 'string') {
            console.warn('OspreyProtectionResult.normalize received a non-string result value', value);
            return resultTypes.FAILED;
        }

        if (validValues.has(value)) {
            return value;
        }

        if (!Object.hasOwn(legacyMap, value)) {
            console.warn(`OspreyProtectionResult.normalize received an unknown result '${value}'`);
        }
        return legacyMap[value] || resultTypes.FAILED;
    };

    const fromProviderString = value => {
        const normalized = String(value || '').toLowerCase();
        const resolved = resultAliases[normalized] || resultTypes.FAILED;

        if (resolved === resultTypes.FAILED && normalized.length > 0 && normalized !== 'failed') {
            console.warn(`OspreyProtectionResult could not map provider result '${value}', defaulting to FAILED`);
        }
        return resolved;
    };

    const create = ({url, result, origin, sourceUrl = '', providerName = ''}) => {
        const normalizedResult = normalize(result);

        return Object.freeze({
            url,
            result: normalizedResult,
            origin,
            sourceUrl,
            providerName,
            isBlocking: blockingResults.has(normalizedResult),
        });
    };

    // Public API
    return Object.freeze({
        resultTypes,
        messageKeys,
        blockingResults,
        Origin: Object.freeze({
            UNKNOWN: 'unknown'
        }),
        normalize,
        fromProviderString,
        create,
    });
})();
