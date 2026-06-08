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
'use strict';

globalThis.OspreyProtectionResult = (() => {
    const resultTypes = Object.freeze(Object.assign(Object.create(null), {
        KNOWN_SAFE: 'known_safe',
        FAILED: 'failed',
        WAITING: 'waiting',
        ALLOWED: 'allowed',
        MALICIOUS: 'malicious',
        PHISHING: 'phishing',
        ADULT_CONTENT: 'adult_content',
    }));

    const messageKeys = Object.freeze(Object.assign(Object.create(null), {
        known_safe: 'knownSafe',
        failed: 'failed',
        waiting: 'waiting',
        allowed: 'allowed',
        malicious: 'malicious',
        phishing: 'phishing',
        adult_content: 'adultContent',
    }));

    const isBlockingMap = Object.assign(Object.create(null), {
        malicious: true,
        phishing: true,
        adult_content: true,
    });

    const blockingResults = Object.freeze(new Set(['malicious', 'phishing', 'adult_content']));

    const legacyMap = Object.assign(Object.create(null), {
        '0': 'known_safe',
        '1': 'failed',
        '2': 'waiting',
        '3': 'allowed',
        '4': 'malicious',
        '5': 'phishing',
        '6': 'adult_content',
    });

    const resultAliases = Object.assign(Object.create(null), {
        known_safe: 'known_safe',
        safe: 'known_safe',
        allowed: 'allowed',
        malicious: 'malicious',
        phishing: 'phishing',
        adult_content: 'adult_content',
        adult: 'adult_content',
        failed: 'failed',
    });

    const normalize = value => {
        if (!value) {
            return 'failed';
        }

        if (typeof value !== 'string') {
            console.warn('OspreyProtectionResult.normalize received a non-string result value', value);
            return 'failed';
        }

        if (messageKeys[value] !== undefined) {
            return value;
        }

        const legacy = legacyMap[value];

        if (legacy !== undefined) {
            return legacy;
        }

        console.warn(`OspreyProtectionResult.normalize received an unknown result '${value}'`);
        return 'failed';
    };

    const fromProviderString = value => {
        if (!value || typeof value !== 'string') {
            return 'failed';
        }

        let resolved = resultAliases[value];

        if (resolved !== undefined) {
            return resolved;
        }

        resolved = resultAliases[value.toLowerCase()];

        if (resolved !== undefined) {
            return resolved;
        }

        console.warn(`OspreyProtectionResult could not map provider result '${value}', defaulting to FAILED`);
        return 'failed';
    };

    class ProtectionResult {
        constructor(url, result, origin, isBlocking) {
            this.url = url;
            this.result = result;
            this.origin = origin;
            this.isBlocking = isBlocking;
            Object.freeze(this);
        }
    }

    const create = ({url, result, origin}) => {
        const normalizedResult = normalize(result);

        return new ProtectionResult(
            url,
            normalizedResult,
            origin,
            isBlockingMap[normalizedResult] === true,
        );
    };

    return Object.freeze({
        resultTypes,
        messageKeys,
        blockingResults,
        Origin: Object.freeze({
            UNKNOWN: 'unknown',
        }),
        normalize,
        fromProviderString,
        create,
    });
})();
