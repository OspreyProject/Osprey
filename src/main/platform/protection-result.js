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
        PHISHING: 'phishing',
        MALICIOUS: 'malicious',
        SUSPICIOUS: 'suspicious',
        NEWLY_REGISTERED: 'newly_registered',
        DYNAMIC_DNS: 'dynamic_dns',
    }));

    const messageKeys = Object.freeze(Object.assign(Object.create(null), {
        known_safe: 'knownSafe',
        failed: 'failed',
        waiting: 'waiting',
        allowed: 'allowed',
        phishing: 'phishing',
        malicious: 'malicious',
        suspicious: 'suspicious',
        newly_registered: 'newly_registered',
        dynamic_dns: 'dynamic_dns',
    }));

    const isBlockingMap = Object.assign(Object.create(null), {
        phishing: true,
        malicious: true,
        suspicious: true,
        newly_registered: true,
        dynamic_dns: true,
    });

    const blockingResults = Object.freeze(new Set([
        'phishing',
        'malicious',
        'suspicious',
        'newly_registered',
        'dynamic_dns',
    ]));

    const blockingSeverityOrder = Object.freeze([
        'phishing',
        'malicious',
        'suspicious',
        'newly_registered',
        'dynamic_dns',
    ]);

    const severityRankByResult = Object.create(null);

    for (let i = 0, len = blockingSeverityOrder.length; i < len; i++) {
        severityRankByResult[blockingSeverityOrder[i]] = i;
    }

    const severityRank = value => {
        const rank = typeof value === 'string' ? severityRankByResult[value] : undefined;
        return rank === undefined ? Number.MAX_SAFE_INTEGER : rank;
    };

    const mostSevere = values => {
        let best = null;
        let bestRank = Number.MAX_SAFE_INTEGER;

        if (values) {
            for (const value of values) {
                const rank = severityRankByResult[value];

                if (rank !== undefined && rank < bestRank) {
                    bestRank = rank;
                    best = value;
                }
            }
        }
        return best;
    };

    const legacyMap = Object.assign(Object.create(null), {
        '0': 'known_safe',
        '1': 'failed',
        '2': 'waiting',
        '3': 'allowed',
        '4': 'malicious',
        '5': 'phishing',
        '6': 'suspicious',
        '7': 'newly_registered',
        '8': 'dynamic_dns',
    });

    const resultAliases = Object.assign(Object.create(null), {
        known_safe: 'known_safe',
        failed: 'failed',
        allowed: 'allowed',
        malicious: 'malicious',
        phishing: 'phishing',
        suspicious: 'suspicious',
        newly_registered: 'newly_registered',
        dynamic_dns: 'dynamic_dns',
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
        blockingSeverityOrder,
        severityRank,
        mostSevere,
        Origin: Object.freeze({
            UNKNOWN: 'unknown',
        }),
        normalize,
        fromProviderString,
        create,
    });
})();
