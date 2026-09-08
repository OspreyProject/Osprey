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
        LOOKALIKE: 'lookalike',
        PARKED: 'parked',
        ADULT_CONTENT: 'adult_content',
        SEX_EDUCATION: 'sex_education',
        DATING: 'dating',
        GAMBLING: 'gambling',
        DRUGS: 'drugs',
        ALCOHOL_TOBACCO: 'alcohol_tobacco',
        WEAPONS: 'weapons',
        HATE_DISCRIMINATION: 'hate_discrimination',
        VIOLENCE_GORE: 'violence_gore',
        PIRACY: 'piracy',
        HACKING: 'hacking',
        SOCIAL_MEDIA: 'social_media',
        STREAMING_MEDIA: 'streaming_media',
        GAMES: 'games',
        CHAT_MESSAGING: 'chat_messaging',
        FILE_SHARING: 'file_sharing',
        SHOPPING_AUCTIONS: 'shopping_auctions',
        JOB_SEARCH: 'job_search',
        WEBMAIL: 'webmail',
        REMOTE_ACCESS: 'remote_access',
        AI_APPLICATIONS: 'ai_applications',
        CRYPTOCURRENCY: 'cryptocurrency',
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
        lookalike: 'lookalike',
        parked: 'parked',
        adult_content: 'adultContent',
        sex_education: 'sexEducation',
        dating: 'dating',
        gambling: 'gambling',
        drugs: 'drugs',
        alcohol_tobacco: 'alcoholTobacco',
        weapons: 'weapons',
        hate_discrimination: 'hateDiscrimination',
        violence_gore: 'violenceGore',
        piracy: 'piracy',
        hacking: 'hacking',
        social_media: 'socialMedia',
        streaming_media: 'streamingMedia',
        games: 'games',
        chat_messaging: 'chatMessaging',
        file_sharing: 'fileSharing',
        shopping_auctions: 'shoppingAuctions',
        job_search: 'jobSearch',
        webmail: 'webmail',
        remote_access: 'remoteAccess',
        ai_applications: 'aiApplications',
        cryptocurrency: 'cryptocurrency',
    }));

    const isBlockingMap = Object.assign(Object.create(null), {
        phishing: true,
        malicious: true,
        suspicious: true,
        newly_registered: true,
        dynamic_dns: true,
        lookalike: true,
        parked: true,
        adult_content: true,
        sex_education: true,
        dating: true,
        gambling: true,
        drugs: true,
        alcohol_tobacco: true,
        weapons: true,
        hate_discrimination: true,
        violence_gore: true,
        piracy: true,
        hacking: true,
        social_media: true,
        streaming_media: true,
        games: true,
        chat_messaging: true,
        file_sharing: true,
        shopping_auctions: true,
        job_search: true,
        webmail: true,
        remote_access: true,
        ai_applications: true,
        cryptocurrency: true,
    });

    const blockingResults = Object.freeze(new Set([
        'phishing',
        'malicious',
        'lookalike',
        'suspicious',
        'newly_registered',
        'dynamic_dns',
        'parked',
        'adult_content',
        'sex_education',
        'dating',
        'gambling',
        'drugs',
        'alcohol_tobacco',
        'weapons',
        'hate_discrimination',
        'violence_gore',
        'piracy',
        'hacking',
        'social_media',
        'streaming_media',
        'games',
        'chat_messaging',
        'file_sharing',
        'shopping_auctions',
        'job_search',
        'webmail',
        'remote_access',
        'ai_applications',
        'cryptocurrency',
    ]));

    const blockingSeverityOrder = Object.freeze([
        'phishing',
        'malicious',
        'suspicious',
        'newly_registered',
        'dynamic_dns',
        'parked',
        'adult_content',
        'sex_education',
        'dating',
        'gambling',
        'drugs',
        'alcohol_tobacco',
        'weapons',
        'hate_discrimination',
        'violence_gore',
        'piracy',
        'hacking',
        'social_media',
        'streaming_media',
        'games',
        'chat_messaging',
        'file_sharing',
        'shopping_auctions',
        'job_search',
        'webmail',
        'remote_access',
        'ai_applications',
        'cryptocurrency',
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
        '9': 'parked',
        '32': 'lookalike',
        '10': 'adult_content',
        '11': 'sex_education',
        '12': 'dating',
        '13': 'gambling',
        '14': 'drugs',
        '15': 'alcohol_tobacco',
        '16': 'weapons',
        '17': 'hate_discrimination',
        '18': 'violence_gore',
        '19': 'piracy',
        '20': 'hacking',
        '21': 'social_media',
        '22': 'streaming_media',
        '23': 'games',
        '24': 'chat_messaging',
        '25': 'file_sharing',
        '26': 'shopping_auctions',
        '27': 'job_search',
        '28': 'webmail',
        '29': 'remote_access',
        '30': 'ai_applications',
        '31': 'cryptocurrency',
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
        lookalike: 'lookalike',
        parked: 'parked',
        adult_content: 'adult_content',
        sex_education: 'sex_education',
        dating: 'dating',
        gambling: 'gambling',
        drugs: 'drugs',
        alcohol_tobacco: 'alcohol_tobacco',
        weapons: 'weapons',
        hate_discrimination: 'hate_discrimination',
        violence_gore: 'violence_gore',
        piracy: 'piracy',
        hacking: 'hacking',
        social_media: 'social_media',
        streaming_media: 'streaming_media',
        games: 'games',
        chat_messaging: 'chat_messaging',
        file_sharing: 'file_sharing',
        shopping_auctions: 'shopping_auctions',
        job_search: 'job_search',
        webmail: 'webmail',
        remote_access: 'remote_access',
        ai_applications: 'ai_applications',
        cryptocurrency: 'cryptocurrency',
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

    /**
     * Content policy categories: blockable when their provider toggle is on, but they are
     * organization policy blocks rather than security verdicts, and the warning page
     * renders them with policy copy instead of danger copy.
     */
    const contentCategoryResults = Object.freeze(new Set([
        'parked',
        'adult_content',
        'sex_education',
        'dating',
        'gambling',
        'drugs',
        'alcohol_tobacco',
        'weapons',
        'hate_discrimination',
        'violence_gore',
        'piracy',
        'hacking',
        'social_media',
        'streaming_media',
        'games',
        'chat_messaging',
        'file_sharing',
        'shopping_auctions',
        'job_search',
        'webmail',
        'remote_access',
        'ai_applications',
        'cryptocurrency',
    ]));

    const isContentCategory = value => contentCategoryResults.has(normalize(value));

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
        contentCategoryResults,
        isContentCategory,
        create,
    });
})();
