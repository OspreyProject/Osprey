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

{
    // Defined before the class so the constructor can reference them for validation
    const _ResultType = Object.freeze({
        KNOWN_SAFE: 0,
        FAILED: 1,
        WAITING: 2,
        ALLOWED: 3,
        MALICIOUS: 4,
        PHISHING: 5,
        UNTRUSTED: 6,
        ADULT_CONTENT: 7,
    });

    const _Origin = Object.freeze({
        UNKNOWN: 0,
        CLOUDFLARE_RESOLVER: 1,

        // Official Partners
        ADGUARD_SECURITY: 2,
        ADGUARD_FAMILY: 3,
        ALPHAMOUNTAIN: 4,
        PRECISIONSEC: 5,

        // Non-Partnered Providers
        CERT_EE: 6,
        CLEANBROWSING_SECURITY: 7,
        CLEANBROWSING_FAMILY: 8,
        CLOUDFLARE_SECURITY: 9,
        CLOUDFLARE_FAMILY: 10,
        CONTROL_D_SECURITY: 11,
        CONTROL_D_FAMILY: 12,
        QUAD9: 13,
        SWITCH_CH: 14,

        // Local Filtering Lists
        PHISH_DESTROY: 15,
        PHISHING_DATABASE: 16,
    });

    // Pre-built sets for O(1) validation in the constructor
    const _validResultTypes = new Set(Object.values(_ResultType));
    const _validOrigins = new Set(Object.values(_Origin));

    class ProtectionResult {

        /**
         * Constructor function for creating a browser protection result object.
         *
         * @param {string} urlChecked The URL that was checked.
         * @param {number} resultType The result type of the protection check (see ResultType for more info).
         * @param {number} resultOrigin The origin of the result (e.g., from endpoint or known top website).
         */
        constructor(urlChecked, resultType, resultOrigin) {
            if (typeof urlChecked !== 'string' || urlChecked.length === 0) {
                throw new TypeError('urlChecked must be a non-empty string');
            }

            let parsedUrl;
            try {
                parsedUrl = new URL(urlChecked);
            } catch {
                throw new TypeError(`urlChecked is not a valid URL: ${urlChecked}`);
            }

            if (parsedUrl.protocol !== 'https:' && parsedUrl.protocol !== 'http:') {
                throw new TypeError(`urlChecked has an unsupported scheme: ${parsedUrl.protocol}`);
            }

            if (!Number.isInteger(resultType) || !_validResultTypes.has(resultType)) {
                throw new TypeError(`Invalid resultType: ${resultType}`);
            }

            if (!Number.isInteger(resultOrigin) || !_validOrigins.has(resultOrigin)) {
                throw new TypeError(`Invalid resultOrigin: ${resultOrigin}`);
            }

            this.url = urlChecked;
            this.resultType = resultType;
            this.origin = resultOrigin;
            Object.freeze(this);
        }
    }

    ProtectionResult.ResultType = _ResultType;

    // Lazy getter defers LangUtil resolution to call time, removing the parse-time load-order dependency.
    Object.defineProperty(ProtectionResult, 'ResultTypeName', {
        get() {
            return Object.freeze(Object.assign(Object.create(null), {
                0: LangUtil.KNOWN_SAFE,
                1: LangUtil.FAILED,
                2: LangUtil.WAITING,
                3: LangUtil.ALLOWED,
                4: LangUtil.MALICIOUS,
                5: LangUtil.PHISHING,
                6: LangUtil.UNTRUSTED,
                7: LangUtil.ADULT_CONTENT,
            }));
        },
        configurable: false,
        enumerable: true,
    });

    ProtectionResult.ResultTypeNameEN = Object.freeze(Object.assign(Object.create(null), {
        0: "Known Safe",
        1: "Failed",
        2: "Waiting",
        3: "Allowed",
        4: "Malicious",
        5: "Phishing",
        6: "Untrusted",
        7: "Adult Content",
    }));

    ProtectionResult.Origin = _Origin;

    ProtectionResult.FullName = Object.freeze(Object.assign(Object.create(null), {
        0: "Unknown",
        1: "Cloudflare Resolver",
        2: "AdGuard Security DNS",
        3: "AdGuard Family DNS",
        4: "alphaMountain Web Protection",
        5: "PrecisionSec Web Protection",
        6: "CERT-EE Security DNS",
        7: "CleanBrowsing Security DNS",
        8: "CleanBrowsing Family DNS",
        9: "Cloudflare Security DNS",
        10: "Cloudflare Family DNS",
        11: "Control D Security DNS",
        12: "Control D Family DNS",
        13: "Quad9 Security DNS",
        14: "Switch.ch Security DNS",
        15: "PhishDestroy Feed",
        16: "Phishing.Database Feed",
    }));

    ProtectionResult.ShortName = Object.freeze(Object.assign(Object.create(null), {
        0: "Unknown",
        1: "Cloudflare Resolver",
        2: "AdGuard Security",
        3: "AdGuard Family",
        4: "alphaMountain",
        5: "PrecisionSec",
        6: "CERT-EE",
        7: "CleanBrowsing Security",
        8: "CleanBrowsing Family",
        9: "Cloudflare Security",
        10: "Cloudflare Family",
        11: "Control D Security",
        12: "Control D Family",
        13: "Quad9",
        14: "Switch.ch",
        15: "PhishDestroy",
        16: "Phishing.Database",
    }));

    ProtectionResult.CacheName = Object.freeze(Object.assign(Object.create(null), {
        0: "unknown",
        1: "cloudflareResolver",
        2: "adGuardSecurity",
        3: "adGuardFamily",
        4: "alphaMountain",
        5: "precisionSec",
        6: "certEE",
        7: "cleanBrowsingSecurity",
        8: "cleanBrowsingFamily",
        9: "cloudflareSecurity",
        10: "cloudflareFamily",
        11: "controlDSecurity",
        12: "controlDFamily",
        13: "quad9",
        14: "switchCH",
        15: "phishDestroy",
        16: "phishingDatabase",
    }));

    for (const originValue of Object.values(_Origin)) {
        console.assert(originValue in ProtectionResult.FullName, `ProtectionResult.FullName missing entry for origin ${originValue}`);
        console.assert(originValue in ProtectionResult.ShortName, `ProtectionResult.ShortName missing entry for origin ${originValue}`);
        console.assert(originValue in ProtectionResult.CacheName, `ProtectionResult.CacheName missing entry for origin ${originValue}`);
    }

    for (const resultValue of Object.values(_ResultType)) {
        console.assert(resultValue in ProtectionResult.ResultTypeNameEN, `ProtectionResult.ResultTypeNameEN missing entry for resultType ${resultValue}`);
    }

    const _cacheNameValues = Object.values(ProtectionResult.CacheName);
    console.assert(
        new Set(_cacheNameValues).size === _cacheNameValues.length,
        'ProtectionResult.CacheName contains duplicate values; cache partitions will collide'
    );

    globalThis.ProtectionResult = ProtectionResult;
}
