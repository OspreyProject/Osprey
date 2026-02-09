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

class ProtectionResult {

    /**
     * Constructor function for creating a browser protection result object.
     *
     * @param {string} urlChecked - The URL that was checked.
     * @param {number} resultType - The result type of the protection check (see ResultType for more info).
     * @param {number} resultOrigin - The origin of the result (e.g., from endpoint or known top website).
     */
    constructor(urlChecked, resultType, resultOrigin) {
        if (typeof urlChecked !== 'string' || !urlChecked) {
            throw new TypeError('urlChecked must be a non-empty string');
        }

        if (typeof resultType !== 'number' || !Object.values(ProtectionResult.ResultType).includes(resultType)) {
            throw new TypeError('resultType must be a valid ResultType');
        }

        if (typeof resultOrigin !== 'number' || !Object.values(ProtectionResult.Origin).includes(resultOrigin)) {
            throw new TypeError('resultOrigin must be a valid Origin');
        }

        this.url = urlChecked;
        this.resultType = resultType;
        this.origin = resultOrigin;
    }
}

ProtectionResult.ResultType = Object.freeze({
    KNOWN_SAFE: 0,
    FAILED: 1,
    WAITING: 2,
    ALLOWED: 3,
    MALICIOUS: 4,
    PHISHING: 5,
    UNTRUSTED: 6,
    ADULT_CONTENT: 7,
});

ProtectionResult.ResultTypeName = Object.freeze({
    0: LangUtil.KNOWN_SAFE,
    1: LangUtil.FAILED,
    2: LangUtil.WAITING,
    3: LangUtil.ALLOWED,
    4: LangUtil.MALICIOUS,
    5: LangUtil.PHISHING,
    6: LangUtil.UNTRUSTED,
    7: LangUtil.ADULT_CONTENT
});

ProtectionResult.ResultTypeNameEN = Object.freeze({
    0: "Known Safe",
    1: "Failed",
    2: "Waiting",
    3: "Allowed",
    4: "Malicious",
    5: "Phishing",
    6: "Untrusted",
    7: "Adult Content",
});

ProtectionResult.Origin = Object.freeze({
    UNKNOWN: 0,

    // Official Partners
    ADGUARD_SECURITY: 1,
    ADGUARD_FAMILY: 2,
    ALPHAMOUNTAIN: 3,
    PRECISIONSEC: 4,

    // Non-Partnered Providers
    CERT_EE: 5,
    CLEANBROWSING_SECURITY: 6,
    CLEANBROWSING_FAMILY: 7,
    CLOUDFLARE_SECURITY: 8,
    CLOUDFLARE_FAMILY: 9,
    CONTROL_D_SECURITY: 10,
    CONTROL_D_FAMILY: 11,
    DNS4EU_SECURITY: 12,
    DNS4EU_FAMILY: 13,
    SECLOOKUP: 14,
    SWITCH_CH: 15,
    QUAD9: 16,
});

ProtectionResult.FullName = Object.freeze({
    0: "Unknown",

    // Official Partners
    1: "AdGuard Security DNS",
    2: "AdGuard Family DNS",
    3: "alphaMountain Web Protection",
    4: "PrecisionSec Web Protection",

    // Non-Partnered Providers
    5: "CERT-EE Security DNS",
    6: "CleanBrowsing Security DNS",
    7: "CleanBrowsing Family DNS",
    8: "Cloudflare Security DNS",
    9: "Cloudflare Family DNS",
    10: "Control D Security DNS",
    11: "Control D Family DNS",
    12: "DNS4EU Security DNS",
    13: "DNS4EU Family DNS",
    14: "Seclookup Web Protection",
    15: "Switch.ch Security DNS",
    16: "Quad9 Security DNS",
});

ProtectionResult.ShortName = Object.freeze({
    0: "Unknown",

    // Official Partners
    1: "AdGuard Security",
    2: "AdGuard Family",
    3: "alphaMountain",
    4: "PrecisionSec",

    // Non-Partnered Providers
    5: "CERT-EE",
    6: "CleanBrowsing Security",
    7: "CleanBrowsing Family",
    8: "Cloudflare Security",
    9: "Cloudflare Family",
    10: "Control D Security",
    11: "Control D Family",
    12: "DNS4EU Security",
    13: "DNS4EU Family",
    14: "Seclookup",
    15: "Switch.ch",
    16: "Quad9",
});

ProtectionResult.CacheName = Object.freeze({
    0: "unknown",

    // Official Partners
    1: "adGuardSecurity",
    2: "adGuardFamily",
    3: "alphaMountain",
    4: "precisionSec",

    // Non-Partnered Providers
    5: "certEE",
    6: "cleanBrowsingSecurity",
    7: "cleanBrowsingFamily",
    8: "cloudflareSecurity",
    9: "cloudflareFamily",
    10: "controlDSecurity",
    11: "controlDFamily",
    12: "dns4EUSecurity",
    13: "dns4EUFamily",
    14: "seclookup",
    15: "switchCH",
    16: "quad9",
});
