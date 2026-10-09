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

globalThis.OspreyUrlService = (() => {
    const browserAPI = globalThis.OspreyBrowserAPI;

    class BoundedCache {
        constructor(limit = 4096) {
            this.map = new Map();
            this.limit = limit;
        }

        getFromMap(k) {
            return this.map.get(k);
        }

        setToMap(k, v) {
            if (this.map.size >= this.limit) {
                this.map.clear();
            }

            this.map.set(k, v);
        }
    }

    const canonicalizeHostnameCache = new BoundedCache(4096);
    const normalizeUrlCache = new BoundedCache(4096);

    const regexTrailingDots = /\.+$/;
    const regexIPvFour = /^\d+\.\d+\.\d+\.\d+$/;
    const regexIPvSix = /^\[|]$/g;
    const regexValidHostChars = /^[a-z0-9._-]+$/;
    // RFC 3986 reg-name characters. Browsers navigate to hosts like `a$b.example`, so parsed URLs
    // must accept them or those pages would skip every check. Bare host patterns keep the set above.
    const regexNavigableHostChars = /^[a-z0-9._~!$&'()*+,;=-]+$/;
    const regexValidIPv6Literal = /^\[[0-9a-f:.]+]$/;

    const hostMatches = (hostname, validChars) => {
        if (typeof hostname !== 'string' || hostname.length === 0) {
            return false;
        }

        const lower = hostname.toLowerCase();

        if (lower.codePointAt(0) === 91) {
            return regexValidIPv6Literal.test(lower);
        }

        if (!validChars.test(lower)) {
            return false;
        }

        const host = lower.codePointAt(lower.length - 1) === 46 ? lower.slice(0, -1) : lower;

        if (host.length === 0) {
            return false;
        }

        const labels = host.split('.');

        for (let i = 0, len = labels.length; i < len; i++) {
            const label = labels[i];

            if (label.length === 0) {
                return false;
            }
        }
        return true;
    };

    const isAcceptableHost = hostname => hostMatches(hostname, regexValidHostChars);
    const isNavigableHost = hostname => hostMatches(hostname, regexNavigableHostChars);

    let cachedBlockPageUrl = null;

    const blockPageUrl = () => {
        if (cachedBlockPageUrl === null) {
            cachedBlockPageUrl = browserAPI.safeRuntimeURL('pages/warning/warning-page.html');
        }
        return cachedBlockPageUrl;
    };

    const isWarningPageUrl = value => typeof value === 'string' && value.startsWith(blockPageUrl());

    const canonicalizeHostname = hostname => {
        if (typeof hostname !== 'string' || hostname.length === 0) {
            return '';
        }

        const cached = canonicalizeHostnameCache.getFromMap(hostname);

        if (cached !== undefined) {
            return cached;
        }

        let result = hostname.trim().toLowerCase();

        if (result.codePointAt(result.length - 1) === 46) {
            result = result.replace(regexTrailingDots, '');
        }

        if (result.startsWith('www.')) {
            result = result.slice(4);
        }

        canonicalizeHostnameCache.setToMap(hostname, result);
        return result;
    };

    const parseHttpUrl = value => {
        if (value instanceof URL) {
            const p = value.protocol;
            return (p === 'http:' || p === 'https:') && isNavigableHost(value.hostname) ? value : null;
        }

        const strVal = String(value);

        try {
            const url = new URL(strVal);
            const p = url.protocol;
            return (p === 'http:' || p === 'https:') && isNavigableHost(url.hostname) ? url : null;
        } catch (error) {
            if (strVal.trim()) {
                console.warn('OspreyUrlService failed to parse URL', error);
            }
            return null;
        }
    };

    const stripTrailingSlash = value => {
        const len = value.length;

        if (len <= 1) {
            return value;
        }

        let end = len;

        while (end > 1 && value.codePointAt(end - 1) === 47) {
            end--;
        }
        return end === len ? value : value.slice(0, end);
    };

    const toComparableUrl = value => {
        const url = value instanceof URL ? new URL(value.href) : parseHttpUrl(value);

        if (!url) {
            return null;
        }

        url.username = '';
        url.password = '';

        const canonHost = canonicalizeHostname(url.hostname);

        if (url.hostname !== canonHost) {
            url.hostname = canonHost;
        }

        const strippedPath = stripTrailingSlash(url.pathname);

        if (url.pathname !== strippedPath) {
            url.pathname = strippedPath;
        }

        const protocol = url.protocol;
        const port = url.port;

        if (protocol === 'https:' && port === '443' || protocol === 'http:' && port === '80') {
            url.port = '';
        }
        return url;
    };

    const queryRetentionRules = [
        {hostname: 'drive.google.com', pathname: '/uc', keys: ['export', 'id']},
        {hostname: 'adclick.g.doubleclick.net', pathname: '/pcs/click', keys: ['adurl']},
        {hostname: 'drive.usercontent.google.com', pathname: '/download', keys: ['id', 'export']},
        {hostname: 'google.com', pathname: '/share.google', keys: ['q']},
    ];

    const retainedSearch = (hostname, pathname, searchParams) => {
        let keys = null;

        for (let i = 0, len = queryRetentionRules.length; i < len; i++) {
            const rule = queryRetentionRules[i];

            if (rule.hostname === hostname && rule.pathname === pathname) {
                keys = rule.keys;
                break;
            }
        }

        if (keys === null) {
            return '';
        }

        const parts = [];

        for (let i = 0, len = keys.length; i < len; i++) {
            const key = keys[i];
            const value = searchParams.get(key);

            if (value !== null) {
                parts.push(`${key}=${encodeURIComponent(value)}`);
            }
        }
        return parts.length === 0 ? '' : `?${parts.join('&')}`;
    };

    const normalizeUrl = value => {
        const cacheKey = typeof value === 'string' ? value : value.href;
        const cached = normalizeUrlCache.getFromMap(cacheKey);

        if (cached !== undefined) {
            return cached;
        }

        const normalized = toComparableUrl(value);

        if (!normalized) {
            normalizeUrlCache.setToMap(cacheKey, null);
            return null;
        }

        normalized.hash = '';

        const result = normalized.href;
        normalizeUrlCache.setToMap(cacheKey, result);
        return result;
    };

    const normalizeLookupUrl = value => {
        const normalized = normalizeUrl(value);

        if (!normalized) {
            return null;
        }

        const url = new URL(normalized);
        url.search = retainedSearch(url.hostname, url.pathname, url.searchParams);
        return url.href;
    };

    const lookupValueForTarget = (url, target) => {
        const parsed = parseHttpUrl(url);

        if (!parsed) {
            return '';
        }

        if (target === 'hostname') {
            return canonicalizeHostname(parsed.hostname);
        }
        return normalizeUrl(parsed);
    };

    const internalSuffixes = Object.freeze(['.local', '.localhost', '.internal', '.lan', '.localdomain', '.home.arpa']);
    const regexMappedIPvSixHex = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/;
    const regexMappedIPvSixDotted = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/;

    const isInternalHostname = hostname => {
        if (typeof hostname !== 'string' || hostname.length === 0) {
            return true;
        }

        const lower = canonicalizeHostname(hostname);

        if (lower === 'localhost' || internalSuffixes.some(suffix => lower.endsWith(suffix))) {
            return true;
        }

        if (regexIPvFour.test(lower)) {
            const parts = lower.split('.');
            const first = Number(parts[0]);
            const second = Number(parts[1]);

            return first === 10 || first === 127 || first === 0 ||
                first === 100 && second >= 64 && second <= 127 ||
                first === 169 && second === 254 ||
                first === 172 && second >= 16 && second <= 31 ||
                first === 192 && second === 168 ||
                first === 198 && (second === 18 || second === 19);
        }

        if (lower.includes(':')) {
            const compact = lower.replace(regexIPvSix, '');

            // IPv4-mapped addresses take the verdict of the embedded IPv4 address.
            const dotted = regexMappedIPvSixDotted.exec(compact);

            if (dotted) {
                return isInternalHostname(dotted[1]);
            }

            const hex = regexMappedIPvSixHex.exec(compact);

            if (hex) {
                const high = Number.parseInt(hex[1], 16);
                const low = Number.parseInt(hex[2], 16);
                return isInternalHostname(`${high >> 8}.${high & 255}.${low >> 8}.${low & 255}`);
            }

            // ::1, ::, unique-local fc00::/7, link-local fe80::/10 and deprecated site-local fec0::/10.
            return compact === '::1' || compact === '::' || compact.startsWith('fc') || compact.startsWith('fd') ||
                /^fe[89abcdef]/.test(compact);
        }

        // A single-label name (such as "intranet") only resolves on a private network.
        return !lower.includes('.');
    };

    const maxBlockedUrlParamLength = 8192;

    const clampBlockedUrlForTransport = value => {
        const str = typeof value === 'string' ? value : String(value ?? '');

        if (str.length <= maxBlockedUrlParamLength) {
            return str;
        }

        let end = maxBlockedUrlParamLength;
        const code = str.charCodeAt(end - 1);

        if (code >= 0xD800 && code <= 0xDBFF) {
            end -= 1;
        }
        return str.slice(0, end);
    };

    const buildWarningPageUrl = ({url, origin, result}) =>
        `${blockPageUrl()}?url=${encodeURIComponent(clampBlockedUrlForTransport(url))}&or=${encodeURIComponent(origin || 'unknown')}&rs=${encodeURIComponent(result)}`;

    const haveSameOrigin = (leftUrl, rightUrl) => {
        const left = parseHttpUrl(leftUrl);
        const right = parseHttpUrl(rightUrl);

        if (!left || !right) {
            return false;
        }

        if (left.protocol !== right.protocol) {
            return false;
        }

        const leftHost = canonicalizeHostname(left.hostname);
        const rightHost = canonicalizeHostname(right.hostname);

        if (leftHost !== rightHost) {
            return false;
        }

        const lPort = left.port === '80' && left.protocol === 'http:' || left.port === '443' && left.protocol === 'https:' ? '' : left.port;
        const rPort = right.port === '80' && right.protocol === 'http:' || right.port === '443' && right.protocol === 'https:' ? '' : right.port;
        return lPort === rPort;
    };

    return Object.freeze({
        parseHttpUrl,
        normalizeUrl,
        normalizeLookupUrl,
        lookupValueForTarget,
        canonicalizeHostname,
        isInternalHostname,
        isAcceptableHost,
        isNavigableHost,
        buildWarningPageUrl,
        haveSameOrigin,
        isWarningPageUrl,
        blockPageUrl,
    });
})();
