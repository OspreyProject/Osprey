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

    let cachedBlockPageUrl = null;

    const blockPageUrl = () => {
        if (cachedBlockPageUrl === null) {
            cachedBlockPageUrl = browserAPI.safeRuntimeURL('pages/warning/warning-page.html');
        }
        return cachedBlockPageUrl;
    };

    const isWarningPageUrl = value => {
        return typeof value === 'string' && value.startsWith(blockPageUrl());
    };

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
            return p === 'http:' || p === 'https:' ? value : null;
        }

        const strVal = String(value);

        try {
            const url = new URL(strVal);
            const p = url.protocol;
            return p === 'http:' || p === 'https:' ? url : null;
        } catch (error) {
            if (strVal.trim()) {
                console.warn("OspreyUrlService failed to parse URL", error);
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

        normalized.search = '';
        normalized.hash = '';
        normalized.port = '';

        const result = normalized.href;
        normalizeUrlCache.setToMap(cacheKey, result);
        return result;
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

    const isInternalHostname = hostname => {
        if (typeof hostname !== 'string' || hostname.length === 0) {
            return true;
        }

        const lower = canonicalizeHostname(hostname);

        if (lower === 'localhost' || lower.codePointAt(lower.length - 1) === 108 && lower.endsWith('.local')) {
            return true;
        }

        if (regexIPvFour.test(lower)) {
            const parts = lower.split('.');
            const first = Number(parts[0]);
            const second = Number(parts[1]);

            return first === 10 || first === 127 || first === 0 ||
                first === 169 && second === 254 ||
                first === 172 && second >= 16 && second <= 31 ||
                first === 192 && second === 168;
        }

        if (lower.indexOf(':') !== -1) {
            const compact = lower.replace(regexIPvSix, '');
            return compact === '::1' || compact.startsWith('fc') || compact.startsWith('fd') || compact.startsWith('fe80');
        }
        return false;
    };

    const buildWarningPageUrl = ({url, origin, result, tabId}) => {
        let page = blockPageUrl() + '?url=' + encodeURIComponent(url) +
            '&or=' + encodeURIComponent(origin || 'unknown') +
            '&rs=' + encodeURIComponent(result);

        if (typeof tabId === 'number' && Number.isFinite(tabId)) {
            page += '&tid=' + tabId;
        }
        return page;
    };

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
        lookupValueForTarget,
        canonicalizeHostname,
        isInternalHostname,
        buildWarningPageUrl,
        haveSameOrigin,
        isWarningPageUrl,
        blockPageUrl,
    });
})();
