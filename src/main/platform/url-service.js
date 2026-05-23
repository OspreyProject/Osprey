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
    // Global variables
    const browserAPI = globalThis.OspreyBrowserAPI;

    const allowedSchemes = Object.freeze([
        'http:', 'https:'
    ]);

    const warningContextFallback = Object.freeze({
        blockedUrl: '',
        continueUrl: '',
        origin: 'unknown',
        result: 'failed'
    });

    const blockPageUrl = () => browserAPI.safeRuntimeURL('pages/warning/warning-page.html');
    const isWarningPageUrl = value => typeof value === 'string' && value.startsWith(blockPageUrl());

    const canonicalizeHostname = hostname => typeof hostname !== 'string' || hostname.length === 0 ? '' :
        hostname.trim().toLowerCase().replaceAll(/\.+$/g, '').replace(/^www\./i, '');

    const parseHttpUrl = value => {
        try {
            const url = new URL(String(value));
            return allowedSchemes.includes(url.protocol) ? url : null;
        } catch (error) {
            if (String(value ?? '').trim()) {
                console.warn(`OspreyUrlService failed to parse URL '${value}'`, error);
            }
            return null;
        }
    };

    const stripTrailingSlash = value => value === '/' ? '' : value.endsWith('/') ? value.slice(0, -1) : value;

    const toComparableUrl = value => {
        const url = value instanceof URL ? new URL(value.toString()) : parseHttpUrl(value);

        if (!url) {
            return null;
        }

        url.username = '';
        url.password = '';
        url.hostname = canonicalizeHostname(url.hostname);
        url.pathname = stripTrailingSlash(url.pathname);

        if (url.protocol === 'https:' && url.port === '443' || url.protocol === 'http:' && url.port === '80') {
            url.port = '';
        }
        return url;
    };

    const normalizeUrl = value => {
        const normalized = toComparableUrl(value);

        if (!normalized) {
            return null;
        }

        normalized.search = '';
        normalized.hash = '';
        normalized.port = '';
        return normalized.toString();
    };

    const lookupValueForTarget = (url, target) => {
        const parsed = url instanceof URL ? url : parseHttpUrl(url);

        if (target === 'hostname') {
            return parsed ? canonicalizeHostname(parsed.hostname) : '';
        } else {
            return parsed ? normalizeUrl(parsed) || parsed.toString() : '';
        }
    };

    const isInternalHostname = hostname => {
        if (typeof hostname !== 'string' || hostname.length === 0) {
            return true;
        }

        const lower = canonicalizeHostname(hostname);

        if (lower === 'localhost' || lower.endsWith('.local')) {
            return true;
        }

        if (/^\d+\.\d+\.\d+\.\d+$/.test(lower)) {
            const [first, second] = lower.split('.').map(Number);

            return first === 10 || first === 127 || first === 0 || first === 169 && second === 254 ||
                first === 172 && second >= 16 && second <= 31 || first === 192 && second === 168;
        }

        const compact = lower.replaceAll(/^\[|]$/g, '');

        return compact.includes(':') && (
            compact === '::1' || compact.startsWith('fc') || compact.startsWith('fd') || compact.startsWith('fe80')
        );
    };

    const hostnameIsValid = hostname => {
        const canonical = canonicalizeHostname(hostname);

        if (!canonical || isInternalHostname(canonical) || canonical.length > 253) {
            return false;
        }

        const labels = canonical.split('.');

        return !labels.some(label => label.length === 0 || label.length > 63) &&
            labels.every(label => /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/i.test(label));
    };

    const buildWarningPageUrl = ({url, continueUrl, origin, result, tabId}) => {
        const page = new URL(blockPageUrl());
        page.searchParams.set('url', url);
        page.searchParams.set('curl', continueUrl || url);
        page.searchParams.set('or', origin || 'unknown');
        page.searchParams.set('rs', result);

        if (typeof tabId === 'number' && Number.isFinite(tabId)) {
            page.searchParams.set('tid', String(tabId));
        }

        return page.toString();
    };

    const extractWarningContext = pageUrl => {
        try {
            const url = new URL(pageUrl);

            const rawTabId = url.searchParams.get('tid');
            const parsedTabId = Number.parseInt(String(rawTabId || ''), 10);

            return Object.freeze({
                blockedUrl: url.searchParams.get('url') || '',
                continueUrl: url.searchParams.get('curl') || '',
                origin: url.searchParams.get('or') || 'unknown',
                result: url.searchParams.get('rs') || 'failed',
                tabId: Number.isFinite(parsedTabId) ? parsedTabId : null
            });
        } catch (error) {
            console.warn(`OspreyUrlService failed to extract warning context from '${pageUrl}'`, error);
            return warningContextFallback;
        }
    };

    const areEquivalentURLs = (leftUrl, rightUrl) => leftUrl === rightUrl || (() => {
        const left = toComparableUrl(leftUrl);
        const right = toComparableUrl(rightUrl);
        return !!left && !!right && left.toString() === right.toString();
    })();

    // Public API
    return Object.freeze({
        parseHttpUrl,
        normalizeUrl,
        lookupValueForTarget,
        canonicalizeHostname,
        isInternalHostname,
        hostnameIsValid,
        buildWarningPageUrl,
        extractWarningContext,
        areEquivalentURLs,
        isWarningPageUrl,
        blockPageUrl,
    });
})();
