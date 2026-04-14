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

globalThis.OspreyDnsValidator = (() => {
    // Global variables
    const cacheService = globalThis.OspreyCacheService;
    const timedSignal = globalThis.OspreyTimedSignal;
    const urlService = globalThis.OspreyUrlService;

    const providerId = 'cloudflare-resolver';

    const isResolvable = async (hostname, parentSignal, tabId = 0) => {
        if (!urlService.hostnameIsValid(hostname)) {
            console.warn(`OspreyDnsValidator skipped validation for invalid hostname '${hostname}'`);
            return false;
        }

        const lookupKey = urlService.canonicalizeHostname(hostname);

        if (await cacheService.getAllowedEntry(providerId, lookupKey)) {
            return true;
        }

        if (cacheService.isProcessing(providerId, lookupKey)) {
            return true;
        }

        cacheService.markProcessing(providerId, lookupKey, tabId);
        const timed = timedSignal.create(parentSignal, 5000);

        try {
            const response = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}`, {
                method: 'GET',
                headers: {
                    'Accept': 'application/dns-json'
                },
                signal: timed.signal,
            });

            if (!response.ok) {
                console.warn(`OspreyDnsValidator request failed for '${lookupKey}' with status ${response.status}`);
                return false;
            }

            const data = await response.json();
            const resolvable = data?.Status === 0 && Array.isArray(data?.Answer) && data.Answer.length > 0;

            if (resolvable) {
                await cacheService.markAllowed(providerId, lookupKey, 86400);
            }
            return resolvable;
        } catch (error) {
            console.warn(`OspreyDnsValidator failed for hostname '${lookupKey}'`, error);
            return false;
        } finally {
            timed.cleanup();
            cacheService.clearProcessing(providerId, lookupKey);
        }
    };

    // Public API
    return Object.freeze({
        isResolvable,
    });
})();
