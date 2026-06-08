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

globalThis.OspreyProviderEngine = (() => {
    const cacheService = globalThis.OspreyCacheService;
    const protectionResult = globalThis.OspreyProtectionResult;
    const requestBuilder = globalThis.OspreyRequestBuilder;
    const responseRuleEngine = globalThis.OspreyResponseRuleEngine;
    const timedSignal = globalThis.OspreyTimedSignal;
    const urlService = globalThis.OspreyUrlService;

    const abortControllers = new Map();
    const providerNamesCache = new WeakMap();

    const normalizeLookupName = value => typeof value === 'string' ? value.trim().toLowerCase() : String(value || '').trim().toLowerCase();

    const getCachedProviderNames = provider => {
        let names = providerNamesCache.get(provider);

        if (!names) {
            const raw = provider?.metaDefenderProviderNames;

            if (Array.isArray(raw)) {
                names = [];

                for (const element of raw) {
                    const val = element;

                    if (val) {
                        names.push(normalizeLookupName(val));
                    }
                }
            } else {
                names = [];
            }

            providerNamesCache.set(provider, names);
        }
        return names;
    };

    const createSharedResponseIndexes = responseBody => {
        const sources = responseBody?.data?.[0]?.lookup_results?.sources;

        if (!Array.isArray(sources) || sources.length === 0) {
            return null;
        }

        const metaDefenderMap = new Map();

        for (const element of sources) {
            const source = element;

            if (source?.provider) {
                const key = normalizeLookupName(source.provider);

                if (key) {
                    metaDefenderMap.set(key, source);
                }
            }
        }
        return metaDefenderMap;
    };

    const getMetaDefenderProviderBlock = (provider, responseBody, metaDefenderMap = null) => {
        const providerNames = getCachedProviderNames(provider);
        const len = providerNames.length;

        if (len === 0) {
            return null;
        }

        if (metaDefenderMap instanceof Map) {
            for (let i = 0; i < len; i++) {
                const match = metaDefenderMap.get(providerNames[i]);

                if (match) {
                    return match;
                }
            }
            return null;
        }

        const sources = responseBody?.data?.[0]?.lookup_results?.sources;

        if (!Array.isArray(sources)) {
            return null;
        }

        for (const element of sources) {
            const source = element;

            if (source?.provider && providerNames.includes(normalizeLookupName(source.provider))) {
                return source;
            }
        }
        return null;
    };

    const getRuleEvaluationBody = (provider, responseBody, metaDefenderMap = null) => {
        if (provider?.responseRuleScope === 'metadefender_provider_block') {
            return getMetaDefenderProviderBlock(provider, responseBody, metaDefenderMap);
        }
        return responseBody;
    };

    const evaluateDirectResponse = (provider, responseBody, metaDefenderMap = null) => {
        const evaluationBody = getRuleEvaluationBody(provider, responseBody, metaDefenderMap);

        if (evaluationBody == null) {
            return protectionResult.resultTypes.ALLOWED;
        }

        const matched = responseRuleEngine.evaluateRules(evaluationBody, provider.responseRules || []);

        if (!matched || matched === 'KNOWN_SAFE') {
            return protectionResult.resultTypes.KNOWN_SAFE;
        }

        const normalized = typeof matched === 'string' ? matched.toLowerCase() : String(matched).toLowerCase();

        if (normalized === 'known_safe') {
            return protectionResult.resultTypes.KNOWN_SAFE;
        }

        if (normalized === 'allowed') {
            return protectionResult.resultTypes.ALLOWED;
        }
        return protectionResult.fromProviderString(normalized);
    };

    const emitResult = (provider, targetUrl, result, onResult) => onResult(protectionResult.create({
        url: targetUrl,
        result,
        origin: provider.id,
        providerName: provider.displayName,
    }));

    const fetchJsonResponse = async (provider, targetUrl, parentSignal) => {
        const built = requestBuilder.buildRequest(provider, targetUrl, provider.state);
        const timed = timedSignal.create(parentSignal, built.timeoutMs);

        try {
            const response = await fetch(built.url, {...built.options, signal: timed.signal});

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }
            return await response.json();
        } finally {
            timed.cleanup();
        }
    };

    const finalizeProviderResult = async (provider, lookupKey, targetUrl, expirationSeconds, onResult, outcome) => {
        if (protectionResult.blockingResults.has(outcome)) {
            cacheService.markBlocked(provider.id, lookupKey, outcome, expirationSeconds).catch(() => {
                // ignored
            });
        } else {
            cacheService.markAllowed(provider.id, lookupKey, expirationSeconds).catch(() => {
                // ignored
            });
        }

        console.info(`[${provider.displayName}] URL result: ${outcome} for ${targetUrl}`);
        emitResult(provider, targetUrl, outcome, onResult);
    };

    const checkProviderCache = async (provider, lookupKey, targetUrl, expirationSeconds, onResult, globalAllowMatched) => {
        if (globalAllowMatched && !provider.bypassBlockingThreshold) {
            cacheService.markAllowed(provider.id, lookupKey, expirationSeconds).catch(() => {
                // ignored
            });

            emitResult(provider, targetUrl, protectionResult.resultTypes.ALLOWED, onResult);
            return false;
        }

        const blockedEntry = await cacheService.getBlockedEntry(provider.id, lookupKey);

        if (blockedEntry?.result) {
            console.debug(`[${provider.displayName}] URL is already blocked: ${targetUrl}`);
            emitResult(provider, targetUrl, blockedEntry.result, onResult);
            return false;
        }

        const allowedEntry = await cacheService.getAllowedEntry(provider.id, lookupKey);

        if (allowedEntry) {
            console.debug(`[${provider.displayName}] URL is already allowed: ${targetUrl}`);
            emitResult(provider, targetUrl, protectionResult.resultTypes.ALLOWED, onResult);
            return false;
        }

        if (cacheService.isProcessing(provider.id, lookupKey)) {
            console.debug(`[${provider.displayName}] URL is already processing: ${targetUrl}`);
            emitResult(provider, targetUrl, protectionResult.resultTypes.WAITING, onResult);
            return false;
        }
        return true;
    };

    const fetchProviderResult = async (provider, targetUrl, parentSignal, expirationSeconds, onResult, tabId, globalAllowMatched) => {
        const lookupKey = urlService.lookupValueForTarget(targetUrl, provider.lookupTarget || 'url');

        if (!lookupKey) {
            console.warn(`OspreyProviderEngine could not derive a lookup key for provider '${provider.id}' and URL '${targetUrl}'`);
            return;
        }

        if (!await checkProviderCache(provider, lookupKey, targetUrl, expirationSeconds, onResult, globalAllowMatched)) {
            return;
        }

        cacheService.markProcessing(provider.id, lookupKey, tabId);

        try {
            const data = await fetchJsonResponse(provider, targetUrl, parentSignal);

            const outcome = provider.kind === 'proxy_builtin' ?
                protectionResult.fromProviderString(data?.result) :
                evaluateDirectResponse(provider, data);

            await finalizeProviderResult(provider, lookupKey, targetUrl, expirationSeconds, onResult, outcome);
        } catch (error) {
            console.warn(`[${provider.displayName}] Failed to check URL: ${error}`);
            emitResult(provider, targetUrl, protectionResult.resultTypes.FAILED, onResult);
        } finally {
            cacheService.clearProcessing(provider.id, lookupKey);
        }
    };

    const fetchSharedProviderResults = async (providers, targetUrl, parentSignal, expirationSeconds, onResult, tabId, globalAllowMatched) => {
        const providersLen = providers.length;

        if (providersLen === 0) {
            return;
        }

        const lookupKeys = new Map();
        const activeProviders = [];

        for (let i = 0; i < providersLen; i++) {
            const provider = providers[i];
            const lookupKey = urlService.lookupValueForTarget(targetUrl, provider.lookupTarget || 'url');

            if (!lookupKey) {
                console.warn(`OspreyProviderEngine could not derive a lookup key for provider '${provider.id}' and URL '${targetUrl}'`);
                continue;
            }

            lookupKeys.set(provider.id, lookupKey);

            if (!await checkProviderCache(provider, lookupKey, targetUrl, expirationSeconds, onResult, globalAllowMatched)) {
                continue;
            }

            cacheService.markProcessing(provider.id, lookupKey, tabId);
            activeProviders.push(provider);
        }

        const activeLen = activeProviders.length;

        if (activeLen === 0) {
            return;
        }

        try {
            const data = await fetchJsonResponse(activeProviders[0], targetUrl, parentSignal);
            const metaDefenderMap = createSharedResponseIndexes(data);

            const computedOutcomes = [];
            const cacheStorePayload = [];

            for (let i = 0; i < activeLen; i++) {
                const provider = activeProviders[i];
                const lookupKey = lookupKeys.get(provider.id);

                try {
                    const outcome = evaluateDirectResponse(provider, data, metaDefenderMap);
                    computedOutcomes.push({provider, outcome});
                    cacheStorePayload.push({providerId: provider.id, lookupKey, outcome});
                } catch (error) {
                    console.warn(`[${provider.displayName}] Failed to evaluate shared response: ${error}`);
                    computedOutcomes.push({provider, outcome: protectionResult.resultTypes.FAILED});
                }
            }

            if (cacheStorePayload.length > 0) {
                cacheService.storeOutcomes(cacheStorePayload, expirationSeconds).catch(() => {
                });
            }

            for (const element of computedOutcomes) {
                const entry = element;
                console.info(`[${entry.provider.displayName}] URL result: ${entry.outcome} for ${targetUrl}`);
                emitResult(entry.provider, targetUrl, entry.outcome, onResult);
            }
        } catch (error) {
            for (let i = 0; i < activeLen; i++) {
                const provider = activeProviders[i];
                console.warn(`[${provider.displayName}] Failed to check URL: ${error}`);
                emitResult(provider, targetUrl, protectionResult.resultTypes.FAILED, onResult);
            }
        } finally {
            for (let i = 0; i < activeLen; i++) {
                const id = activeProviders[i].id;
                const lookupKey = lookupKeys.get(id);

                if (lookupKey) {
                    cacheService.clearProcessing(id, lookupKey);
                }
            }
        }
    };

    const abortTab = async tabId => {
        const controller = abortControllers.get(tabId);

        if (controller) {
            controller.abort('navigation-replaced');
            abortControllers.delete(tabId);
        }

        cacheService.clearProcessingByTab(tabId);
    };

    const scanUrl = async ({tabId, url, providers, expirationSeconds, onResult}) => {
        const parsedUrl = urlService.parseHttpUrl(url);

        if (!parsedUrl) {
            console.debug(`OspreyProviderEngine skipping invalid URL: ${url}`);
            return;
        }

        if (urlService.isInternalHostname(parsedUrl.hostname)) {
            return;
        }

        const individualProviders = [];
        const sharedGroups = new Map();
        let hasEnabled = false;

        for (const element of providers) {
            const provider = element;

            if (!provider.state.enabled) {
                continue;
            }

            hasEnabled = true;
            const groupId = provider.sharedRequestGroup;

            if (groupId) {
                let group = sharedGroups.get(groupId);

                if (!group) {
                    group = [];
                    sharedGroups.set(groupId, group);
                }

                group.push(provider);
            } else {
                individualProviders.push(provider);
            }
        }

        if (!hasEnabled) {
            return;
        }

        await abortTab(tabId);

        const controller = new AbortController();
        abortControllers.set(tabId, controller);

        const targetUrl = parsedUrl.toString();
        const globalAllowMatched = await cacheService.matchesGlobalPattern(parsedUrl);
        const tasks = [];

        for (const element of individualProviders) {
            tasks.push(fetchProviderResult(
                element,
                targetUrl,
                controller.signal,
                expirationSeconds,
                onResult,
                tabId,
                globalAllowMatched,
            ));
        }

        for (const group of sharedGroups.values()) {
            tasks.push(fetchSharedProviderResults(
                group,
                targetUrl,
                controller.signal,
                expirationSeconds,
                onResult,
                tabId,
                globalAllowMatched,
            ));
        }

        await Promise.allSettled(tasks);

        if (abortControllers.get(tabId) === controller) {
            abortControllers.delete(tabId);
        }
    };

    return Object.freeze({
        scanUrl,
        abortTab,
    });
})();
