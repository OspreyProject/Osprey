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

globalThis.OspreyProviderEngine = (() => {
    // Global variables
    const cacheService = globalThis.OspreyCacheService;
    const dnsValidator = globalThis.OspreyDnsValidator;
    const protectionResult = globalThis.OspreyProtectionResult;
    const requestBuilder = globalThis.OspreyRequestBuilder;
    const responseRuleEngine = globalThis.OspreyResponseRuleEngine;
    const timedSignal = globalThis.OspreyTimedSignal;
    const urlService = globalThis.OspreyUrlService;

    const abortControllers = new Map();

    const normalizeCandidateNames = names => Array.isArray(names)
        ? names.map(value => String(value || '').trim().toLowerCase()).filter(Boolean)
        : [];
    const normalizeLookupName = value => String(value || '').trim().toLowerCase();

    const createSharedResponseIndexes = responseBody => {
        const metaDefenderByProvider = new Map();
        const metaDefenderSources = responseBody?.data?.[0]?.lookup_results?.sources;

        if (Array.isArray(metaDefenderSources)) {
            for (const source of metaDefenderSources) {
                const key = normalizeLookupName(source?.provider);

                if (key) {
                    metaDefenderByProvider.set(key, source);
                }
            }
        }

        const apiVoidByEngine = new Map();
        const apiVoidEngines = responseBody?.blacklists?.engines;
        const apiVoidEngineList = apiVoidEngines && typeof apiVoidEngines === 'object' ? Object.values(apiVoidEngines) : [];

        if (Array.isArray(apiVoidEngineList)) {
            for (const engine of apiVoidEngineList) {
                const key = normalizeLookupName(engine?.name);

                if (key) {
                    apiVoidByEngine.set(key, engine);
                }
            }
        }

        return Object.freeze({metaDefenderByProvider, apiVoidByEngine});
    };

    const getMetaDefenderProviderBlock = (provider, responseBody, indexes = null) => {
        const providerNames = normalizeCandidateNames(provider?.metaDefenderProviderNames);

        if (providerNames.length === 0) {
            return null;
        }

        if (indexes?.metaDefenderByProvider instanceof Map) {
            for (const providerName of providerNames) {
                if (indexes.metaDefenderByProvider.has(providerName)) {
                    return indexes.metaDefenderByProvider.get(providerName) || null;
                }
            }
            return null;
        }

        const sources = responseBody?.data?.[0]?.lookup_results?.sources;

        if (!Array.isArray(sources)) {
            return null;
        }

        return sources.find(source => providerNames.includes(normalizeLookupName(source?.provider))) || null;
    };

    const getAPIVoidProviderBlock = (provider, responseBody, indexes = null) => {
        const engineNames = normalizeCandidateNames(provider?.apiVoidEngineNames);

        if (engineNames.length === 0) {
            return null;
        }

        if (indexes?.apiVoidByEngine instanceof Map) {
            for (const engineName of engineNames) {
                if (indexes.apiVoidByEngine.has(engineName)) {
                    return indexes.apiVoidByEngine.get(engineName) || null;
                }
            }
            return null;
        }

        const engines = responseBody?.blacklists?.engines;
        const engineList = engines && typeof engines === 'object' ? Object.values(engines) : [];

        if (!Array.isArray(engineList)) {
            return null;
        }

        return engineList.find(engine => engineNames.includes(normalizeLookupName(engine?.name))) || null;
    };

    const getRuleEvaluationBody = (provider, responseBody, indexes = null) => {
        if (provider?.responseRuleScope === 'metadefender_provider_block') {
            return getMetaDefenderProviderBlock(provider, responseBody, indexes);
        }

        if (provider?.responseRuleScope === 'apivoid_provider_block') {
            return getAPIVoidProviderBlock(provider, responseBody, indexes);
        }

        return responseBody;
    };

    const evaluateDirectResponse = (provider, responseBody, indexes = null) => {
        const evaluationBody = getRuleEvaluationBody(provider, responseBody, indexes);

        if (evaluationBody === null || evaluationBody === undefined) {
            return protectionResult.resultTypes.ALLOWED;
        }

        const matched = responseRuleEngine.evaluateRules(evaluationBody, provider.responseRules || []);
        const normalized = String(matched || 'KNOWN_SAFE').toUpperCase();
        let result;

        if (normalized === 'KNOWN_SAFE') {
            result = protectionResult.resultTypes.KNOWN_SAFE;
        } else if (normalized === 'ALLOWED') {
            result = protectionResult.resultTypes.ALLOWED;
        } else {
            result = protectionResult.fromProviderString(normalized.toLowerCase());
        }
        return result;
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
        protectionResult.blockingResults.has(outcome) ?
            await cacheService.markBlocked(provider.id, lookupKey, outcome, expirationSeconds) :
            await cacheService.markAllowed(provider.id, lookupKey, expirationSeconds);

        console.info(`[${provider.displayName}] URL result: ${outcome} for ${targetUrl}`);
        emitResult(provider, targetUrl, outcome, onResult);
    };

    const fetchProviderResult = async (provider, targetUrl, parentSignal, expirationSeconds, onResult, tabId = 0, options = {}) => {
        const lookupKey = urlService.lookupValueForTarget(targetUrl, provider.lookupTarget || 'url');

        if (!lookupKey) {
            console.warn(`OspreyProviderEngine could not derive a lookup key for provider '${provider.id}' and URL '${targetUrl}'`);
            return;
        }

        if (options.globalAllowMatched && !provider.bypassBlockingThreshold) {
            await cacheService.markAllowed(provider.id, lookupKey, expirationSeconds);
            emitResult(provider, targetUrl, protectionResult.resultTypes.ALLOWED, onResult);
            return;
        }

        const blockedEntry = await cacheService.getBlockedEntry(provider.id, lookupKey);

        if (blockedEntry?.result) {
            console.debug(`[${provider.displayName}] URL is already blocked: ${targetUrl}`);
            emitResult(provider, targetUrl, blockedEntry.result, onResult);
            return;
        }

        if (cacheService.isProcessing(provider.id, lookupKey)) {
            console.debug(`[${provider.displayName}] URL is already processing: ${targetUrl}`);
            emitResult(provider, targetUrl, protectionResult.resultTypes.WAITING, onResult);
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

    const fetchSharedProviderResults = async (providers, targetUrl, parentSignal, expirationSeconds, onResult, tabId = 0, options = {}) => {
        if (!Array.isArray(providers) || providers.length === 0) {
            return;
        }

        const lookupKeys = new Map();
        const activeProviders = [];

        for (const provider of providers) {
            const lookupKey = urlService.lookupValueForTarget(targetUrl, provider.lookupTarget || 'url');

            if (!lookupKey) {
                console.warn(`OspreyProviderEngine could not derive a lookup key for provider '${provider.id}' and URL '${targetUrl}'`);
                continue;
            }

            lookupKeys.set(provider.id, lookupKey);

            if (options.globalAllowMatched && !provider.bypassBlockingThreshold) {
                await cacheService.markAllowed(provider.id, lookupKey, expirationSeconds);
                emitResult(provider, targetUrl, protectionResult.resultTypes.ALLOWED, onResult);
                continue;
            }

            const blockedEntry = await cacheService.getBlockedEntry(provider.id, lookupKey);

            if (blockedEntry?.result) {
                console.debug(`[${provider.displayName}] URL is already blocked: ${targetUrl}`);
                emitResult(provider, targetUrl, blockedEntry.result, onResult);
                continue;
            }

            if (cacheService.isProcessing(provider.id, lookupKey)) {
                console.debug(`[${provider.displayName}] URL is already processing: ${targetUrl}`);
                emitResult(provider, targetUrl, protectionResult.resultTypes.WAITING, onResult);
                continue;
            }

            cacheService.markProcessing(provider.id, lookupKey, tabId);
            activeProviders.push(provider);
        }

        if (activeProviders.length === 0) {
            return;
        }

        try {
            const data = await fetchJsonResponse(activeProviders[0], targetUrl, parentSignal);
            const indexes = createSharedResponseIndexes(data);
            const computedOutcomes = [];

            for (const provider of activeProviders) {
                try {
                    computedOutcomes.push({
                        provider,
                        lookupKey: lookupKeys.get(provider.id),
                        outcome: evaluateDirectResponse(provider, data, indexes),
                    });
                } catch (error) {
                    console.warn(`[${provider.displayName}] Failed to evaluate shared response: ${error}`);
                    computedOutcomes.push({
                        provider,
                        lookupKey: lookupKeys.get(provider.id),
                        outcome: protectionResult.resultTypes.FAILED,
                        skipCache: true,
                    });
                }
            }

            await cacheService.storeOutcomes(
                computedOutcomes.filter(entry => !entry.skipCache).map(entry => ({
                    providerId: entry.provider.id,
                    lookupKey: entry.lookupKey,
                    outcome: entry.outcome,
                })),
                expirationSeconds
            );

            for (const entry of computedOutcomes) {
                console.info(`[${entry.provider.displayName}] URL result: ${entry.outcome} for ${targetUrl}`);
                emitResult(entry.provider, targetUrl, entry.outcome, onResult);
            }
        } catch (error) {
            for (const provider of activeProviders) {
                console.warn(`[${provider.displayName}] Failed to check URL: ${error}`);
                emitResult(provider, targetUrl, protectionResult.resultTypes.FAILED, onResult);
            }
        } finally {
            for (const provider of activeProviders) {
                const lookupKey = lookupKeys.get(provider.id);

                if (lookupKey) {
                    cacheService.clearProcessing(provider.id, lookupKey);
                }
            }
        }
    };

    const abortTab = async tabId => {
        const controller = abortControllers.get(tabId);

        if (controller) {
            try {
                controller.abort('navigation-replaced');
            } catch {
                controller.abort();
            }

            abortControllers.delete(tabId);
        }

        cacheService.clearProcessingByTab(tabId);
    };

    const scanUrl = async ({tabId, url, providers, expirationSeconds, onResult}) => {
        const parsedUrl = urlService.parseHttpUrl(url);

        if (!parsedUrl || urlService.isInternalHostname(parsedUrl.hostname)) {
            return;
        }

        const enabledProviders = providers.filter(provider => provider.state.enabled);

        if (enabledProviders.length === 0) {
            return;
        }

        await abortTab(tabId);

        const controller = new AbortController();
        abortControllers.set(tabId, controller);

        if (!await dnsValidator.isResolvable(parsedUrl.hostname, controller.signal, tabId)) {
            abortControllers.delete(tabId);
            return;
        }

        const targetUrl = parsedUrl.toString();
        const globalAllowMatched = await cacheService.matchesGlobalPattern(parsedUrl);
        const sharedGroups = new Map();
        const individualProviders = [];

        for (const provider of enabledProviders) {
            const groupId = String(provider?.sharedRequestGroup || '');

            if (!groupId) {
                individualProviders.push(provider);
                continue;
            }

            if (!sharedGroups.has(groupId)) {
                sharedGroups.set(groupId, []);
            }

            sharedGroups.get(groupId).push(provider);
        }

        const tasks = [
            ...individualProviders.map(provider => fetchProviderResult(
                provider,
                targetUrl,
                controller.signal,
                expirationSeconds,
                onResult,
                tabId,
                {globalAllowMatched}
            )),
            ...Array.from(sharedGroups.values()).map(group => fetchSharedProviderResults(
                group,
                targetUrl,
                controller.signal,
                expirationSeconds,
                onResult,
                tabId,
                {globalAllowMatched}
            )),
        ];

        await Promise.allSettled(tasks);

        if (abortControllers.get(tabId) === controller) {
            abortControllers.delete(tabId);
        }
    };

    // Public API
    return Object.freeze({
        scanUrl,
        abortTab,
    });
})();
