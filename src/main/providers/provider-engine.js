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

globalThis.OspreyProviderEngine = (() => {
    const cacheService = globalThis.OspreyCacheService;
    const protectionResult = globalThis.OspreyProtectionResult;
    const requestBuilder = globalThis.OspreyRequestBuilder;
    const responseRuleEngine = globalThis.OspreyResponseRuleEngine;
    const timedSignal = globalThis.OspreyTimedSignal;
    const urlService = globalThis.OspreyUrlService;

    const abortControllers = new Map();
    const pendingResults = new Map();

    const pendingFor = (providerId, lookupKey) => pendingResults.get(providerId)?.get(lookupKey);
    const beginPending = (providerId, lookupKey) => {
        let byKey = pendingResults.get(providerId);

        if (!byKey) {
            byKey = new Map();
            pendingResults.set(providerId, byKey);
        }

        let resolve;
        const promise = new Promise(done => {
            resolve = done;
        });

        byKey.set(lookupKey, {promise, resolve});
    };
    const finishPending = (providerId, lookupKey, outcome) => {
        const byKey = pendingResults.get(providerId);
        const pending = byKey?.get(lookupKey);

        if (pending) {
            byKey.delete(lookupKey);

            if (byKey.size === 0) {
                pendingResults.delete(providerId);
            }
            pending.resolve(outcome);
        }
    };

    const evaluateDirectResponse = (provider, responseBody) => {
        if (responseBody == null) {
            return protectionResult.resultTypes.ALLOWED;
        }

        const matched = responseRuleEngine.evaluateRules(responseBody, provider.responseRules || []);

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

    const allowedResult = protectionResult.resultTypes.ALLOWED;
    const knownSafeResult = protectionResult.resultTypes.KNOWN_SAFE;
    const failedResult = protectionResult.resultTypes.FAILED;

    const resolveProxyBuiltinOutcome = (provider, data) => {
        const categories = provider.blockCategoryState;
        const hasCategories = Boolean(categories) && Object.keys(categories).length > 0;

        if (!hasCategories) {
            return protectionResult.fromProviderString(data?.result);
        }

        const list = Array.isArray(data?.results) && data.results.length > 0
            ? data.results
            : typeof data?.result === 'string' && data.result ? [data.result] : null;

        if (!list) {
            return failedResult;
        }

        const blockingCandidates = [];
        let sawSoftCategory = false;
        let sawAllowSignal = false;
        let sawFailed = false;

        for (const raw of list) {
            const value = typeof raw === 'string' ? raw.trim().toLowerCase() : '';

            if (!value) {
                continue;
            }

            if (value in categories) {
                sawSoftCategory = true;

                if (categories[value] === true && protectionResult.blockingResults.has(value)) {
                    blockingCandidates.push(value);
                }
                continue;
            }

            if (protectionResult.blockingResults.has(value)) {
                blockingCandidates.push(value);
                continue;
            }

            if (value === allowedResult || value === knownSafeResult || value === 'safe') {
                sawAllowSignal = true;
            } else if (value === failedResult) {
                sawFailed = true;
            }
        }

        const blockingResult = protectionResult.mostSevere(blockingCandidates);

        if (blockingResult) {
            return blockingResult;
        }

        if (sawSoftCategory || sawAllowSignal) {
            return allowedResult;
        }
        return sawFailed ? failedResult : allowedResult;
    };

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
        } else if (outcome !== failedResult) {
            cacheService.markAllowed(provider.id, lookupKey, expirationSeconds).catch(() => {
                // ignored
            });
        }

        console.info(`[${provider.displayName}] URL result: ${outcome} for ${targetUrl}`);
        emitResult(provider, targetUrl, outcome, onResult);
    };

    const checkProviderCache = async (
        provider, lookupKey, targetUrl, onResult, globalAllowMatched, parentSignal, pendingReplays, retry
    ) => {
        if (globalAllowMatched) {
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

        const pending = pendingFor(provider.id, lookupKey);

        if (pending) {
            console.debug(`[${provider.displayName}] URL is already processing: ${targetUrl}`);
            emitResult(provider, targetUrl, protectionResult.resultTypes.WAITING, onResult);
            if (pendingReplays) {
                pendingReplays.push(pending.promise.then(outcome => {
                    if (parentSignal.aborted) {
                        return;
                    }
                    return outcome === null ? retry() : emitResult(provider, targetUrl, outcome, onResult);
                }));
                return false;
            }
            const outcome = await pending.promise;

            if (parentSignal.aborted) {
                return false;
            }

            if (outcome !== null) {
                emitResult(provider, targetUrl, outcome, onResult);
                return false;
            }
        }
        beginPending(provider.id, lookupKey);
        return true;
    };

    const isNavigationReplaced = (error, parentSignal) =>
        error === 'navigation-replaced' ||
        parentSignal?.aborted && parentSignal.reason === 'navigation-replaced';

    const fetchProviderResult = async (provider, targetUrl, parentSignal, expirationSeconds, onResult, tabId, globalAllowMatched) => {
        const lookupKey = urlService.lookupValueForTarget(targetUrl, provider.lookupTarget || 'url');

        if (!lookupKey) {
            console.warn(`OspreyProviderEngine could not derive a lookup key for provider '${provider.id}' and URL '${targetUrl}'`);
            return;
        }

        if (!await checkProviderCache(provider, lookupKey, targetUrl, onResult, globalAllowMatched, parentSignal)) {
            return;
        }

        cacheService.markProcessing(provider.id, lookupKey, tabId);
        let finalOutcome = null;

        try {
            const data = await fetchJsonResponse(provider, targetUrl, parentSignal);

            const outcome = provider.kind === 'proxy_builtin' ?
                resolveProxyBuiltinOutcome(provider, data) :
                evaluateDirectResponse(provider, data);

            finalOutcome = outcome;
            await finalizeProviderResult(provider, lookupKey, targetUrl, expirationSeconds, onResult, outcome);
        } catch (error) {
            if (isNavigationReplaced(error, parentSignal)) {
                console.info(`[${provider.displayName}] Failed to check URL: ${error}`);
            } else {
                console.warn(`[${provider.displayName}] Failed to check URL: ${error}`);
            }

            finalOutcome = isNavigationReplaced(error, parentSignal) ? null : failedResult;
            emitResult(provider, targetUrl, failedResult, onResult);
        } finally {
            cacheService.clearProcessing(provider.id, lookupKey);
            finishPending(provider.id, lookupKey, finalOutcome);
        }
    };

    const fetchSharedProviderResults = async (providers, targetUrl, parentSignal, expirationSeconds, onResult, tabId, globalAllowMatched) => {
        const providersLen = providers.length;

        if (providersLen === 0) {
            return;
        }

        const lookupKeys = new Map();
        const activeProviders = [];
        const finalOutcomes = new Map();
        const pendingReplays = [];

        try {
            for (let i = 0; i < providersLen; i++) {
                const provider = providers[i];
                const lookupKey = urlService.lookupValueForTarget(targetUrl, provider.lookupTarget || 'url');

                if (!lookupKey) {
                    console.warn(`OspreyProviderEngine could not derive a lookup key for provider '${provider.id}' and URL '${targetUrl}'`);
                    continue;
                }

                lookupKeys.set(provider.id, lookupKey);

                if (!await checkProviderCache(
                    provider, lookupKey, targetUrl, onResult, globalAllowMatched, parentSignal,
                    pendingReplays,
                    () => fetchSharedProviderResults(
                        [provider], targetUrl, parentSignal, expirationSeconds, onResult, tabId, globalAllowMatched
                    ),
                )) {
                    continue;
                }
                cacheService.markProcessing(provider.id, lookupKey, tabId);
                activeProviders.push(provider);
            }
        } catch (error) {
            // A cache read failed part-way through. Every lookup this call already claimed must be
            // released, or later lookups for the same key would wait on it forever.
            for (const provider of activeProviders) {
                const lookupKey = lookupKeys.get(provider.id);
                cacheService.clearProcessing(provider.id, lookupKey);
                finishPending(provider.id, lookupKey, null);
            }
            throw error;
        }

        const activeLen = activeProviders.length;

        if (activeLen === 0) {
            await Promise.all(pendingReplays);
            return;
        }

        try {
            const data = await fetchJsonResponse(activeProviders[0], targetUrl, parentSignal);
            const computedOutcomes = [];
            const cacheStorePayload = [];

            for (let i = 0; i < activeLen; i++) {
                const provider = activeProviders[i];
                const lookupKey = lookupKeys.get(provider.id);

                try {
                    const outcome = evaluateDirectResponse(provider, data);
                    finalOutcomes.set(provider.id, outcome);
                    computedOutcomes.push({provider, outcome});
                    cacheStorePayload.push({providerId: provider.id, lookupKey, outcome});
                } catch (error) {
                    console.warn(`[${provider.displayName}] Failed to evaluate shared response: ${error}`);
                    finalOutcomes.set(provider.id, failedResult);
                    computedOutcomes.push({provider, outcome: failedResult});
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

                if (isNavigationReplaced(error, parentSignal)) {
                    console.info(`[${provider.displayName}] Failed to check URL: ${error}`);
                } else {
                    console.warn(`[${provider.displayName}] Failed to check URL: ${error}`);
                    finalOutcomes.set(provider.id, failedResult);
                }

                emitResult(provider, targetUrl, failedResult, onResult);
            }
        } finally {
            for (let i = 0; i < activeLen; i++) {
                const id = activeProviders[i].id;
                const lookupKey = lookupKeys.get(id);

                if (lookupKey) {
                    cacheService.clearProcessing(id, lookupKey);
                    finishPending(id, lookupKey, finalOutcomes.get(id) ?? null);
                }
            }
        }
        await Promise.all(pendingReplays);
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

        if (!urlService.isAcceptableHost(parsedUrl.hostname) || urlService.isInternalHostname(parsedUrl.hostname)) {
            return;
        }

        const individualProviders = [];
        const sharedGroups = new Map();
        let hasEnabled = false;
        let managedProvider = null;

        for (const element of providers) {
            const provider = element;

            if (provider.kind === 'managed_local') {
                managedProvider = provider;
                continue;
            }

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

        const managedDecision = await cacheService.getManagedListDecision(parsedUrl);

        if (managedDecision.blocked && managedProvider) {
            await abortTab(tabId);
            emitResult(managedProvider, parsedUrl.toString(), protectionResult.resultTypes.MALICIOUS, onResult);
            return;
        }

        if (!hasEnabled) {
            return;
        }

        await abortTab(tabId);

        const controller = new AbortController();
        abortControllers.set(tabId, controller);

        const targetUrl = parsedUrl.toString();
        const globalAllowMatched = managedDecision.allowed || await cacheService.matchesGlobalPattern(parsedUrl);
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
