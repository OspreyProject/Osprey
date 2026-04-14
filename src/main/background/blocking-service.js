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

globalThis.OspreyBlockingService = (() => {
    // Global variables
    const badgeService = globalThis.OspreyBadgeService;
    const browserAPI = globalThis.OspreyBrowserAPI;
    const cacheService = globalThis.OspreyCacheService;
    const messages = globalThis.OspreyMessageBus.Messages;
    const providerCatalog = globalThis.OspreyProviderCatalog;
    const providerEngine = globalThis.OspreyProviderEngine;
    const providerRuntimeFactory = globalThis.OspreyProviderRuntimeFactory;
    const resultAggregationService = globalThis.OspreyResultAggregationService;
    const urlService = globalThis.OspreyUrlService;

    const inFlightNavigations = new Map();
    const suppressedNavigations = new Map();
    const suppressedNavDuration = 2500;
    const lastBlockedPayloadByTab = new Map();
    const verboseResultLogging = false;
    const buildNavigationKey = (tabId, frameId, normalizedUrl) => `${tabId}::${frameId}::${normalizedUrl}`;
    const buildSuppressedNavigationKey = (tabId, normalizedUrl) => `${tabId}::${normalizedUrl}`;
    const getBlockingThreshold = enabledCount => enabledCount >= 4 ? 2 : 1;
    const getProvidersById = runtime => new Map((runtime?.providers || []).map(provider => [provider.id, provider]));
    const getApplicableEnabledProviders = (runtime, result) => (runtime?.providers || []).filter(provider =>
        provider.state.enabled && providerCatalog.supportsBlockingResult(provider, result)
    );
    const getBlockedCount = (runtime, blockedContext, result) => {
        if (!runtime || !Array.isArray(blockedContext?.origins) || blockedContext.origins.length === 0) {
            return 0;
        }

        const providersById = getProvidersById(runtime);
        return blockedContext.origins.filter(origin => providerCatalog.supportsBlockingResult(providersById.get(origin), result)).length;
    };
    const shouldBypassBlockingThreshold = (runtime, blockedContext, result) => {
        if (!runtime || !Array.isArray(blockedContext?.origins) || blockedContext.origins.length === 0) {
            return false;
        }

        const providersById = getProvidersById(runtime);
        return blockedContext.origins.some(origin => {
            const provider = providersById.get(origin);
            return providerCatalog.supportsBlockingResult(provider, result) && provider?.bypassBlockingThreshold === true;
        });
    };
    const failureResult = Object.freeze({ok: false});
    const isMissingTabError = error => /No tab with id/i.test(String(error?.message || error || ''));

    const pruneSuppressedNavigations = () => {
        const now = Date.now();

        for (const [key, timestamp] of suppressedNavigations.entries()) {
            if (now - timestamp > suppressedNavDuration) {
                suppressedNavigations.delete(key);
            }
        }
    };

    const rememberSuppressedNavigation = (tabId, normalizedUrl) => {
        if (typeof tabId !== "number" || typeof normalizedUrl !== "string" || normalizedUrl.length === 0) {
            return;
        }

        suppressedNavigations.set(buildSuppressedNavigationKey(tabId, normalizedUrl), Date.now());
    };

    const shouldSkipSuppressedNavigation = (tabId, frameId, normalizedUrl) => {
        if (frameId !== 0) {
            return false;
        }

        pruneSuppressedNavigations();

        const key = buildSuppressedNavigationKey(tabId, normalizedUrl);

        if (!suppressedNavigations.has(key)) {
            return false;
        }

        suppressedNavigations.delete(key);
        return true;
    };

    const getBlockedContextPayload = context => {
        if (!context) {
            return {
                messageType: messages.BLOCKED_COUNTER_PONG,
                count: 0,
                systems: [],
                primaryOrigin: null,
                primaryResult: null,
            };
        }

        const systems = context.origins.filter(origin => origin !== context.primaryOrigin);

        return {
            messageType: messages.BLOCKED_COUNTER_PONG,
            count: systems.length,
            systems,
            primaryOrigin: context.primaryOrigin,
            primaryResult: context.primaryResult,
        };
    };

    const pushBlockedContextUpdate = async tabId => {
        if (!resultAggregationService.isRedirected(tabId)) {
            lastBlockedPayloadByTab.delete(tabId);
            return;
        }

        const payload = {
            ...getBlockedContextPayload(resultAggregationService.getBlockedContext(tabId)),
            tabId,
        };
        const payloadKey = JSON.stringify(payload);

        if (lastBlockedPayloadByTab.get(tabId) === payloadKey) {
            return;
        }

        const tab = await browserAPI.tabsGet(tabId).catch(() => null);

        if (!tab?.url || !urlService.isWarningPageUrl(tab.url)) {
            return;
        }

        lastBlockedPayloadByTab.set(tabId, payloadKey);
        await browserAPI.runtimeSendMessage(payload).catch(() => {
        });
    };

    const clearBlockedUI = async tabId => {
        resultAggregationService.clear(tabId);
        lastBlockedPayloadByTab.delete(tabId);
        await badgeService.clear(tabId);
    };

    const sendToSafety = async tabId => {
        await providerEngine.abortTab(tabId);
        await clearBlockedUI(tabId);

        try {
            await browserAPI.tabsUpdate(tabId, {url: "about:newtab"});
        } catch {
            console.warn(`Failed to navigate to about:newtab for tabId ${tabId}, navigating to fallback URL instead`);

            await browserAPI.tabsUpdate(tabId, {url: "https://www.google.com"}).catch(error => {
                console.error(`Failed to navigate to fallback URL for tabId ${tabId}`, error);
            });
        }
    };

    const failClosed = async (action, value, reason, tabId) => {
        console.warn(`Failed to ${action} for URL ${value} (Reason: ${reason})`);
        await sendToSafety(tabId);
        return failureResult;
    };

    const navigateWithSafetyFallback = async (tabId, targetUrl, failureMessage) => {
        try {
            await browserAPI.tabsUpdate(tabId, {url: targetUrl});
            return true;
        } catch (error) {
            console.error(failureMessage, error);
            await sendToSafety(tabId);
            return false;
        }
    };

    const handleProtectionResult = async (tabId, navigationUrl, runtime, protectionResult) => {
        if (!protectionResult?.isBlocking) {
            return;
        }

        const frameZeroUrl = resultAggregationService.getFrameZeroUrl(tabId);

        if (frameZeroUrl && !urlService.areEquivalentURLs(frameZeroUrl, navigationUrl)) {
            console.debug(`Ignoring stale blocking result for URL ${navigationUrl} in tabId ${tabId} because frame zero URL is different: ${frameZeroUrl}`);
            return;
        }

        resultAggregationService.recordBlockingResult(tabId, navigationUrl, protectionResult.origin, protectionResult.result);
        const blockedContext = resultAggregationService.getBlockedContext(tabId);

        await badgeService.syncWithContext(tabId, blockedContext);

        const applicableEnabledProviders = getApplicableEnabledProviders(runtime, protectionResult.result);
        const thresholdBypassed = shouldBypassBlockingThreshold(runtime, blockedContext, protectionResult.result);
        const requiredBlockedCount = thresholdBypassed ? 1 : getBlockingThreshold(applicableEnabledProviders.length);

        if (getBlockedCount(runtime, blockedContext, protectionResult.result) < requiredBlockedCount) {
            return;
        }

        if (resultAggregationService.isRedirected(tabId)) {
            await pushBlockedContextUpdate(tabId);
            return;
        }

        resultAggregationService.markRedirected(tabId);
        lastBlockedPayloadByTab.delete(tabId);

        const warningUrl = urlService.buildWarningPageUrl({
            url: navigationUrl,
            continueUrl: navigationUrl,
            origin: protectionResult.origin,
            result: protectionResult.result,
            tabId,
        });

        await browserAPI.tabsUpdate(tabId, {
            url: warningUrl
        }).then(() => pushBlockedContextUpdate(tabId)).catch(error => {
            if (isMissingTabError(error)) {
                console.debug(`Skipping warning-page navigation because tabId ${tabId} no longer exists`);
                return;
            }

            console.error(`Failed to navigate to record ${tabId}`, error);
        });
    };

    const handleNavigation = async details => {
        const parsed = urlService.parseHttpUrl(details?.url);

        if (!parsed || typeof details?.tabId !== "number") {
            return;
        }

        const normalizedUrl = urlService.normalizeUrl(parsed);

        if (!normalizedUrl) {
            return;
        }

        const frameId = typeof details?.frameId === "number" ? details.frameId : 0;
        const navigationKey = buildNavigationKey(details.tabId, frameId, normalizedUrl);

        if (shouldSkipSuppressedNavigation(details.tabId, frameId, normalizedUrl) || inFlightNavigations.has(navigationKey)) {
            return;
        }

        const navigationToken = Symbol(navigationKey);
        inFlightNavigations.set(navigationKey, navigationToken);

        try {
            const runtime = await providerRuntimeFactory.createRuntime();
            const enabledProviders = runtime.providers.filter(provider => provider.state.enabled);

            if (enabledProviders.length === 0) {
                return;
            }

            if (runtime.effectiveState.app.hidePopupPanel && details.url.includes("/pages/popup/popup-page.html")) {
                console.warn(`Failed to navigate to record ${details.url} (Reason: protection options are hidden)`);
                return;
            }

            if (frameId !== 0 && runtime.effectiveState.app.ignoreFrameNavigation) {
                console.debug(`Ignoring navigation for ${details.url} (tabId: ${details.tabId} frameId: ${frameId})`);
                return;
            }

            if (frameId === 0) {
                resultAggregationService.beginNavigation(details.tabId, normalizedUrl, 0);
                lastBlockedPayloadByTab.delete(details.tabId);
                await badgeService.clear(details.tabId);
            }

            const startTime = Date.now();
            if (verboseResultLogging) {
                console.info("Checking URL:", normalizedUrl);
            }

            await providerEngine.scanUrl({
                tabId: details.tabId,
                url: normalizedUrl,
                providers: runtime.providers,
                expirationSeconds: runtime.effectiveState.app.cacheExpirationSeconds,

                onResult: protectionResult => {
                    if (verboseResultLogging) {
                        const duration = Date.now() - startTime;
                        const providerName = protectionResult.providerName || protectionResult.origin || 'unknown';
                        const resultName = String(protectionResult.result || 'failed').toUpperCase();
                        console.info(`[${providerName}] Result for ${normalizedUrl}: ${resultName} (${duration}ms)`);
                    }

                    handleProtectionResult(details.tabId, normalizedUrl, runtime, protectionResult).catch(error => {
                        console.error(`Failed to handle protection result for URL ${details.url} in tabId ${details.tabId}`, error);
                    });
                },
            });
        } finally {
            if (inFlightNavigations.get(navigationKey) === navigationToken) {
                inFlightNavigations.delete(navigationKey);
            }
        }
    };

    const allowWebsite = async (tabId, blockedUrl, continueUrl) => {
        const parsed = urlService.parseHttpUrl(blockedUrl);

        if (!parsed) {
            return failClosed("allow website", blockedUrl, "invalid URL", tabId);
        }

        const runtime = await providerRuntimeFactory.createRuntime();
        const hostname = parsed.hostname;
        const labels = hostname.split(".");
        const allowPattern = labels.length >= 3 ? `*.${labels.slice(1).join(".")}` : `*.${hostname}`;
        const normalizedUrl = urlService.normalizeUrl(blockedUrl) || blockedUrl;
        const normalizedHostname = urlService.canonicalizeHostname(parsed.hostname);

        await cacheService.allowPattern(allowPattern);
        await cacheService.clearBlockedForLookup(normalizedUrl);

        for (const provider of runtime.providers) {
            const lookupKey = urlService.lookupValueForTarget(blockedUrl, provider.lookupTarget || "url");

            if (lookupKey && lookupKey !== normalizedUrl) {
                await cacheService.clearBlockedForProviderLookup(provider.id, lookupKey);
            }
        }

        if (normalizedHostname) {
            await cacheService.clearBlockedForLookup(normalizedHostname);
        }

        rememberSuppressedNavigation(tabId, normalizedUrl);

        const navigationSucceeded = await navigateWithSafetyFallback(
            tabId,
            continueUrl || blockedUrl,
            `Failed to navigate to ${continueUrl || blockedUrl} for tabId ${tabId} after allowing website`
        );

        if (navigationSucceeded) {
            providerEngine.abortTab(tabId).catch(() => {
            });
            clearBlockedUI(tabId).catch(() => {
            });
        }

        return {
            ok: true,
            navigated: navigationSucceeded
        };
    };

    const continueToWebsite = async (tabId, blockedUrl, origin, continueUrl) => {
        const lookupSourceUrl = blockedUrl || continueUrl;
        const parsed = urlService.parseHttpUrl(lookupSourceUrl);

        if (!parsed) {
            return failClosed("continue to website", lookupSourceUrl, "invalid URL", tabId);
        }

        if (typeof origin !== "string" || origin.length === 0) {
            return failClosed("continue to website", lookupSourceUrl, "missing provider origin", tabId);
        }

        const runtime = await providerRuntimeFactory.createRuntime();
        const provider = runtime.providers.find(item => item.id === origin);

        if (!provider) {
            return failClosed("continue to website", lookupSourceUrl, `unknown provider '${origin}'`, tabId);
        }

        const lookupKey = urlService.lookupValueForTarget(lookupSourceUrl, provider.lookupTarget || "url");

        if (!lookupKey) {
            return failClosed("continue to website", lookupSourceUrl, "failed to derive lookup key", tabId);
        }

        await cacheService.markAllowed(
            provider.id,
            lookupKey,
            runtime.effectiveState.app.cacheExpirationSeconds
        );

        await cacheService.clearBlockedForProviderLookup(provider.id, lookupKey);

        const nextContext = resultAggregationService.removeOrigin(tabId, origin);

        if (nextContext) {
            resultAggregationService.markRedirected(tabId);
            lastBlockedPayloadByTab.delete(tabId);
            await badgeService.syncWithContext(tabId, nextContext);
            await pushBlockedContextUpdate(tabId);

            return {
                ok: true,
                navigated: false,
                context: nextContext
            };
        }

        const resumeUrl = urlService.normalizeUrl(continueUrl || blockedUrl) || continueUrl || blockedUrl;
        rememberSuppressedNavigation(tabId, resumeUrl);

        const navigationSucceeded = await navigateWithSafetyFallback(
            tabId,
            continueUrl || blockedUrl,
            `Failed to navigate to ${continueUrl || blockedUrl} for tabId ${tabId} after continuing to website`
        );

        if (navigationSucceeded) {
            providerEngine.abortTab(tabId).catch(() => {
            });
            clearBlockedUI(tabId).catch(() => {
            });
        }

        return {
            ok: true,
            navigated: navigationSucceeded,
            context: null
        };
    };

    const reportWebsite = async reportUrl => {
        if (typeof reportUrl !== "string" || reportUrl.length === 0) {
            console.warn(`Failed to report website for URL ${reportUrl} (Reason: invalid URL)`);
            return failureResult;
        }

        try {
            const parsed = new URL(reportUrl);

            if (parsed.protocol === "http:" || parsed.protocol === "https:" || parsed.protocol === "mailto:") {
                await browserAPI.tabsCreate({url: reportUrl});
            } else {
                console.warn(`OspreyBlockingService ignored unsupported report protocol '${parsed.protocol}'`);
            }
            return {ok: true};
        } catch {
            console.warn(`Failed to report website for URL ${reportUrl} (Reason: URL parsing failed)`);
            return failureResult;
        }
    };

    // Public API
    return Object.freeze({
        handleNavigation,
        allowWebsite,
        continueToWebsite,
        reportWebsite,
        sendToSafety,
        pushBlockedContextUpdate,
    });
})();
