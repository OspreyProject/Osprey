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

globalThis.OspreyBlockingService = (() => {
    const badgeService = globalThis.OspreyBadgeService;
    const browserAPI = globalThis.OspreyBrowserAPI;
    const cacheService = globalThis.OspreyCacheService;
    const messages = globalThis.OspreyMessageBus.Messages;
    const providerEngine = globalThis.OspreyProviderEngine;
    const providerRuntimeFactory = globalThis.OspreyProviderRuntimeFactory;
    const resultAggregationService = globalThis.OspreyResultAggregationService;
    const urlService = globalThis.OspreyUrlService;

    const inFlightNavigations = new Map();
    const suppressedNavigations = new Map();
    const suppressedNavDuration = 2500;

    const lastBlockedSignatureByTab = new Map();
    const pendingBlockedPayloadByTab = new Map();
    const warningPortsByTab = new Map();

    const buildNavigationKey = (tabId, normalizedUrl) => `${tabId}::${normalizedUrl}`;

    const getBlockingThreshold = enabledCount => enabledCount >= 4 ? 2 : 1;

    const getPayloadSignature = p => `${p.count}|${p.primaryOrigin}|${p.primaryResult}|${p.systems.join(',')}`;

    const getBlockingAnalysis = (runtime, blockedContext, result) => {
        const blockedOrigins = blockedContext?.origins;
        const supportedOrigins = runtime?.blockingProviderIdsByResult?.[result];

        if (!supportedOrigins?.size || !blockedOrigins?.length) {
            return {
                blockedCount: 0,
                thresholdBypassed: false,
                requiredBlockedCount: 0,
            };
        }

        let blockedCount = 0;
        let thresholdBypassed = false;
        const providersById = runtime.providersById;

        for (let i = 0, len = blockedOrigins.length; i < len; i++) {
            const origin = blockedOrigins[i];

            if (supportedOrigins.has(origin)) {
                blockedCount++;

                if (!thresholdBypassed && providersById.get(origin)?.bypassBlockingThreshold) {
                    thresholdBypassed = true;
                }
            }
        }

        return {
            blockedCount,
            thresholdBypassed,
            requiredBlockedCount: thresholdBypassed ? 1 : getBlockingThreshold(supportedOrigins.size),
        };
    };

    const failureResult = Object.freeze({
        ok: false,
    });

    const pruneSuppressedNavigations = () => {
        const threshold = Date.now() - suppressedNavDuration;

        for (const [key, timestamp] of suppressedNavigations) {
            if (timestamp < threshold) {
                suppressedNavigations.delete(key);
            }
        }
    };

    const rememberSuppressedNavigation = (tabId, normalizedUrl) => {
        if (!tabId || !normalizedUrl) {
            return;
        }

        if (suppressedNavigations.size > 50) {
            pruneSuppressedNavigations();
        }

        suppressedNavigations.set(buildNavigationKey(tabId, normalizedUrl), Date.now());
    };

    const shouldSkipSuppressedNavigation = (tabId, normalizedUrl) => {
        const key = buildNavigationKey(tabId, normalizedUrl);
        const timestamp = suppressedNavigations.get(key);

        if (!timestamp) {
            return false;
        }

        suppressedNavigations.delete(key);
        return Date.now() - timestamp <= suppressedNavDuration;
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

        const {origins, primaryOrigin, primaryResult} = context;
        const systems = origins.filter(o => o !== primaryOrigin);

        return {
            messageType: messages.BLOCKED_COUNTER_PONG,
            count: systems.length,
            systems,
            primaryOrigin,
            primaryResult,
        };
    };

    const buildBlockedPayload = tabId => {
        const payload = getBlockedContextPayload(resultAggregationService.getBlockedContext(tabId));
        payload.tabId = tabId;
        return payload;
    };

    const sendCurrentBlockedContext = (tabId, port) => {
        try {
            const payload = buildBlockedPayload(tabId);
            port.postMessage(payload);
            lastBlockedSignatureByTab.set(tabId, getPayloadSignature(payload));
            badgeService.syncWithContext(tabId, resultAggregationService.getBlockedContext(tabId));
            badgeService.reapply(tabId);
        } catch {
            if (warningPortsByTab.get(tabId) === port) {
                warningPortsByTab.delete(tabId);
            }
        }
    };

    const pushBlockedContextUpdate = async tabId => {
        if (!resultAggregationService.isRedirected(tabId)) {
            pendingBlockedPayloadByTab.delete(tabId);
            lastBlockedSignatureByTab.delete(tabId);
            return;
        }

        const payload = buildBlockedPayload(tabId);
        const signature = getPayloadSignature(payload);
        const port = warningPortsByTab.get(tabId);

        if (!port || !resultAggregationService.isWarningPageReady(tabId)) {
            pendingBlockedPayloadByTab.set(tabId, signature);
            return;
        }

        badgeService.syncWithContext(tabId, resultAggregationService.getBlockedContext(tabId));

        if (lastBlockedSignatureByTab.get(tabId) === signature && !pendingBlockedPayloadByTab.has(tabId)) {
            return;
        }

        lastBlockedSignatureByTab.set(tabId, signature);
        pendingBlockedPayloadByTab.delete(tabId);

        try {
            port.postMessage(payload);
        } catch {
            if (warningPortsByTab.get(tabId) === port) {
                warningPortsByTab.delete(tabId);
            }
        }
    };

    const connectWarningPort = port => {
        const tabId = port?.sender?.tab?.id;

        if (typeof tabId !== 'number') {
            return;
        }

        warningPortsByTab.set(tabId, port);
        resultAggregationService.markWarningPageReady(tabId);

        port.onMessage.addListener(msg => {
            if (msg?.messageType === messages.BLOCKED_COUNTER_PING && warningPortsByTab.get(tabId) === port) {
                sendCurrentBlockedContext(tabId, port);
            }
        });

        port.onDisconnect.addListener(() => {
            if (warningPortsByTab.get(tabId) === port) {
                warningPortsByTab.delete(tabId);
            }
        });

        sendCurrentBlockedContext(tabId, port);
        pendingBlockedPayloadByTab.delete(tabId);
    };

    const clearBlockedUI = async tabId => {
        resultAggregationService.clear(tabId);
        lastBlockedSignatureByTab.delete(tabId);
        pendingBlockedPayloadByTab.delete(tabId);
        badgeService.clear(tabId);
    };

    const clearTab = tabId => {
        warningPortsByTab.delete(tabId);
        lastBlockedSignatureByTab.delete(tabId);
        pendingBlockedPayloadByTab.delete(tabId);
    };

    const markWarningPageReady = tabId => {
        resultAggregationService.markWarningPageReady(tabId);
        return pushBlockedContextUpdate(tabId);
    };

    const cleanupAfterNavigation = tabId => {
        providerEngine.abortTab(tabId).then(() => {
            // ignored
        });

        clearBlockedUI(tabId).then(() => {
            // ignored
        });
    };

    const sendToSafety = async tabId => {
        await providerEngine.abortTab(tabId);
        await clearBlockedUI(tabId);

        try {
            await browserAPI.tabsUpdate(tabId, {url: 'about:newtab'});
        } catch {
            await browserAPI.tabsUpdate(tabId, {url: 'https://www.google.com'}).then(() => {
                // ignored
            });
        }
    };

    const failClosed = async tabId => {
        await sendToSafety(tabId);
        return failureResult;
    };

    const navigateWithSafetyFallback = async (tabId, targetUrl) => {
        try {
            await browserAPI.tabsUpdate(tabId, {url: targetUrl});
            return true;
        } catch {
            await sendToSafety(tabId);
            return false;
        }
    };

    const handleProtectionResult = async (tabId, navigationUrl, runtime, protectionResult) => {
        if (!protectionResult?.isBlocking) {
            return;
        }

        const currentUrl = resultAggregationService.getFrameZeroUrl(tabId);

        if (currentUrl && currentUrl !== navigationUrl) {
            return;
        }

        resultAggregationService.recordBlockingResult(tabId, navigationUrl, protectionResult.origin, protectionResult.result);

        const blockedContext = resultAggregationService.getBlockedContext(tabId);
        const analysis = getBlockingAnalysis(runtime, blockedContext, protectionResult.result);

        if (analysis.blockedCount < analysis.requiredBlockedCount) {
            badgeService.syncWithContext(tabId, blockedContext);
            return;
        }

        badgeService.clear(tabId);

        if (resultAggregationService.isRedirected(tabId)) {
            await pushBlockedContextUpdate(tabId);
            return;
        }

        resultAggregationService.markRedirected(tabId);
        lastBlockedSignatureByTab.delete(tabId);

        const warningUrl = urlService.buildWarningPageUrl({
            url: navigationUrl,
            origin: protectionResult.origin,
            result: protectionResult.result,
            tabId,
        });

        await browserAPI.tabsUpdate(tabId, {url: warningUrl}).then(() => pushBlockedContextUpdate(tabId)).then(() => {
            // ignored
        });
    };

    const handleNavigation = async details => {
        const parsed = urlService.parseHttpUrl(details?.url);

        if (!parsed || typeof details?.tabId !== 'number') {
            return;
        }

        const normalizedUrl = urlService.normalizeUrl(parsed);
        const navKey = buildNavigationKey(details.tabId, normalizedUrl);

        if (shouldSkipSuppressedNavigation(details.tabId, normalizedUrl) || inFlightNavigations.has(navKey)) {
            return;
        }

        const token = {};
        inFlightNavigations.set(navKey, token);

        try {
            const runtime = await providerRuntimeFactory.createRuntime();

            if (!runtime.providers.some(p => p.state.enabled)) {
                return;
            }

            if (runtime.effectiveState.app.hidePopupPanel && details.url.includes('/pages/popup/popup-page.html')) {
                return;
            }

            resultAggregationService.beginNavigation(details.tabId);
            resultAggregationService.setFrameZeroUrl(details.tabId, normalizedUrl);
            lastBlockedSignatureByTab.delete(details.tabId);

            badgeService.clear(details.tabId);

            await providerEngine.scanUrl({
                tabId: details.tabId,
                url: normalizedUrl,
                providers: runtime.providers,
                expirationSeconds: runtime.effectiveState.app.cacheExpirationSeconds,
                onResult: res => handleProtectionResult(details.tabId, normalizedUrl, runtime, res).then(() => {
                    // ignored
                }),
            });
        } finally {
            if (inFlightNavigations.get(navKey) === token) {
                inFlightNavigations.delete(navKey);
            }
        }
    };

    const allowWebsite = async (tabId, blockedUrl) => {
        const parsed = urlService.parseHttpUrl(blockedUrl);

        if (!parsed) {
            return failClosed(tabId);
        }

        const runtime = await providerRuntimeFactory.createRuntime();
        const normalizedUrl = urlService.normalizeUrl(parsed);
        const pattern = '*.' + urlService.canonicalizeHostname(parsed.hostname);

        cacheService.allowPattern(pattern).then(() => {
            // ignored
        });

        cacheService.clearBlockedForLookup(normalizedUrl).then(() => {
            // ignored
        });

        const providers = runtime.providers;

        for (const element of providers) {
            const key = urlService.lookupValueForTarget(blockedUrl, element.lookupTarget || 'url');

            if (key && key !== normalizedUrl) {
                cacheService.clearBlockedForProviderLookup(element.id, key).then(() => {
                });
            }
        }

        rememberSuppressedNavigation(tabId, normalizedUrl);
        const success = await navigateWithSafetyFallback(tabId, blockedUrl);

        if (success) {
            cleanupAfterNavigation(tabId);
        }

        return {
            ok: true,
            navigated: success,
        };
    };

    const continueToWebsite = async (tabId, blockedUrl, origin) => {
        const parsed = urlService.parseHttpUrl(blockedUrl);

        if (!parsed || !origin) {
            return failClosed(tabId);
        }

        const runtime = await providerRuntimeFactory.createRuntime();
        const provider = runtime.providers.find(p => p.id === origin);

        if (!provider) {
            return failClosed(tabId);
        }

        const lookupKey = urlService.lookupValueForTarget(parsed, provider.lookupTarget || 'url');

        if (!lookupKey) {
            return failClosed(tabId);
        }

        cacheService.markAllowed(provider.id, lookupKey, runtime.effectiveState.app.cacheExpirationSeconds).then(() => {
            // ignored
        });

        cacheService.clearBlockedForProviderLookup(provider.id, lookupKey).then(() => {
            // ignored
        });

        const nextContext = resultAggregationService.removeOrigin(tabId, origin);

        if (nextContext) {
            resultAggregationService.markRedirected(tabId);
            lastBlockedSignatureByTab.delete(tabId);

            badgeService.syncWithContext(tabId, nextContext);

            await pushBlockedContextUpdate(tabId);

            return {
                ok: true,
                navigated: false,
                context: nextContext,
            };
        }

        const resumeUrl = urlService.normalizeUrl(parsed);
        rememberSuppressedNavigation(tabId, resumeUrl);

        const success = await navigateWithSafetyFallback(tabId, blockedUrl);

        if (success) {
            cleanupAfterNavigation(tabId);
        }

        return {
            ok: true,
            navigated: success,
            context: null,
        };
    };

    const reportWebsite = async reportUrl => {
        try {
            const reportUrlObject = new URL(reportUrl);

            if (/^(http|https|mailto):$/.test(reportUrlObject.protocol)) {
                await browserAPI.tabsCreate({url: reportUrl});
            }
            return {ok: true};
        } catch {
            return failureResult;
        }
    };

    return Object.freeze({
        handleNavigation,
        allowWebsite,
        continueToWebsite,
        reportWebsite,
        sendToSafety,
        pushBlockedContextUpdate,
        markWarningPageReady,
        connectWarningPort,
        clearTab,
    });
})();
