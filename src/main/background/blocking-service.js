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
    const providerEngine = globalThis.OspreyProviderEngine;
    const providerRuntimeFactory = globalThis.OspreyProviderRuntimeFactory;
    const resultAggregationService = globalThis.OspreyResultAggregationService;
    const urlService = globalThis.OspreyUrlService;
    const timer = globalThis.OspreyTimer;

    const inFlightNavigations = new Map();
    const suppressedNavigations = new Map();
    const suppressedNavDuration = 2500;
    const lastBlockedPayloadByTab = new Map();
    const pendingBlockedPayloadByTab = new Map();
    const warningPortsByTab = new Map();

    const buildNavigationKey = (tabId, normalizedUrl) => `${tabId}::${normalizedUrl}`;

    // TODO: Turn the '2' into a variable on the settings page
    const getBlockingThreshold = enabledCount => enabledCount >= 4 ? 2 : 1;

    const getBlockingAnalysis = (runtime, blockedContext, result) => {
        const blockedOrigins = Array.isArray(blockedContext?.origins) ? blockedContext.origins : [];
        const supportedOrigins = runtime?.blockingProviderIdsByResult?.[result] || null;
        const providersById = runtime?.providersById || null;

        let blockedCount = 0;
        let thresholdBypassed = false;

        if (!supportedOrigins || supportedOrigins.size === 0 || blockedOrigins.length === 0) {
            return {
                blockedCount: 0,
                thresholdBypassed: false,
                requiredBlockedCount: 0,
            };
        }

        for (const origin of blockedOrigins) {
            if (!supportedOrigins.has(origin)) {
                continue;
            }

            blockedCount += 1;

            if (!thresholdBypassed && providersById?.get(origin)?.bypassBlockingThreshold === true) {
                thresholdBypassed = true;
            }
        }

        return {
            blockedCount,
            thresholdBypassed,
            requiredBlockedCount: thresholdBypassed ? 1 : getBlockingThreshold(supportedOrigins.size),
        };
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

        suppressedNavigations.set(buildNavigationKey(tabId, normalizedUrl), Date.now());
    };

    const shouldSkipSuppressedNavigation = (tabId, normalizedUrl) => {
        pruneSuppressedNavigations();

        const key = buildNavigationKey(tabId, normalizedUrl);

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

    const buildBlockedPayload = tabId => ({
        ...getBlockedContextPayload(resultAggregationService.getBlockedContext(tabId)),
        tabId,
    });

    const sendCurrentBlockedContext = (tabId, port) => {
        const payload = buildBlockedPayload(tabId);

        try {
            port.postMessage(payload);
            lastBlockedPayloadByTab.set(tabId, JSON.stringify(payload));
        } catch {
            if (warningPortsByTab.get(tabId) === port) {
                warningPortsByTab.delete(tabId);
            }
        }
    };

    const pushBlockedContextUpdate = async tabId => {
        if (!resultAggregationService.isRedirected(tabId)) {
            pendingBlockedPayloadByTab.delete(tabId);
            lastBlockedPayloadByTab.delete(tabId);
            return;
        }

        const payload = buildBlockedPayload(tabId);
        const payloadKey = JSON.stringify(payload);
        const port = warningPortsByTab.get(tabId);

        if (!port || !resultAggregationService.isWarningPageReady(tabId)) {
            pendingBlockedPayloadByTab.set(tabId, payloadKey);
            return;
        }

        if (lastBlockedPayloadByTab.get(tabId) === payloadKey && !pendingBlockedPayloadByTab.has(tabId)) {
            return;
        }

        badgeService.syncWithContext(tabId, resultAggregationService.getBlockedContext(tabId)).then(() => {
            // ignoring await
        });

        lastBlockedPayloadByTab.set(tabId, payloadKey);
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

        if (typeof tabId !== "number") {
            return;
        }

        warningPortsByTab.set(tabId, port);
        resultAggregationService.markWarningPageReady(tabId);

        port.onMessage.addListener(message => {
            if (message?.messageType === messages.BLOCKED_COUNTER_PING && warningPortsByTab.get(tabId) === port) {
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

    const clearBlockedUI = async tabId => timer.wrap("OspreyBlockingService.clearBlockedUI", async () => {
        resultAggregationService.clear(tabId);
        lastBlockedPayloadByTab.delete(tabId);
        pendingBlockedPayloadByTab.delete(tabId);
        badgeService.clear(tabId);
    });

    const markWarningPageReady = tabId => {
        resultAggregationService.markWarningPageReady(tabId);
        return pushBlockedContextUpdate(tabId);
    };

    const cleanupAfterNavigation = tabId => {
        providerEngine.abortTab(tabId).catch(() => {
            // ignored
        });

        clearBlockedUI(tabId).catch(() => {
            // ignored
        });
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

        if (frameZeroUrl && !urlService.haveSameOrigin(frameZeroUrl, navigationUrl)) {
            console.debug(`Ignoring stale blocking result for URL ${navigationUrl} in tabId ${tabId} because frame zero URL is different: ${frameZeroUrl}`);
            return;
        }

        // Records the blocking result and retrieves the updated blocked context for the tab
        resultAggregationService.recordBlockingResult(tabId, navigationUrl, protectionResult.origin, protectionResult.result);
        const blockedContext = resultAggregationService.getBlockedContext(tabId);

        const blockingAnalysis = getBlockingAnalysis(runtime, blockedContext, protectionResult.result);

        // If the number of providers that have blocked the URL is below the required blocking threshold, do not show the warning page
        if (blockingAnalysis.blockedCount < blockingAnalysis.requiredBlockedCount) {
            badgeService.syncWithContext(tabId, blockedContext);
            return;
        }

        badgeService.clear(tabId);

        if (resultAggregationService.isRedirected(tabId)) {
            await pushBlockedContextUpdate(tabId);
            return;
        }

        resultAggregationService.markRedirected(tabId);
        lastBlockedPayloadByTab.delete(tabId);

        const warningUrl = urlService.buildWarningPageUrl({
            url: navigationUrl,
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

            console.error(`Failed to navigate to recorded warning page for URL ${navigationUrl} in tabId ${tabId}`, error);
        });
    };

    const handleNavigation = async details => {
        const parsed = urlService.parseHttpUrl(details?.url);

        if (!parsed || typeof details?.tabId !== "number") {
            return;
        }

        const normalizedUrl = urlService.normalizeUrl(parsed);
        const navigationKey = buildNavigationKey(details.tabId, normalizedUrl);

        if (shouldSkipSuppressedNavigation(details.tabId, normalizedUrl) || inFlightNavigations.has(navigationKey)) {
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
                console.debug(`Failed to navigate to record ${details.url} (Reason: protection options are hidden)`);
                return;
            }

            // Records the navigation URL for the tab in the result aggregation service
            resultAggregationService.beginNavigation(details.tabId, normalizedUrl);

            // Clears any existing blocked context for the tab
            lastBlockedPayloadByTab.delete(details.tabId);

            // Clears the badge immediately on navigation
            badgeService.clear(details.tabId);

            await providerEngine.scanUrl({
                tabId: details.tabId,
                url: normalizedUrl,
                providers: runtime.providers,
                expirationSeconds: runtime.effectiveState.app.cacheExpirationSeconds,

                // Both frameZeroUrl and badge clear happen here, after DNS passes,
                // so neither fires for navigations that are skipped nor aborted.
                onScanBegin: async () => {
                    resultAggregationService.setFrameZeroUrl(details.tabId, normalizedUrl);
                    badgeService.clear(details.tabId);
                },

                onResult: protectionResult => {
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

    const allowWebsite = async (tabId, blockedUrl) => {
        const parsed = urlService.parseHttpUrl(blockedUrl);

        if (!parsed) {
            return failClosed("allow website", blockedUrl, "invalid URL", tabId);
        }

        const runtime = await providerRuntimeFactory.createRuntime();
        const hostname = parsed.hostname;
        const labels = hostname.split(".");
        const allowPattern = labels.length >= 3 ? `*.${labels.slice(1).join(".")}` : `*.${hostname}`;
        const normalizedUrl = urlService.normalizeUrl(parsed);
        const normalizedHostname = urlService.canonicalizeHostname(parsed.hostname);

        cacheService.allowPattern(allowPattern).then(() => {
            // ignoring await
        });

        cacheService.clearBlockedForLookup(normalizedUrl).then(() => {
            // ignoring await
        });

        for (const provider of runtime.providers) {
            const lookupKey = urlService.lookupValueForTarget(blockedUrl, provider.lookupTarget || "url");

            if (lookupKey && lookupKey !== normalizedUrl) {
                cacheService.clearBlockedForProviderLookup(provider.id, lookupKey).then(() => {
                    // ignoring await
                });
            }
        }

        if (normalizedHostname) {
            cacheService.clearBlockedForLookup(normalizedHostname).then(() => {
                // ignoring await
            });
        }

        rememberSuppressedNavigation(tabId, normalizedUrl);

        const navigationSucceeded = await navigateWithSafetyFallback(
            tabId,
            blockedUrl,
            `Failed to navigate to ${blockedUrl} for tabId ${tabId} after allowing website`
        );

        if (navigationSucceeded) {
            cleanupAfterNavigation(tabId);
        }

        return {
            ok: true,
            navigated: navigationSucceeded
        };
    };

    const continueToWebsite = async (tabId, blockedUrl, origin) => {
        const parsed = urlService.parseHttpUrl(blockedUrl);

        if (!parsed) {
            return failClosed("continue to website", blockedUrl, "invalid URL", tabId);
        }

        if (typeof origin !== "string" || origin.length === 0) {
            return failClosed("continue to website", blockedUrl, "missing provider origin", tabId);
        }

        const runtime = await providerRuntimeFactory.createRuntime();
        const provider = runtime.providers.find(item => item.id === origin);

        if (!provider) {
            return failClosed("continue to website", blockedUrl, `unknown provider '${origin}'`, tabId);
        }

        const lookupKey = urlService.lookupValueForTarget(parsed, provider.lookupTarget || "url");

        if (!lookupKey) {
            return failClosed("continue to website", blockedUrl, "failed to derive lookup key", tabId);
        }

        cacheService.markAllowed(
            provider.id,
            lookupKey,
            runtime.effectiveState.app.cacheExpirationSeconds
        ).then(() => {
            // ignoring await
        });

        cacheService.clearBlockedForProviderLookup(provider.id, lookupKey).then(() => {
            // ignoring await
        });

        const nextContext = resultAggregationService.removeOrigin(tabId, origin);

        if (nextContext) {
            resultAggregationService.markRedirected(tabId);
            lastBlockedPayloadByTab.delete(tabId);
            badgeService.syncWithContext(tabId, nextContext);
            await pushBlockedContextUpdate(tabId);

            return {
                ok: true,
                navigated: false,
                context: nextContext
            };
        }

        const resumeUrl = urlService.normalizeUrl(parsed);
        rememberSuppressedNavigation(tabId, resumeUrl);

        const navigationSucceeded = await navigateWithSafetyFallback(
            tabId,
            blockedUrl,
            `Failed to navigate to ${blockedUrl} for tabId ${tabId} after continuing to website`
        );

        if (navigationSucceeded) {
            cleanupAfterNavigation(tabId);
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
    return timer.instrument('OspreyBlockingService', {
        handleNavigation,
        allowWebsite,
        continueToWebsite,
        reportWebsite,
        sendToSafety,
        pushBlockedContextUpdate,
        markWarningPageReady,
        connectWarningPort,
    });
})();
