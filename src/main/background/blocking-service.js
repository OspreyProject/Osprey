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

globalThis.OspreyBlockingService = (() => {
    const badgeService = globalThis.OspreyBadgeService;
    const browserAPI = globalThis.OspreyBrowserAPI;
    const cacheService = globalThis.OspreyCacheService;
    const eventLogService = globalThis.OspreyEventLogService;
    const messages = globalThis.OspreyMessageBus.Messages;
    const providerEngine = globalThis.OspreyProviderEngine;
    const providerRuntimeFactory = globalThis.OspreyProviderRuntimeFactory;
    const policyService = globalThis.OspreyPolicyService;
    const resultAggregationService = globalThis.OspreyResultAggregationService;
    const urlService = globalThis.OspreyUrlService;

    const inFlightNavigations = new Map();
    const suppressedNavigations = new Map();
    const suppressedNavDuration = 2500;

    const lastBlockedSignatureByTab = new Map();
    const pendingBlockedPayloadByTab = new Map();
    const warningPortsByTab = new Map();

    const buildNavigationKey = (tabId, normalizedUrl) => `${tabId}::${normalizedUrl}`;

    // Synthetic origin for verdicts produced by local domain intelligence rather than a provider.
    const domainIntelOrigin = 'osprey';

    // A lookalike the user already allowed (whole host, or by continuing past the warning) is not blocked again.
    const isUserAllowedLookalike = async (normalizedUrl, parsed) => {
        if (await cacheService.matchesGlobalPattern(normalizedUrl)) {
            return true;
        }

        const entry = await cacheService.getAllowedEntry(domainIntelOrigin, urlService.canonicalizeHostname(parsed.hostname));
        return Boolean(entry);
    };

    const getBlockingThreshold = enabledCount => enabledCount >= 4 ? 2 : 1;

    const getPayloadSignature = p => `${p.known}|${p.count}|${p.remaining}|${p.total}|${p.primaryOrigin}|${p.primaryResult}|${p.systems.join(',')}`;

    const getBlockingAnalysis = (runtime, blockedContext, result) => {
        const blockedOrigins = blockedContext?.origins;
        if (result === 'lookalike' && blockedOrigins?.includes(domainIntelOrigin)) {
            return {blockedCount: 1, thresholdBypassed: true, requiredBlockedCount: 1};
        }
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
                known: false,
                count: 0,
                systems: [],
                primaryOrigin: null,
                primaryResult: null,
                remaining: 0,
                total: 0,
                blockedUrl: '',
            };
        }

        const {origins, primaryOrigin, primaryResult} = context;
        const systems = origins.filter(o => o !== primaryOrigin);

        return {
            messageType: messages.BLOCKED_COUNTER_PONG,
            known: true,
            count: systems.length,
            systems,
            primaryOrigin,
            primaryResult,
            remaining: context.remaining,
            total: context.total,
            blockedUrl: typeof context.url === 'string' ? context.url : '',
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

    const getBlockedUrlFromWarningPage = warningPageUrl => {
        if (typeof warningPageUrl !== 'string' || warningPageUrl.length === 0) {
            return '';
        }

        try {
            return new URL(warningPageUrl).searchParams.get('url') || '';
        } catch {
            return '';
        }
    };

    const reactivateForWarningPage = async (tabId, warningPageUrl) => {
        await resultAggregationService.ensureHydrated();

        let changed = resultAggregationService.reactivate(tabId);
        const blockedUrl = getBlockedUrlFromWarningPage(warningPageUrl);

        if (blockedUrl && resultAggregationService.adoptForUrl(tabId, blockedUrl)) {
            changed = true;
        }

        if (changed) {
            lastBlockedSignatureByTab.delete(tabId);
            await resultAggregationService.persist();
        }
    };

    const pushBlockedContextUpdate = async tabId => {
        await resultAggregationService.ensureHydrated();

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

        const warningPageUrl = port?.sender?.url || port?.sender?.tab?.url || '';

        warningPortsByTab.set(tabId, port);

        port.onMessage.addListener(msg => {
            if (msg?.messageType !== messages.BLOCKED_COUNTER_PING) {
                return;
            }

            reactivateForWarningPage(tabId, warningPageUrl).then(() => {
                if (warningPortsByTab.get(tabId) === port) {
                    sendCurrentBlockedContext(tabId, port);
                }
            });
        });

        port.onDisconnect.addListener(() => {
            if (warningPortsByTab.get(tabId) === port) {
                warningPortsByTab.delete(tabId);
            }
        });

        resultAggregationService.ensureHydrated().then(() => {
            if (warningPortsByTab.get(tabId) !== port) {
                return;
            }

            reactivateForWarningPage(tabId, warningPageUrl).then(() => {
                if (warningPortsByTab.get(tabId) !== port) {
                    return;
                }

                resultAggregationService.markWarningPageReady(tabId);
                sendCurrentBlockedContext(tabId, port);
                pendingBlockedPayloadByTab.delete(tabId);
            });
        });
    };

    const clearBlockedUI = async tabId => {
        resultAggregationService.clear(tabId);
        await resultAggregationService.persist();
        lastBlockedSignatureByTab.delete(tabId);
        pendingBlockedPayloadByTab.delete(tabId);
        badgeService.clear(tabId);
    };

    const retireBlockedUI = async tabId => {
        await resultAggregationService.ensureHydrated();
        resultAggregationService.retire(tabId);
        await resultAggregationService.persist();
        lastBlockedSignatureByTab.delete(tabId);
        pendingBlockedPayloadByTab.delete(tabId);
        badgeService.clear(tabId);
    };

    const clearTab = tabId => {
        warningPortsByTab.delete(tabId);
        lastBlockedSignatureByTab.delete(tabId);
        pendingBlockedPayloadByTab.delete(tabId);
    };

    const markWarningPageReady = async (tabId, warningPageUrl) => {
        await resultAggregationService.ensureHydrated();
        await reactivateForWarningPage(tabId, warningPageUrl);
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
        await retireBlockedUI(tabId);

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

    const handleProtectionResult = async (tabId, navigationUrl, runtime, protectionResult, originalUrl = navigationUrl) => {
        if (!protectionResult?.isBlocking) {
            return;
        }

        await resultAggregationService.ensureHydrated();

        if (resultAggregationService.isRetired(tabId)) {
            return;
        }

        const currentUrl = resultAggregationService.getFrameZeroUrl(tabId);

        if (currentUrl && currentUrl !== navigationUrl) {
            return;
        }

        resultAggregationService.recordBlockingResult(tabId, navigationUrl, protectionResult.origin, protectionResult.result);

        if (runtime.effectiveState.app.notificationProtection === 'on') {
            globalThis.OspreyNotificationService?.blockForUrl?.(originalUrl).catch(error => {
                console.warn('OspreyBlockingService failed to block notifications', error);
            });
        }

        await resultAggregationService.persist();

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
        });

        try {
            await browserAPI.tabsUpdate(tabId, {url: warningUrl});
            await pushBlockedContextUpdate(tabId);
        } catch (error) {
            console.warn(`OspreyBlockingService failed to redirect tab ${tabId} to the warning page`, error);
        }
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

            await resultAggregationService.ensureHydrated();
            resultAggregationService.beginNavigation(details.tabId);
            resultAggregationService.setFrameZeroUrl(details.tabId, normalizedUrl);
            lastBlockedSignatureByTab.delete(details.tabId);

            badgeService.clear(details.tabId);

            const intelMode = runtime.effectiveState.app.domainIntelMode;

            if ((intelMode === 'warn' || intelMode === 'block') && globalThis.OspreyDomainIntel) {
                let finding;
                let shortEditDistance = false;

                try {
                    finding = globalThis.OspreyDomainIntel.analyze(
                        parsed.hostname, runtime.effectiveState.app.protectedDomains
                    );

                    if (finding?.detail === 'edit_distance') {
                        shortEditDistance =
                            globalThis.OspreyDomainIntel.registrable(finding.target).split('.')[0].length <= 5;
                    }
                } catch (error) {
                    console.warn('OspreyBlockingService domain intelligence analysis failed', error);
                    finding = null;
                }

                if (finding) {
                    eventLogService.recordLocal('domain_intel', {
                        url: normalizedUrl, kind: finding.kind, target: finding.target, detail: finding.detail,
                    });

                    const managedDecision = intelMode === 'block' && finding.kind === 'protected_lookalike'
                        ? await cacheService.getManagedListDecision(normalizedUrl) : null;

                    if (intelMode === 'block' && finding.kind === 'protected_lookalike' &&
                        !shortEditDistance && !(managedDecision.allowed && !managedDecision.blocked) &&
                        !(managedDecision.blocked !== true && await isUserAllowedLookalike(normalizedUrl, parsed))) {
                        await handleProtectionResult(details.tabId, normalizedUrl, runtime,
                            globalThis.OspreyProtectionResult.create({
                                url: normalizedUrl,
                                result: 'lookalike',
                                origin: domainIntelOrigin,
                            }), details.url);
                        return;
                    }
                }
            }

            await providerEngine.scanUrl({
                tabId: details.tabId,
                url: normalizedUrl,
                providers: runtime.providers,
                expirationSeconds: runtime.effectiveState.app.cacheExpirationSeconds,
                onResult: res => handleProtectionResult(details.tabId, normalizedUrl, runtime, res, details.url).then(() => {
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
        const restrictions = await policyService.getActionRestrictions();

        if (restrictions.hideWarningProceedButton || restrictions.lockUserAllowlist ||
            restrictions.disableUserAllowlist) {
            console.warn('OspreyBlockingService refused ALLOW_WEBSITE under managed policy');
            return {ok: false, navigated: false};
        }

        const parsed = urlService.parseHttpUrl(blockedUrl);

        if (!parsed) {
            return failClosed(tabId);
        }

        const runtime = await providerRuntimeFactory.createRuntime();
        const normalizedUrl = urlService.normalizeUrl(parsed);

        await resultAggregationService.ensureHydrated();
        const allowContext = resultAggregationService.getBlockedContext(tabId);

        eventLogService?.recordOverride({
            action: 'allowWebsite',
            url: normalizedUrl,
            providerId: allowContext?.primaryOrigin ?? null,
            verdict: allowContext?.primaryResult ?? null,
        });

        const pattern = '*.' + urlService.canonicalizeHostname(parsed.hostname);

        const providers = runtime.providers;
        const allowResult = await cacheService.allowPattern(pattern);

        if (allowResult?.ok === false) {
            return {ok: false, navigated: false};
        }

        // The allowlist entry is already saved, so a failed notification reset must not turn the
        // action into an error the user sees while the site is in fact allowed. It is best-effort.
        if (globalThis.OspreyNotificationService) {
            try {
                const reset = await globalThis.OspreyNotificationService.resetForHost(parsed.hostname);

                if (!reset?.ok) {
                    console.warn('OspreyBlockingService could not fully reset notification protection for an allowed website');
                }
            } catch (error) {
                console.warn('OspreyBlockingService failed to reset notification protection for an allowed website', error);
            }
        }

        const pendingWrites = [
            cacheService.clearBlockedForLookup(normalizedUrl).then(() => {
                // ignored
            })
        ];

        for (const element of providers) {
            const key = urlService.lookupValueForTarget(blockedUrl, element.lookupTarget || 'url');

            if (key && key !== normalizedUrl) {
                pendingWrites.push(cacheService.clearBlockedForProviderLookup(element.id, key));
            }
        }

        await Promise.allSettled(pendingWrites);

        const latestRestrictions = await policyService.getActionRestrictions();

        if (latestRestrictions.hideWarningProceedButton || latestRestrictions.lockUserAllowlist ||
            latestRestrictions.disableUserAllowlist) {
            console.warn('OspreyBlockingService refused ALLOW_WEBSITE after a managed policy change');
            return {ok: false, navigated: false};
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

        await resultAggregationService.ensureHydrated();

        const bypassContext = resultAggregationService.getBlockedContext(tabId);
        const normalizedUrl = urlService.normalizeUrl(parsed);

        if (!bypassContext || bypassContext.url !== normalizedUrl || !bypassContext.origins.includes(origin)) {
            console.warn(`OspreyBlockingService refused CONTINUE_TO_WEBSITE for tab ${tabId} because the blocked context does not match`);

            return {
                ok: false,
                navigated: false,
                context: null,
                known: false
            };
        }

        const managedDecision = await cacheService.getManagedListDecision(normalizedUrl);
        const approved = managedDecision.allowed === true && managedDecision.blocked !== true;

        if (managedDecision.blocked) {
            console.warn('OspreyBlockingService refused CONTINUE_TO_WEBSITE for a managed block');
            return {ok: false, navigated: false};
        }

        if (!approved && (await policyService.getActionRestrictions()).hideWarningProceedButton) {
            console.warn('OspreyBlockingService refused CONTINUE_TO_WEBSITE under managed policy');
            return {ok: false, navigated: false};
        }

        const runtime = approved ? null : await providerRuntimeFactory.createRuntime();
        const provider = runtime?.providers.find(p => p.id === origin);

        if (!approved && !provider && origin !== domainIntelOrigin) {
            return failClosed(tabId);
        }

        const lookupKey = provider && !approved
            ? urlService.lookupValueForTarget(parsed, provider.lookupTarget || 'url') : null;

        if (provider && !approved && !lookupKey) {
            return failClosed(tabId);
        }

        if (approved) {
            eventLogService?.recordLocal('admin_approval', {url: normalizedUrl});
        } else {
            eventLogService?.recordOverride({
                action: 'continueToWebsite',
                url: normalizedUrl,
                providerId: origin,
                verdict: bypassContext?.primaryResult ?? null,
            });
        }

        if (provider && !approved) {
            await Promise.allSettled([
                cacheService.markAllowed(provider.id, lookupKey, runtime.effectiveState.app.cacheExpirationSeconds, true),
                cacheService.clearBlockedForProviderLookup(provider.id, lookupKey),
            ]);
        } else if (!provider && !approved && origin === domainIntelOrigin) {
            // Domain-intel blocks have no provider; remember the host so the same lookalike isn't blocked again.
            const hostKey = urlService.canonicalizeHostname(parsed.hostname);
            const expirationSeconds = (await providerRuntimeFactory.createRuntime()).effectiveState.app.cacheExpirationSeconds;

            await Promise.allSettled([
                cacheService.markAllowed(domainIntelOrigin, hostKey, expirationSeconds, true),
                cacheService.clearBlockedForProviderLookup(domainIntelOrigin, hostKey),
            ]);
        }

        if (!approved && (await policyService.getActionRestrictions()).hideWarningProceedButton) {
            console.warn('OspreyBlockingService refused CONTINUE_TO_WEBSITE after a managed policy change');
            return {ok: false, navigated: false};
        }

        const nextContext = approved ? null : resultAggregationService.removeOrigin(tabId, origin);
        await resultAggregationService.persist();

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

        rememberSuppressedNavigation(tabId, normalizedUrl);

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
