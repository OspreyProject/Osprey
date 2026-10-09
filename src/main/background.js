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

const bootstrapScripts = [
    'shared/browser-api.js',
    'shared/lang-util.js',
    'shared/timed-signal.js',
    'providers/provider-groups.js',
    'providers/proxy-builtins.js',
    'catalog/catalog-validator.js',
    'platform/protection-result.js',
    'platform/domain-intel.js',
    'platform/url-service.js',
    'platform/report-link-builder.js',
    'providers/provider-catalog.js',
    'state/provider-state-store.js',
    'state/policy-service.js',
    'platform/request-builder.js',
    'platform/response-rule-engine.js',
    'state/cache-service.js',
    'state/notification-service.js',
    'state/event-log-service.js',
    'platform/message-bus.js',
    'providers/provider-runtime-factory.js',
    'providers/provider-engine.js',
    'background/result-aggregation-service.js',
    'background/badge-service.js',
    'background/blocking-service.js',
    'background/navigation-service.js',
];

const maxBootstrapAttempts = 3;

const importWithRetry = scripts => {
    for (let attempt = 1; ; attempt++) {
        try {
            importScripts(...scripts);
            return;
        } catch (error) {
            if (attempt >= maxBootstrapAttempts) {
                console.error('Script injection failed; stopping runtime to prevent corrupted state', error);
                throw error;
            }

            console.warn(`Script injection attempt ${attempt} failed; retrying`, error);
        }
    }
};

if (typeof importScripts === 'function') {
    importWithRetry(bootstrapScripts);
} else {
    console.debug('Environment lacks importScripts; relying on HTML document script loading');
}

(() => {
    const badgeService = globalThis.OspreyBadgeService;
    const blockingService = globalThis.OspreyBlockingService;
    const browserAPI = globalThis.OspreyBrowserAPI;
    const cacheService = globalThis.OspreyCacheService;
    const eventLogService = globalThis.OspreyEventLogService;
    const messages = globalThis.OspreyMessageBus.Messages;
    const ports = globalThis.OspreyMessageBus.Ports;
    const navigationService = globalThis.OspreyNavigationService;
    const policyService = globalThis.OspreyPolicyService;
    const providerCatalog = globalThis.OspreyProviderCatalog;
    const providerEngine = globalThis.OspreyProviderEngine;
    const providerStateStore = globalThis.OspreyProviderStateStore;
    const reportLinkBuilder = globalThis.OspreyReportLinkBuilder;
    const resultAggregationService = globalThis.OspreyResultAggregationService;

    const respond = (sendResponse, payload) => {
        if (sendResponse) {
            sendResponse(payload);
        }
        return false;
    };

    const respondAsync = (sendResponse, promise, errorMessage) => {
        promise.then(response => {
            if (sendResponse) {
                sendResponse(response || {ok: true});
            }
        }).catch(error => {
            console.error(errorMessage, error);

            if (sendResponse) {
                sendResponse({ok: false});
            }
        });
        return true;
    };

    const openReportUrlForOrigin = async (origin, blockedUrl) => {
        const definition = providerCatalog.getDefinition(origin);

        if (!definition) {
            console.warn(`No provider definition found for origin ${origin} when building report URL`);
            return null;
        }
        return reportLinkBuilder.build(definition.report, {blockedUrl});
    };

    const emergencySettingsMigrations = Object.freeze([
        {
            providerId: 'phishunt-io',
            setting: 'bypassBlockingThreshold',
            value: false,
        },
    ]);

    const migratableProviderSettings = Object.freeze({
        enabled: {
            read: providerState => providerState.enabled,
            apply: (providerId, value) => providerStateStore.applyEmergencySetting(providerId, 'enabled', value),
        },
        bypassBlockingThreshold: {
            read: providerState => providerState.bypassBlockingThreshold,
            apply: (providerId, value) => providerStateStore.applyEmergencySetting(providerId, 'bypassBlockingThreshold', value),
        },
    });

    const runEmergencySettingsMigrations = async () => {
        if (emergencySettingsMigrations.length === 0) {
            return;
        }

        try {
            const state = await providerStateStore.getState();

            for (const migration of emergencySettingsMigrations) {
                const handler = migratableProviderSettings[migration.setting];
                const providerState = state?.providers?.[migration.providerId];

                if (!handler || !providerState) {
                    console.warn(`Skipping emergency settings migration for ${migration.providerId}/${migration.setting}`);
                    continue;
                }

                if (handler.read(providerState) !== migration.value) {
                    await handler.apply(migration.providerId, migration.value);
                }
            }
        } catch (error) {
            console.error('Failed to apply emergency settings migrations', error);
        }
    };

    const messageHandlers = {
        [messages.CONTINUE_TO_SAFETY]: (_message, tabId, sendResponse) => {
            if (typeof tabId !== 'number') {
                console.warn('OspreyBackground rejected CONTINUE_TO_SAFETY because the sender had no tab id');
                return respond(sendResponse, {ok: false});
            }

            return respondAsync(
                sendResponse,
                blockingService.sendToSafety(tabId).then(() => ({ok: true})),
                `Failed CONTINUE_TO_SAFETY for tab ${tabId}`,
            );
        },

        [messages.CONTINUE_TO_WEBSITE]: (message, tabId, sendResponse) => {
            if (typeof message.blockedUrl !== 'string') {
                console.warn('OspreyBackground rejected CONTINUE_TO_WEBSITE because the message payload was incomplete');
                return respond(sendResponse, {ok: false});
            }

            if (typeof tabId !== 'number') {
                console.warn('OspreyBackground rejected CONTINUE_TO_WEBSITE because the sender had no tab id');
                return respond(sendResponse, {ok: false});
            }

            return respondAsync(
                sendResponse,
                blockingService.continueToWebsite(tabId, message.blockedUrl, message.origin),
                `Failed CONTINUE_TO_WEBSITE for tab ${tabId} and URL ${message.blockedUrl}`,
            );
        },

        [messages.RECHECK_BLOCKED_URL]: (message, tabId, sendResponse) => {
            if (typeof message.blockedUrl !== 'string' || message.blockedUrl.length === 0) {
                console.warn('OspreyBackground rejected RECHECK_BLOCKED_URL because the message payload was incomplete');
                return respond(sendResponse, {ok: false});
            }

            return respondAsync(
                sendResponse,
                policyService.refreshRemoteConfig()
                    .then(() => cacheService.getManagedListDecision(message.blockedUrl))
                    .then(decision => ({ok: true, allowed: decision.allowed === true && decision.blocked !== true})),
                `Failed RECHECK_BLOCKED_URL for tab ${tabId}`,
            );
        },

        [messages.ALLOW_WEBSITE]: (message, tabId, sendResponse) => {
            if (typeof message.blockedUrl !== 'string') {
                console.warn('OspreyBackground rejected ALLOW_WEBSITE because the message payload was incomplete');
                return respond(sendResponse, {ok: false});
            }

            if (typeof tabId !== 'number') {
                console.warn('OspreyBackground rejected ALLOW_WEBSITE because the sender had no tab id');
                return respond(sendResponse, {ok: false});
            }

            return respondAsync(
                sendResponse,
                blockingService.allowWebsite(tabId, message.blockedUrl),
                `Failed ALLOW_WEBSITE for tab ${tabId}`,
            );
        },

        [messages.REPORT_WEBSITE]: (message, tabId, sendResponse) => {
            if (typeof message.reportUrl === 'string') {
                return respondAsync(
                    sendResponse,
                    blockingService.reportWebsite(message.reportUrl),
                    `Failed REPORT_WEBSITE for tab ${tabId}`,
                );
            }

            if (typeof message.origin === 'string' && typeof message.blockedUrl === 'string') {
                return respondAsync(
                    sendResponse,
                    openReportUrlForOrigin(message.origin, message.blockedUrl)
                        .then(reportUrl => reportUrl ? blockingService.reportWebsite(reportUrl) : {ok: false}),
                    `Failed REPORT_WEBSITE for tab ${tabId}`,
                );
            }

            console.warn('OspreyBackground rejected REPORT_WEBSITE because the message payload was incomplete');
            return respond(sendResponse, {ok: false});
        },

        [messages.CLEAR_ALLOWED_WEBSITES]: (_message, _tabId, sendResponse) => respondAsync(
            sendResponse,
            cacheService.clearAll(),
            'Failed CLEAR_ALLOWED_WEBSITES',
        ),

        [messages.GET_EXCLUSIONS]: (_message, _tabId, sendResponse) => respondAsync(
            sendResponse,
            cacheService.listExclusions().then(data => ({ok: true, data})),
            'Failed GET_EXCLUSIONS',
        ),

        [messages.ADD_GLOBAL_EXCLUSION]: (message, _tabId, sendResponse) => {
            if (typeof message.host !== 'string') {
                console.warn('OspreyBackground rejected ADD_GLOBAL_EXCLUSION because the message payload was incomplete');
                return respond(sendResponse, {ok: false});
            }

            return respondAsync(
                sendResponse,
                cacheService.addGlobalHost(message.host),
                'Failed ADD_GLOBAL_EXCLUSION',
            );
        },

        [messages.REMOVE_GLOBAL_EXCLUSION]: (message, _tabId, sendResponse) => {
            if (typeof message.pattern !== 'string') {
                console.warn('OspreyBackground rejected REMOVE_GLOBAL_EXCLUSION because the message payload was incomplete');
                return respond(sendResponse, {ok: false});
            }

            return respondAsync(
                sendResponse,
                cacheService.removeGlobalPattern(message.pattern),
                'Failed REMOVE_GLOBAL_EXCLUSION',
            );
        },

        [messages.REMOVE_PROVIDER_EXCLUSION]: (message, _tabId, sendResponse) => {
            if (typeof message.providerId !== 'string' || typeof message.lookupKey !== 'string') {
                console.warn('OspreyBackground rejected REMOVE_PROVIDER_EXCLUSION because the message payload was incomplete');
                return respond(sendResponse, {ok: false});
            }

            return respondAsync(
                sendResponse,
                cacheService.removeProviderAllowed(message.providerId, message.lookupKey),
                'Failed REMOVE_PROVIDER_EXCLUSION',
            );
        },

    };

    const handleMessage = (message, sender, sendResponse) => {
        const apiId = browserAPI.api?.runtime.id;

        if (!message || sender?.id !== apiId) {
            console.warn(`No message for ${message?.id} for ${sender?.id}`);
            return false;
        }

        const handler = messageHandlers[message.messageType];

        if (!handler) {
            console.warn(`No message for ${message?.id}`);
            return false;
        }

        const senderTabId = sender?.tab?.id;
        const tabId = typeof senderTabId === 'number' ? senderTabId : null;
        return handler(message, tabId, sendResponse, sender);
    };

    const uninstallSurveyUrl = 'https://osprey.ac/uninstall';
    const welcomePagePath = 'pages/welcome/welcome-page.html';

    const openWelcomePage = async () => {
        let disabled = false;

        try {
            disabled = await policyService.isWelcomePageDisabled();
        } catch (error) {
            console.error('Failed to resolve the welcome page policy', error);
        }

        if (disabled) {
            return;
        }

        try {
            await browserAPI.tabsCreate({url: browserAPI.safeRuntimeURL(welcomePagePath), active: true});
        } catch (error) {
            console.error('Failed to open the welcome page', error);
        }
    };

    const handleInstalled = details => {
        if (details?.reason !== 'install') {
            return;
        }

        openWelcomePage().catch(error => {
            console.error('Welcome page handling failed', error);
        });
    };

    const applyUninstallSurvey = async api => {
        if (typeof api?.runtime?.setUninstallURL !== 'function') {
            return;
        }

        let disabled = false;

        try {
            disabled = await policyService.isUninstallSurveyDisabled();
        } catch (error) {
            console.error('Failed to resolve the uninstall survey policy', error);
        }

        try {
            await api.runtime.setUninstallURL(disabled ? '' : uninstallSurveyUrl);
        } catch {
            console.error('Failed to set uninstall URL, browser API may not be available');
        }
    };

    const sessionMarkerKey = 'osprey_session_started';

    // Session storage survives service-worker restarts but not browser restarts, so it separates the two.
    const detectFreshSession = async () => {
        try {
            const stored = await browserAPI.storageGet('session', sessionMarkerKey);

            if (stored?.[sessionMarkerKey]) {
                return false;
            }

            await browserAPI.storageSet('session', {[sessionMarkerKey]: true});
        } catch (error) {
            console.warn('Failed to read the session marker; treating as a fresh session', error);
        }

        return true;
    };

    // Creates the alarm only when missing or changed so worker restarts don't postpone it; returns whether it was created.
    const ensureAlarm = async (alarms, name, periodInMinutes) => {
        if (!alarms?.create) {
            return false;
        }

        try {
            const existing = typeof alarms.get === 'function' ? await alarms.get(name) : null;

            if (existing && existing.periodInMinutes === periodInMinutes) {
                return false;
            }

            alarms.create(name, {periodInMinutes});
            return true;
        } catch (error) {
            console.error(`Failed to schedule the ${name} alarm`, error);
            return false;
        }
    };

    const setUpRemoteConfig = async (api, freshSession) => {
        if (!policyService || typeof policyService.initRemoteConfig !== 'function') {
            return;
        }

        try {
            await policyService.initRemoteConfig();
        } catch (error) {
            console.error('Failed to load persisted remote config', error);
        }

        const created = await ensureAlarm(api.alarms, policyService.remoteConfigAlarmName, policyService.remoteConfigRefreshMinutes);

        // Idle wake-ups use the persisted config; the alarm refreshes it. Fetch now only for a new session or alarm.
        if (await freshSession || created) {
            policyService.refreshRemoteConfig()
                .then(() => applyUninstallSurvey(api))
                .catch(error => {
                    console.error('Startup remote config refresh failed', error);
                });
        }
    };

    const runFlush = () => eventLogService.flushToReporting().catch(error => {
        console.error('Event reporting flush failed', error);
    });

    const runHeartbeat = () => eventLogService.sendHeartbeat().catch(error => {
        console.error('Reporting heartbeat failed', error);
    });

    const registerAlarmListeners = api => {
        if (policyService && typeof policyService.initRemoteConfig === 'function') {
            api.alarms?.onAlarm?.addListener(alarm => {
                if (alarm?.name === policyService.remoteConfigAlarmName) {
                    policyService.refreshRemoteConfig()
                        .then(() => applyUninstallSurvey(api))
                        .catch(error => {
                            console.error('Scheduled remote config refresh failed', error);
                        });
                }
            });
        }

        if (eventLogService && typeof eventLogService.flushToReporting === 'function') {
            api.alarms?.onAlarm?.addListener(alarm => {
                if (alarm?.name === eventLogService.reportFlushAlarmName) {
                    runFlush().then(() => {
                        // ignored
                    });
                } else if (alarm?.name === eventLogService.heartbeatAlarmName) {
                    runHeartbeat().then(() => {
                        // ignored
                    });
                }
            });
        }
    };

    const setUpReporting = async (api, freshSession) => {
        if (!eventLogService || typeof eventLogService.flushToReporting !== 'function') {
            return;
        }

        const createdFlush = await ensureAlarm(api.alarms, eventLogService.reportFlushAlarmName, eventLogService.reportFlushIntervalMinutes);
        const createdHeartbeat = await ensureAlarm(api.alarms, eventLogService.heartbeatAlarmName, eventLogService.heartbeatIntervalMinutes);

        // Idle wake-ups are covered by the alarms; only report immediately for a new browser session or a new alarm.
        if (await freshSession || createdHeartbeat) {
            runHeartbeat().then(() => {
                // ignored
            });
        }

        if (await freshSession || createdFlush) {
            runFlush().then(() => {
                // ignored
            });
        }
    };

    const init = async () => {
        const api = browserAPI.api;

        if (!api) {
            console.error('Browser API not available during background init');
            return;
        }

        api.runtime.onMessage?.addListener(handleMessage);
        api.runtime.onInstalled?.addListener(handleInstalled);

        api.runtime.onConnect?.addListener(port => {
            if (port?.name === ports.BLOCKED_COUNTER) {
                blockingService.connectWarningPort(port);
            }
        });

        api.tabs?.onRemoved?.addListener(tabId => {
            resultAggregationService.releaseTab(tabId);
            providerEngine.abortTab(tabId);
            cacheService.clearProcessingByTab(tabId);
            badgeService.clearTab(tabId);
            blockingService.clearTab(tabId);
        });

        registerAlarmListeners(api);
        navigationService.register();

        const freshSession = detectFreshSession();

        await runEmergencySettingsMigrations();
        await setUpRemoteConfig(api, freshSession);
        await applyUninstallSurvey(api);

        setUpReporting(api, freshSession).catch(error => {
            console.error('Failed to set up reporting', error);
        });
    };

    init().catch(error => {
        console.error('Background init failed', error);
    });
})();
