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

const bootstrapScripts = [
    'shared/browser-api.js',
    'shared/lang-util.js',
    'shared/timed-signal.js',
    'providers/provider-groups.js',
    'providers/proxy-builtins.js',
    'providers/direct-integrations.js',
    'catalog/catalog-validator.js',
    'platform/protection-result.js',
    'platform/url-service.js',
    'platform/report-link-builder.js',
    'providers/provider-catalog.js',
    'state/provider-state-store.js',
    'state/policy-service.js',
    'platform/request-builder.js',
    'platform/response-rule-engine.js',
    'state/cache-service.js',
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
    const messages = globalThis.OspreyMessageBus.Messages;
    const ports = globalThis.OspreyMessageBus.Ports;
    const navigationService = globalThis.OspreyNavigationService;
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
            value: false
        },
    ]);

    const migratableProviderSettings = Object.freeze({
        enabled: {
            read: providerState => providerState.enabled,
            apply: (providerId, value) => providerStateStore.setProviderEnabled(providerId, value),
        },
        bypassBlockingThreshold: {
            read: providerState => providerState.bypassBlockingThreshold,
            apply: (providerId, value) => providerStateStore.setBypassBlockingThreshold(providerId, value),
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
            cacheService.clearAll().then(() => ({ok: true})),
            'Failed CLEAR_ALLOWED_WEBSITES',
        ),
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

        const tabId = typeof message.tabId === 'number' ? message.tabId : sender.tab?.id ?? null;
        return handler(message, tabId, sendResponse, sender);
    };

    const init = async () => {
        const api = browserAPI.api;

        if (!api) {
            console.error('Browser API not available during background init');
            return;
        }

        try {
            api.runtime.setUninstallURL?.('https://osprey.ac/uninstall');
        } catch {
            console.error('Failed to set uninstall URL, browser API may not be available');
        }

        api.runtime.onMessage?.addListener(handleMessage);

        api.runtime.onConnect?.addListener(port => {
            if (port?.name === ports.BLOCKED_COUNTER) {
                blockingService.connectWarningPort(port);
            }
        });

        api.tabs?.onRemoved?.addListener(tabId => {
            resultAggregationService.clear(tabId);
            providerEngine.abortTab(tabId);
            cacheService.clearProcessingByTab(tabId);
            badgeService.clearTab(tabId);
            blockingService.clearTab(tabId);
        });

        await runEmergencySettingsMigrations();

        navigationService.register();
    };

    init().catch(error => {
        console.error('Background init failed', error);
    });
})();
