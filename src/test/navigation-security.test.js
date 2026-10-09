/*
 * Copyright (C) 2024-2026 Osprey Project LLC and contributors (https://osprey.ac)
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
'use strict';

const assert = require('node:assert/strict');
const {readFileSync} = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const main = path.join(__dirname, '..', 'main');
const load = (context, file) => vm.runInContext(
    readFileSync(path.join(main, file), 'utf8'),
    context,
    {filename: file},
);

const createContext = overrides => vm.createContext({
    URL,
    console,
    ...overrides,
});

test('HTTP URLs with underscores and edge hyphens remain eligible for scans', () => {
    const context = createContext({
        OspreyBrowserAPI: {safeRuntimeURL: path => `chrome-extension://test/${path}`},
    });
    load(context, 'platform/url-service.js');

    const urls = [
        'https://login_microsoft.evil.com/login',
        'https://-x.evil.com/',
        'https://x-.evil.com/',
    ];

    for (const url of urls) {
        assert.equal(context.OspreyUrlService.parseHttpUrl(url)?.href, url);
        assert.ok(context.OspreyUrlService.normalizeUrl(url));
    }

    assert.equal(context.OspreyUrlService.parseHttpUrl('https://a..evil.com/'), null);
    assert.equal(context.OspreyUrlService.parseHttpUrl('file:///popup.html'), null);
    assert.equal(context.OspreyUrlService.parseHttpUrl('chrome-extension://test/pages/popup/popup-page.html'), null);
});

test('provider engine evaluates managed protection for nonstandard DNS labels', async () => {
    const checked = [];
    const results = [];
    const context = createContext({
        AbortController,
        OspreyBrowserAPI: {safeRuntimeURL: path => `chrome-extension://test/${path}`},
        OspreyCacheService: {
            getManagedListDecision: async url => {
                checked.push(url.hostname);
                return {blocked: true};
            },
            clearProcessingByTab() {
            },
        },
        OspreyProtectionResult: {
            resultTypes: {MALICIOUS: 'malicious'},
            create: result => result,
        },
    });
    load(context, 'platform/url-service.js');
    load(context, 'providers/provider-engine.js');

    for (const host of ['login_microsoft.evil.com', '-x.evil.com']) {
        await context.OspreyProviderEngine.scanUrl({
            tabId: 1,
            url: `https://${host}/`,
            providers: [{id: 'managed', kind: 'managed_local'}],
            onResult: result => results.push(result.result),
        });
    }
    assert.deepEqual(checked, ['login_microsoft.evil.com', '-x.evil.com']);
    assert.deepEqual(results, ['malicious', 'malicious']);
});

test('managed popup-hiding policy cannot skip external URLs containing the popup path', async () => {
    const scanned = [];
    const context = createContext({
        OspreyBrowserAPI: {safeRuntimeURL: path => `chrome-extension://test/${path}`},
        OspreyBadgeService: {
            clear() {
            }
        },
        OspreyCacheService: {},
        OspreyEventLogService: {},
        OspreyMessageBus: {Messages: {}},
        OspreyProviderEngine: {
            scanUrl: async request => scanned.push(request.url),
        },
        OspreyProviderRuntimeFactory: {
            createRuntime: async () => ({
                providers: [{state: {enabled: true}}],
                effectiveState: {app: {hideProviderControls: true, domainIntelMode: 'off'}},
            }),
        },
        OspreyResultAggregationService: {
            ensureHydrated: async () => {
            },
            beginNavigation() {
            },
            setFrameZeroUrl() {
            },
        },
    });
    load(context, 'platform/url-service.js');
    load(context, 'background/blocking-service.js');

    await context.OspreyBlockingService.handleNavigation({
        tabId: 1,
        url: 'https://evil.com/?x=/pages/popup/popup-page.html',
    });
    await context.OspreyBlockingService.handleNavigation({
        tabId: 1,
        url: 'https://evil.com/pages/popup/popup-page.html',
    });
    await context.OspreyBlockingService.handleNavigation({
        tabId: 1,
        url: 'https://login_microsoft.evil.com/',
    });

    assert.deepEqual(scanned, [
        'https://evil.com/?x=/pages/popup/popup-page.html',
        'https://evil.com/pages/popup/popup-page.html',
        'https://login_microsoft.evil.com/',
    ]);
});

test('navigation and alarm listeners are ready before startup storage resolves', async () => {
    const listeners = new Map();
    const event = name => ({
        addListener: listener => {
            const registered = listeners.get(name) || [];
            registered.push(listener);
            listeners.set(name, registered);
        },
    });
    let finishMigration;
    const migration = new Promise(resolve => {
        finishMigration = resolve;
    });
    const navigations = [];
    const alarms = [];
    let refreshes = 0;
    let flushes = 0;
    let heartbeats = 0;

    const api = {
        runtime: {
            id: 'test',
            onMessage: event('message'),
            onInstalled: event('installed'),
            onConnect: event('connect'),
            setUninstallURL: async () => {
            },
        },
        tabs: {
            onRemoved: event('removed'),
            onUpdated: event('updated'),
        },
        webNavigation: {
            onBeforeNavigate: event('beforeNavigate'),
        },
        alarms: {
            onAlarm: event('alarm'),
            create: name => alarms.push(name),
        },
    };
    const context = createContext({
        OspreyBrowserAPI: {api, safeRuntimeURL: path => `chrome-extension://test/${path}`},
        OspreyBadgeService: {},
        OspreyBlockingService: {
            handleNavigation: async details => navigations.push(details.url),
        },
        OspreyCacheService: {},
        OspreyEventLogService: {
            reportFlushAlarmName: 'flush',
            heartbeatAlarmName: 'heartbeat',
            reportFlushIntervalMinutes: 5,
            heartbeatIntervalMinutes: 5,
            flushToReporting: async () => {
                flushes++;
            },
            sendHeartbeat: async () => {
                heartbeats++;
            },
        },
        OspreyMessageBus: {Messages: {}, Ports: {}},
        OspreyPolicyService: {
            remoteConfigAlarmName: 'remote',
            remoteConfigRefreshMinutes: 5,
            initRemoteConfig: async () => {
            },
            refreshRemoteConfig: async () => {
                refreshes++;
            },
            isUninstallSurveyDisabled: async () => true,
        },
        OspreyProviderCatalog: {},
        OspreyProviderEngine: {},
        OspreyProviderStateStore: {getState: () => migration},
        OspreyReportLinkBuilder: {},
        OspreyResultAggregationService: {},
    });
    load(context, 'platform/url-service.js');
    load(context, 'background/navigation-service.js');
    load(context, 'background.js');

    assert.equal(listeners.get('beforeNavigate')?.length, 1);
    assert.equal(listeners.get('updated')?.length, 1);
    assert.equal(listeners.get('alarm')?.length, 2);
    listeners.get('beforeNavigate')[0]({tabId: 1, frameId: 0, url: 'https://-x.evil.com/'});
    listeners.get('updated')[0](2, {url: 'https://x-.evil.com/'});
    for (const listener of listeners.get('alarm')) {
        for (const name of ['remote', 'flush', 'heartbeat']) {
            listener({name});
        }
    }
    await Promise.resolve();
    assert.deepEqual(navigations, ['https://-x.evil.com/', 'https://x-.evil.com/']);
    assert.equal(refreshes, 1);
    assert.equal(flushes, 1);
    assert.equal(heartbeats, 1);

    finishMigration({providers: {}});
    await new Promise(resolve => setImmediate(resolve));
    assert.ok(alarms.includes('remote'));
    assert.ok(alarms.includes('flush'));
    assert.ok(alarms.includes('heartbeat'));
});
