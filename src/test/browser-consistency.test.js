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
const source = file => readFileSync(path.join(main, file), 'utf8');
const load = (context, file) => vm.runInContext(source(file), context, {filename: file});
const deferred = () => {
    let resolve;
    const promise = new Promise(done => {
        resolve = done;
    });
    return {promise, resolve};
};

test('Firefox background page loads every Chrome bootstrap dependency in order', () => {
    const scripts = [...source('background.html').matchAll(/<script src="([^"]+)"/g)].map(match => match[1]);
    const worker = source('background.js');
    const bootstrap = worker.match(/const bootstrapScripts = \[([\s\S]*?)\];/);
    assert.ok(bootstrap);
    const dependencies = [...bootstrap[1].matchAll(/'([^']+)'/g)].map(match => match[1]);
    assert.deepEqual(scripts, [...dependencies, 'background.js']);

    const workflow = readFileSync(path.join(main, '..', '..', '.github', 'workflows', 'firefox.yml'), 'utf8');
    assert.match(workflow, /"page": "background\.html"/);
    assert.match(workflow, /browser_specific_settings/);
    assert.equal((source('pages/settings/settings-page.html').match(/src="\.\.\/\.\.\/shared\/lang-util\.js"/g) || []).length, 1);
});

test('Cloudflare report sends a hostname without leaking the blocked URL path', () => {
    const context = vm.createContext({
        URL, console: {
            warn() {
            }
        }
    });
    load(context, 'providers/provider-groups.js');
    load(context, 'providers/proxy-builtins.js');
    load(context, 'catalog/catalog-validator.js');
    load(context, 'platform/report-link-builder.js');
    assert.doesNotThrow(() => context.OspreyCatalogValidator.validate(context.OspreyProxyBuiltins));
    const template = context.OspreyProxyBuiltins.find(provider => provider.id === 'cloudflare').report;
    const build = context.OspreyReportLinkBuilder.build;
    assert.equal(build(template, {blockedUrl: 'https://sub.example.com/private?token=secret'}),
        'https://radar.cloudflare.com/domains/feedback/sub.example.com');
    assert.equal(build(template, {blockedUrl: 'not a URL'}), null);
    assert.equal(build({type: 'url_template', template: 'https://report.example/?url={url}'},
            {blockedUrl: 'https://example.com/a?b=c'}),
        'https://report.example/?url=https%3A%2F%2Fexample.com%2Fa%3Fb%3Dc');
});

test('hydration shields closed tabs, then releases all per-tab authority markers', async () => {
    const requested = deferred();
    const release = deferred();
    const sets = [];

    class TrackedSet extends Set {
        constructor(...args) {
            super(...args);
            sets.push(this);
        }
    }

    const snapshots = [];
    const context = vm.createContext({
        console,
        Set: TrackedSet,
        OspreyBrowserAPI: {
            storageGet: async () => {
                requested.resolve();
                await release.promise;
                return {
                    'osprey.blockedContexts': {
                        tabs: {
                            '1': {
                                blocked: {
                                    url: 'https://blocked.example/',
                                    entries: [['provider', 'malicious']],
                                    total: 1
                                },
                                frameZeroUrl: 'https://blocked.example/',
                                warningReady: true,
                            }
                        },
                    }
                };
            },
            storageSet: async (_, value) => {
                snapshots.push(value['osprey.blockedContexts']);
            },
        },
        OspreyProtectionResult: {severityRank: () => 1},
        OspreyUrlService: {normalizeUrl: url => url},
    });
    load(context, 'background/result-aggregation-service.js');
    const service = context.OspreyResultAggregationService;
    const hydration = service.ensureHydrated();
    await requested.promise;
    service.releaseTab(1);
    release.resolve();
    await hydration;
    assert.equal(service.getBlockedContext(1), null);
    assert.equal(service.getFrameZeroUrl(1), '');
    assert.equal(service.isWarningPageReady(1), false);
    assert.equal(sets[0].size, 0);
    assert.equal(sets[1].size, 0);

    for (let tabId = 2; tabId < 2002; tabId++) {
        service.beginNavigation(tabId);
        service.setFrameZeroUrl(tabId, `https://${tabId}.example/`);
        service.releaseTab(tabId);
    }
    await service.persist();
    assert.equal(sets[0].size, 0);
    assert.equal(sets[1].size, 0);
    assert.equal(Object.keys(snapshots.at(-1).tabs).length, 0);
});

test('navigation service does not register an unhandled navigation-target event', () => {
    const registered = [];
    const webNavigation = Object.fromEntries(
        ['onBeforeNavigate', 'onCompleted', 'onHistoryStateUpdated', 'onReferenceFragmentUpdated',
            'onCreatedNavigationTarget'].map(name => [name, {addListener: () => registered.push(name)}]),
    );
    const context = vm.createContext({
        OspreyBrowserAPI: {api: {webNavigation}},
        OspreyBlockingService: {},
        OspreyUrlService: {},
    });
    load(context, 'background/navigation-service.js');
    context.OspreyNavigationService.register();
    assert.deepEqual(registered, [
        'onBeforeNavigate', 'onCompleted', 'onHistoryStateUpdated', 'onReferenceFragmentUpdated',
    ]);
});
