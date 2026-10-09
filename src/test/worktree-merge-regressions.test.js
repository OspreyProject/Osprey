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
    readFileSync(path.join(main, file), 'utf8'), context, {filename: file},
);

test('internal hostnames cover reserved suffixes, shared ranges, mapped IPv6 and single-label names', () => {
    const context = vm.createContext({
        URL,
        console,
        OspreyBrowserAPI: {safeRuntimeURL: p => `chrome-extension://test/${p}`},
    });
    load(context, 'platform/url-service.js');
    const internal = context.OspreyUrlService.isInternalHostname;

    for (const host of ['printer.lan', 'nas.home.arpa', 'a.internal', '100.64.0.1', '198.18.0.1',
        '[::ffff:7f00:1]', '[::ffff:10.0.0.1]', '[fec0::1]', 'intranet']) {
        assert.equal(internal(host), true, host);
    }

    for (const host of ['example.com', '8.8.8.8', '100.128.0.1', '[::ffff:808:808]', '[2001:db8::1]']) {
        assert.equal(internal(host), false, host);
    }
});

test('custom providers cannot use ids that collide with Object.prototype members', () => {
    const context = vm.createContext({URL, console: {warn() {}}, OspreyProviderGroups: {feeds: {}}});
    load(context, 'catalog/catalog-validator.js');
    const definition = id => ({
        id, kind: 'direct_static', group: 'feeds', displayName: 'Test Feed',
        enabledByDefault: true, lookupTarget: 'url', icon: 'icon.svg', tags: [],
        report: {type: 'none'}, request: {urlTemplate: 'https://feed.example/check', headers: []},
        responseRules: [{path: 'value', operator: 'equals', value: 'bad', result: 'BLOCKED'}],
    });

    assert.equal(context.OspreyCatalogValidator.validateCustom([definition('test-feed')], []).valid.length, 1);
    assert.equal(context.OspreyCatalogValidator.validateCustom([definition('constructor')], []).valid.length, 0);
    assert.equal(context.OspreyCatalogValidator.validateCustom([definition('prototype')], []).valid.length, 0);
});

test('notification registry is never rewritten when it could not be read', async () => {
    let registryReadable = false;
    let writes = 0;
    const settings = [];
    const context = vm.createContext({
        URL, console,
        OspreyBrowserAPI: {
            storage: {
                local: {
                    get: (_, callback) => callback(registryReadable ? {osprey_notification_origins: {}} : undefined),
                    set: (_, callback) => {
                        writes++;
                        callback();
                    },
                }
            }
        },
        chrome: {
            runtime: {lastError: null},
            contentSettings: {
                notifications: {
                    set: (entry, callback) => {
                        settings.push(entry);
                        callback();
                    },
                }
            }
        },
    });
    context.OspreyBrowserAPI.storage.local.get = (_, callback) => {
        context.chrome.runtime.lastError = registryReadable ? null : {message: 'read failed'};
        callback(registryReadable ? {osprey_notification_origins: {}} : undefined);
    };
    load(context, 'state/notification-service.js');
    const service = context.OspreyNotificationService;

    assert.equal((await service.blockForUrl('https://scam.example/')).reason, 'registry_unavailable');
    assert.equal(settings.length, 0);
    assert.equal(writes, 0);
    assert.equal((await service.resetForHost('scam.example')).reason, 'registry_unavailable');
    assert.equal(writes, 0);

    registryReadable = true;
    assert.equal((await service.blockForUrl('https://scam.example/')).ok, true);
    assert.equal(settings.length, 1);
});

test('custom providers with malformed block categories or report emails are rejected', () => {
    const context = vm.createContext({URL, console: {warn() {}}, OspreyProviderGroups: {feeds: {}}});
    load(context, 'catalog/catalog-validator.js');
    const definition = overrides => ({
        id: 'test-feed', kind: 'direct_static', group: 'feeds', displayName: 'Test Feed',
        enabledByDefault: true, lookupTarget: 'url', icon: 'icon.svg', tags: [],
        report: {type: 'none'}, request: {urlTemplate: 'https://feed.example/check', headers: []},
        responseRules: [{path: 'value', operator: 'equals', value: 'bad', result: 'BLOCKED'}],
        ...overrides,
    });
    const accepted = overrides => context.OspreyCatalogValidator.validateCustom([definition(overrides)], []).valid.length === 1;
    const mailto = email => ({report: {type: 'mailto_false_positive', email, productName: 'Feed'}});

    assert.equal(accepted({blockCategories: [{key: 'newly_registered', label: 'blockNewlyRegistered'}]}), true);
    assert.equal(accepted({blockCategories: [null]}), false);
    assert.equal(accepted({blockCategories: [{label: 'missing key'}]}), false);
    assert.equal(accepted({blockCategories: {key: 'suspicious'}}), false);
    assert.equal(accepted(mailto('reports@feed.example')), true);
    assert.equal(accepted(mailto('a@b.example?cc=x@evil.example&')), false);
    assert.equal(accepted(mailto('a@b.example#x')), false);
});
