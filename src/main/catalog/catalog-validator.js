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

globalThis.OspreyCatalogValidator = (() => {
    const providerGroups = globalThis.OspreyProviderGroups;

    const validKinds = new Set(['proxy_builtin', 'direct_static']);
    const validLookupTargets = new Set(['hostname', 'url']);
    const validReportTypes = new Set(['mailto_false_positive', 'external_url', 'url_template', 'none']);
    const validProtocols = new Set(['http:', 'https:', 'mailto:']);
    const validRequestMethods = new Set(['GET', 'POST']);

    const validRuleOperators = new Set([
        'exists', 'not_exists', 'truthy', 'falsy', 'equals', 'not_equals',
        'contains', 'greater_than', 'less_than', 'greater_or_equal', 'less_or_equal', 'regex',
    ]);

    const idPattern = /^[a-z0-9-]+$/;
    const templateRegex = /{lookupValue}|{hostname}|{url}|{apiKey}|{api_key}/g;

    const urlValidationCache = new Map();

    const fail = (message, ErrorType = Error) => {
        throw new ErrorType(message);
    };

    const requireObject = (value, message) => value !== null && typeof value === 'object' && !Array.isArray(value) || fail(message);
    const requireString = (value, message) => typeof value === 'string' && value.trim().length > 0 || fail(message);
    const requireArray = (value, message) => Array.isArray(value) || fail(message, TypeError);
    const requireBoolean = (value, message) => typeof value === 'boolean' || fail(message, TypeError);
    const requireOneOf = (value, validSet, message) => validSet.has(value) || fail(message);
    const requirePattern = (value, pattern, message) => typeof value === 'string' && pattern.test(value) || fail(message);

    const addUnique = (set, value, message) => {
        if (set.has(value)) {
            fail(message);
        }

        set.add(value);
    };

    const cacheUrlResult = (strValue, isValid) => {
        if (urlValidationCache.size >= 2048) {
            urlValidationCache.clear();
        }
        urlValidationCache.set(strValue, isValid);
    };

    const ensureUrl = (label, value) => {
        const strValue = String(value || '');

        if (urlValidationCache.has(strValue)) {
            if (!urlValidationCache.get(strValue)) {
                fail(`${label} must be a valid URL`);
            }
            return;
        }

        try {
            const parsed = new URL(strValue);

            if (!validProtocols.has(parsed.protocol)) {
                cacheUrlResult(strValue, false);
                fail('unsupported protocol');
            }

            cacheUrlResult(strValue, true);
        } catch {
            cacheUrlResult(strValue, false);
            fail(`${label} must be a valid URL`);
        }
    };

    const validateReport = (definition, report) => {
        requireObject(report, `Missing report template for ${definition.id}`);
        requireOneOf(report.type, validReportTypes, `Invalid report type for ${definition.id}: ${report.type}`);

        switch (report.type) {
            case 'mailto_false_positive':
                if (typeof report.email !== 'string' || !report.email.includes('@')) {
                    fail(`Invalid report email for ${definition.id}`);
                }

                requireString(report.productName, `Missing report product name for ${definition.id}`);
                break;

            case 'external_url':
                ensureUrl(`External report URL for ${definition.id}`, report.url);
                break;

            case 'url_template':
                if (typeof report.template !== 'string' || !report.template.includes('{url}')) {
                    fail(`URL-template report for ${definition.id} must include {url}`);
                }

                ensureUrl(`Template report URL for ${definition.id}`, report.template.replaceAll('{url}', 'https%3A%2F%2Fexample.com'));
                break;
        }
    };

    const validateDirectRequestRule = (definition, rule) => {
        requireObject(rule, `Invalid response rule for ${definition.id}`);
        requireString(rule.path, `Response rule path missing for ${definition.id}`);
        requireOneOf(String(rule.operator || 'equals'), validRuleOperators, `Invalid response rule operator for ${definition.id}`);
        requireString(rule.result, `Response rule result missing for ${definition.id}`);
    };

    const templateReplacer = match => {
        switch (match) {
            case '{url}':
                return 'https://example.com';

            case '{apiKey}':
            case '{api_key}':
                return 'sample';

            default:
                return 'example.com';
        }
    };

    const validateDirectRequest = definition => {
        const request = definition.request;
        const responseRules = definition.responseRules;

        requireObject(request, `Missing request definition for ${definition.id}`);
        requireString(request.urlTemplate, `Missing request URL template for ${definition.id}`);

        const template = request.urlTemplate.replace(templateRegex, templateReplacer);

        ensureUrl(`Request URL for ${definition.id}`, template);

        const method = String(request.method || 'GET').toUpperCase();
        requireOneOf(method, validRequestMethods, `Invalid request method for ${definition.id}`);
        requireArray(request.headers, `Headers must be an array for ${definition.id}`);
        requireArray(responseRules, `Direct provider ${definition.id} must declare response rules`);

        const rulesLength = responseRules.length;

        if (rulesLength === 0) {
            fail(`Direct provider ${definition.id} must declare response rules`);
        }

        for (let i = 0; i < rulesLength; i++) {
            validateDirectRequestRule(definition, responseRules[i]);
        }
    };

    const validateAliases = (definition, aliases) => {
        addUnique(aliases, definition.id, `Alias collision on provider id: ${definition.id}`);

        const definitionAliases = definition.aliases;

        if (definitionAliases !== undefined && definitionAliases !== null) {
            requireArray(definitionAliases, `Aliases must be an array on ${definition.id}`);
            const aliasLength = definitionAliases.length;

            for (let i = 0; i < aliasLength; i++) {
                const alias = definitionAliases[i];
                requireString(alias, `Invalid alias on ${definition.id}`);

                if (alias !== definition.id) {
                    addUnique(aliases, alias, `Duplicate alias: ${alias}`);
                }
            }
        }
    };

    const validateProxyBuiltin = (definition, proxyEndpoints) => {
        const proxyBaseUrl = definition.proxyBaseUrl;

        if (typeof proxyBaseUrl !== 'string' || !proxyBaseUrl.startsWith('http')) {
            fail(`Invalid proxy base URL for ${definition.id}`);
        }

        requirePattern(definition.endpoint, idPattern, `Invalid proxy endpoint for ${definition.id}`);
        addUnique(proxyEndpoints, definition.endpoint, `Duplicate proxy endpoint: ${definition.endpoint}`);
    };

    const validateDefinition = (definition, state) => {
        requireObject(definition, 'Catalog entry must be an object');

        const id = definition.id;
        const kind = definition.kind;

        requireOneOf(kind, validKinds, `Invalid provider kind for ${id}: ${kind}`);
        requirePattern(id, idPattern, `Invalid provider id: ${id}`);

        addUnique(state.ids, id, `Duplicate provider id: ${id}`);
        validateAliases(definition, state.aliases);

        if (!state.groups.has(definition.group)) {
            fail(`Unknown provider group for ${id}: ${definition.group}`);
        }

        requireString(definition.displayName, `Missing displayName for ${id}`);
        requireBoolean(definition.enabledByDefault, `Missing enabledByDefault boolean for ${id}`);
        requireOneOf(definition.lookupTarget, validLookupTargets, `Invalid lookup target for ${id}: ${definition.lookupTarget}`);

        if (definition.bypassBlockingThreshold !== undefined && definition.bypassBlockingThreshold !== null) {
            requireBoolean(definition.bypassBlockingThreshold, `Invalid bypassBlockingThreshold flag for ${id}`);
        }

        requireString(definition.icon, `Icon path must be a string for ${id}`);
        requireArray(definition.tags, `Tags must be an array for ${id}`);
        validateReport(definition, definition.report);

        const policyKey = definition.policyKey;

        if (policyKey) {
            addUnique(state.policyKeys, policyKey, `Duplicate policy key: ${policyKey}`);
        }

        if (kind === 'proxy_builtin') {
            validateProxyBuiltin(definition, state.proxyEndpoints);
        } else if (kind === 'direct_static') {
            validateDirectRequest(definition);
        }
    };

    const validate = definitions => {
        if (!Array.isArray(definitions)) {
            return;
        }

        const state = {
            ids: new Set(),
            aliases: new Set(),
            policyKeys: new Set(),
            proxyEndpoints: new Set(),
            groups: new Set(Object.keys(providerGroups || {})),
        };

        const len = definitions.length;

        for (let i = 0; i < len; i++) {
            validateDefinition(definitions[i], state);
        }
    };

    return Object.freeze({
        validate,
    });
})();
