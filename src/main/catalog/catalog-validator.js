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

globalThis.OspreyCatalogValidator = (() => {
    // Global variables
    const providerGroups = globalThis.OspreyProviderGroups;

    const validKinds = Object.freeze(['proxy_builtin', 'direct_static']);
    const validLookupTargets = Object.freeze(['hostname', 'url']);
    const validReportTypes = Object.freeze(['mailto_false_positive', 'external_url', 'url_template', 'none']);
    const validProtocols = Object.freeze(['http:', 'https:', 'mailto:']);
    const validRequestMethods = Object.freeze(['GET', 'POST']);

    const validRuleOperators = Object.freeze([
        'exists', 'not_exists', 'truthy', 'falsy', 'equals', 'not_equals',
        'contains', 'greater_than', 'less_than', 'greater_or_equal', 'less_or_equal', 'regex',
    ]);

    const idPattern = /^[a-z0-9-]+$/;

    const fail = (message, ErrorType = Error) => {
        throw new ErrorType(message);
    };

    const requireObject = (value, message) => value && typeof value === 'object' || fail(message);
    const requireString = (value, message) => typeof value === 'string' && value.trim() || fail(message);
    const requireArray = (value, message) => Array.isArray(value) || fail(message, TypeError);
    const requireBoolean = (value, message) => typeof value === 'boolean' || fail(message, TypeError);
    const requireOneOf = (value, validValues, message) => validValues.includes(value) || fail(message);
    const requirePattern = (value, pattern, message) => typeof value === 'string' && pattern.test(value) || fail(message);

    const addUnique = (set, value, message) => {
        if (set.has(value)) {
            fail(message);
        }

        set.add(value);
    };

    const ensureUrl = (label, value) => {
        try {
            const parsed = new URL(String(value || ''));

            if (!validProtocols.includes(parsed.protocol)) {
                fail('unsupported protocol');
            }
        } catch {
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

                ensureUrl(`Template report URL for ${definition.id}`, report.template.replace('{url}', 'https%3A%2F%2Fexample.test'));
                break;
        }
    };

    const validateDirectRequestRule = (definition, rule) => {
        requireObject(rule, `Invalid response rule for ${definition.id}`);
        requireString(rule.path, `Response rule path missing for ${definition.id}`);
        requireOneOf(String(rule.operator || 'equals'), validRuleOperators, `Invalid response rule operator for ${definition.id}`);
        requireString(rule.result, `Response rule result missing for ${definition.id}`);
    };

    const validateDirectRequest = definition => {
        const {request, responseRules} = definition;

        requireObject(request, `Missing request definition for ${definition.id}`);
        requireString(request.urlTemplate, `Missing request URL template for ${definition.id}`);

        ensureUrl(
            `Request URL for ${definition.id}`,
            request.urlTemplate
                .replaceAll('{lookupValue}', 'example.test')
                .replaceAll('{hostname}', 'example.test')
                .replaceAll('{url}', 'https://example.test')
                .replaceAll('{apiKey}', 'sample')
                .replaceAll('{api_key}', 'sample')
        );

        requireOneOf(String(request.method || 'GET').toUpperCase(), validRequestMethods, `Invalid request method for ${definition.id}`);
        requireArray(request.headers, `Headers must be an array for ${definition.id}`);
        requireArray(responseRules, `Direct provider ${definition.id} must declare response rules`);

        if (responseRules.length === 0) {
            fail(`Direct provider ${definition.id} must declare response rules`);
        }

        for (const rule of responseRules) {
            validateDirectRequestRule(definition, rule);
        }
    };

    const validateAliases = (definition, aliases) => {
        addUnique(aliases, definition.id, `Alias collision on provider id: ${definition.id}`);

        for (const alias of definition.aliases || []) {
            requireString(alias, `Invalid alias on ${definition.id}`);

            if (alias !== definition.id) {
                addUnique(aliases, alias, `Duplicate alias: ${alias}`);
            }
        }
    };

    const validateProxyBuiltin = (definition, proxyEndpoints) => {
        if (typeof definition.proxyBaseUrl !== 'string' || !definition.proxyBaseUrl.startsWith('http')) {
            fail(`Invalid proxy base URL for ${definition.id}`);
        }

        requirePattern(definition.endpoint, idPattern, `Invalid proxy endpoint for ${definition.id}`);
        addUnique(proxyEndpoints, definition.endpoint, `Duplicate proxy endpoint: ${definition.endpoint}`);
    };

    const validateDefinition = (definition, state) => {
        requireObject(definition, 'Catalog entry must be an object');
        requireOneOf(definition.kind, validKinds, `Invalid provider kind for ${definition?.id}: ${definition?.kind}`);
        requirePattern(definition.id, idPattern, `Invalid provider id: ${definition?.id}`);

        addUnique(state.ids, definition.id, `Duplicate provider id: ${definition.id}`);
        validateAliases(definition, state.aliases);

        if (!state.groups.has(definition.group)) {
            fail(`Unknown provider group for ${definition.id}: ${definition.group}`);
        }

        requireString(definition.displayName, `Missing displayName for ${definition.id}`);
        requireBoolean(definition.enabledByDefault, `Missing enabledByDefault boolean for ${definition.id}`);
        requireOneOf(definition.lookupTarget, validLookupTargets, `Invalid lookup target for ${definition.id}: ${definition.lookupTarget}`);

        if (definition.bypassBlockingThreshold != null) {
            requireBoolean(definition.bypassBlockingThreshold, `Invalid bypassBlockingThreshold flag for ${definition.id}`);
        }

        requireString(definition.icon, `Icon path must be a string for ${definition.id}`);
        requireArray(definition.tags, `Tags must be an array for ${definition.id}`);
        validateReport(definition, definition.report);

        if (definition.policyKey) {
            addUnique(state.policyKeys, definition.policyKey, `Duplicate policy key: ${definition.policyKey}`);
        }

        if (definition.kind === 'proxy_builtin') {
            validateProxyBuiltin(definition, state.proxyEndpoints);
        } else if (definition.kind === 'direct_static') {
            validateDirectRequest(definition);
        }
    };

    const validate = definitions => {
        const state = {
            ids: new Set(),
            aliases: new Set(),
            policyKeys: new Set(),
            proxyEndpoints: new Set(),
            groups: new Set(Object.keys(providerGroups || {})),
        };

        for (const definition of definitions) {
            validateDefinition(definition, state);
        }
    };

    // Public API
    return Object.freeze({
        validate
    });
})();
