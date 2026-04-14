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

globalThis.OspreyProviderCatalog = (() => {
    // Global variables
    const catalogValidator = globalThis.OspreyCatalogValidator;
    const directIntegrations = globalThis.OspreyDirectIntegrations || [];
    const protectionResult = globalThis.OspreyProtectionResult;
    const proxyBuiltins = globalThis.OspreyProxyBuiltins || [];

    const cloneArray = value => Array.isArray(value) ? value.slice() : [];

    const normalizeHeaders = headers => Array.isArray(headers) ? headers.map(({name = '', value = ''} = {}) => ({
        name, value
    })) : [];

    const staticDefinitions = Object.freeze([...proxyBuiltins, ...directIntegrations]);
    catalogValidator.validate(staticDefinitions);

    const byId = new Map(staticDefinitions.map(definition => [definition.id, definition]));
    const staticAliasMap = new Map();

    for (const {id, aliases = []} of staticDefinitions) {
        staticAliasMap.set(id, id);

        for (const alias of aliases) {
            staticAliasMap.set(alias, id);
        }
    }

    const customDefinitionFromState = record => {
        if (!record || typeof record !== 'object' || typeof record.id !== 'string' || !/^custom-[a-z0-9-]+$/.test(record.id)) {
            return null;
        }

        const request = record.request || {};

        return Object.freeze({
            kind: 'direct_custom',
            group: 'custom_providers',
            enabledByDefault: false,
            icon: '',
            aliases: cloneArray(record.aliases),
            tags: cloneArray(record.tags),
            report: record.report || {type: 'none'},
            id: record.id,
            displayName: String(record.displayName || record.name || record.id),
            lookupTarget: record.lookupTarget === 'hostname' ? 'hostname' : 'url',
            bypassBlockingThreshold: record.bypassBlockingThreshold === true,
            request: Object.freeze({
                urlTemplate: String(request.urlTemplate || ''),
                method: request.method === 'POST' ? 'POST' : 'GET',
                headers: normalizeHeaders(request.headers),
                bodyTemplate: String(request.bodyTemplate || ''),
                contentType: String(request.contentType || 'application/json'),
                timeoutMs: Number(request.timeoutMs) > 0 ? Number(request.timeoutMs) : 7000,
            }),
            responseRules: Array.isArray(record.responseRules) ? record.responseRules.map(rule => Object.freeze({...rule})) : [],
        });
    };

    const getCustomDefinitions = state => Object.values(state?.customProviders || {}).map(customDefinitionFromState).filter(Boolean);

    const resolveCustomId = (idOrAlias, state) => {
        const needle = String(idOrAlias || '');

        for (const {id, aliases = []} of getCustomDefinitions(state)) {
            if (id === needle || aliases.includes(needle)) {
                return id;
            }
        }
        return needle;
    };

    const getAllDefinitions = state => Object.freeze([...staticDefinitions, ...getCustomDefinitions(state)]);
    const resolveId = (idOrAlias, state = null) => staticAliasMap.get(idOrAlias) || resolveCustomId(idOrAlias, state);

    const getDefinition = (idOrAlias, state = null) => {
        const resolvedId = resolveId(idOrAlias, state);
        const definition = byId.get(resolvedId) || getCustomDefinitions(state).find(({id}) => id === resolvedId) || null;

        if (!definition && String(idOrAlias || '').trim() && !/^custom-[a-z0-9-]+$/i.test(String(idOrAlias))) {
            console.warn(`OspreyProviderCatalog could not resolve provider '${idOrAlias}'`);
        }
        return definition;
    };

    const requiresApiKey = definition => {
        if (definition?.kind !== 'direct_static') {
            return false;
        }

        const request = definition.request || {};

        return cloneArray(definition.tags).includes('api_key_required') ||
            /\{api(?:_|)key}/.test(String(request.urlTemplate || '')) ||
            /\{api(?:_|)key}/.test(String(request.bodyTemplate || '')) ||
            normalizeHeaders(request.headers).some(({value}) => /\{api(?:_|)key}/.test(String(value)));
    };

    const proxyEndpointUrl = definition => {
        if (definition?.kind !== 'proxy_builtin') {
            return '';
        }

        const base = String(definition.proxyBaseUrl || 'https://api.osprey.ac').replace(/\/+$/u, '');
        const endpoint = String(definition.endpoint || definition.id).replace(/^\/+/, '');
        return `${base}/${endpoint}`;
    };

    const hasAdultFilter = definition => cloneArray(definition?.tags).includes('adult_filter') ||
        definition?.group === 'adult_content_filters';

    const supportsBlockingResult = (definition, result) => {
        const normalizedResult = String(result || '');

        if (normalizedResult === protectionResult?.resultTypes?.ADULT_CONTENT) {
            return hasAdultFilter(definition);
        }

        if (protectionResult?.blockingResults?.has(normalizedResult)) {
            return !hasAdultFilter(definition);
        }

        return false;
    };

    const resolveIconUrl = (definition, depth = 2) => {
        const value = String(definition?.icon || '').replace(/^\/+/, '');
        return value ? `${'../'.repeat(depth)}${value}` : '';
    };

    const getBuiltins = () => proxyBuiltins.slice();
    const getDirectIntegrations = () => directIntegrations.slice();

    const getSharedApiKeyGroupMembers = groupId => directIntegrations
        .filter(definition => String(definition?.sharedApiKeyGroup || '') === String(groupId || ''))
        .map(definition => definition.id);

    // Public API
    return Object.freeze({
        getBuiltins,
        getDirectIntegrations,
        getSharedApiKeyGroupMembers,
        getAllDefinitions,
        getDefinition,
        requiresApiKey,
        proxyEndpointUrl,
        hasAdultFilter,
        supportsBlockingResult,
        resolveIconUrl,
    });
})();
