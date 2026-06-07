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

    const allDefinitions = Object.freeze([...staticDefinitions]);
    const byId = new Map(allDefinitions.map(definition => [definition.id, definition]));
    const staticAliasMap = new Map();
    const sharedApiKeyGroupMembers = new Map();

    for (const {id, aliases = []} of staticDefinitions) {
        staticAliasMap.set(id, id);

        for (const alias of aliases) {
            staticAliasMap.set(alias, id);
        }
    }

    for (const definition of directIntegrations) {
        const groupId = String(definition?.sharedApiKeyGroup || '');

        if (!groupId) {
            continue;
        }

        const members = sharedApiKeyGroupMembers.get(groupId) || [];
        members.push(definition.id);
        sharedApiKeyGroupMembers.set(groupId, members);
    }

    const getAllDefinitions = () => allDefinitions;
    const resolveId = (idOrAlias) => staticAliasMap.get(idOrAlias);

    const getDefinition = (idOrAlias) => {
        const resolvedId = resolveId(idOrAlias);
        const definition = byId.get(resolvedId) || null;

        if (!definition && String(idOrAlias || '').trim()) {
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

    const getSharedGroupMembersById = providerId => {
        const definition = getDefinition(providerId);
        const groupId = String(definition?.sharedApiKeyGroup || '');
        return groupId ? sharedApiKeyGroupMembers.get(groupId) || [] : [];
    };

    // Public API
    return Object.freeze({
        getBuiltins,
        getDirectIntegrations,
        getSharedGroupMembersById,
        getAllDefinitions,
        getDefinition,
        requiresApiKey,
        proxyEndpointUrl,
        hasAdultFilter,
        supportsBlockingResult,
        resolveIconUrl,
    });
})();
