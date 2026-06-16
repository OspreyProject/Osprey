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

globalThis.OspreyProviderCatalog = (() => {
    const catalogValidator = globalThis.OspreyCatalogValidator;
    const directIntegrations = globalThis.OspreyDirectIntegrations || [];
    const protectionResult = globalThis.OspreyProtectionResult;
    const proxyBuiltins = globalThis.OspreyProxyBuiltins || [];

    const apiKeyPattern = /\{api_?key}/;

    const builtinsLen = proxyBuiltins.length;
    const directLen = directIntegrations.length;

    const emptyArray = Object.freeze([]);
    const allDefinitions = Array.from({length: builtinsLen + directLen});

    const byId = new Map();
    const staticAliasMap = new Map();
    const sharedApiKeyGroupMembers = new Map();

    let defIdx = 0;

    const processDefinition = definition => {
        if (!definition) {
            return;
        }

        allDefinitions[defIdx++] = definition;

        const id = definition.id;

        if (id !== undefined) {
            byId.set(id, definition);
            staticAliasMap.set(id, id);
        }

        const aliases = definition.aliases;

        if (Array.isArray(aliases)) {
            const aliasLen = aliases.length;
            for (let i = 0; i < aliasLen; i++) {
                staticAliasMap.set(aliases[i], id);
            }
        }
    };

    for (let i = 0; i < builtinsLen; i++) {
        processDefinition(proxyBuiltins[i]);
    }

    for (let i = 0; i < directLen; i++) {
        const definition = directIntegrations[i];
        processDefinition(definition);

        if (!definition) {
            continue;
        }

        const groupId = definition.sharedApiKeyGroup;

        if (groupId) {
            const strGroupId = String(groupId);
            let members = sharedApiKeyGroupMembers.get(strGroupId);

            if (!members) {
                members = [];
                sharedApiKeyGroupMembers.set(strGroupId, members);
            }

            members.push(definition.id);
        }
    }

    allDefinitions.length = defIdx;
    Object.freeze(allDefinitions);

    if (catalogValidator && typeof catalogValidator.validate === 'function') {
        catalogValidator.validate(allDefinitions);
    }

    const getAllDefinitions = () => allDefinitions;

    const getDefinition = idOrAlias => {
        if (!idOrAlias) {
            return null;
        }

        const resolvedId = staticAliasMap.get(idOrAlias);

        if (resolvedId !== undefined) {
            const definition = byId.get(resolvedId);

            if (definition !== undefined) {
                return definition;
            }
        }

        const strId = String(idOrAlias).trim();

        if (strId) {
            console.warn(`OspreyProviderCatalog could not resolve provider '${strId}'`);
        }
        return null;
    };

    const requiresApiKey = definition => {
        if (definition?.kind !== 'direct_static') {
            return false;
        }

        if (Array.isArray(definition.tags) && definition.tags.includes('api_key_required')) {
            return true;
        }

        const request = definition.request;

        if (!request) {
            return false;
        }

        const urlTpl = request.urlTemplate;

        if (urlTpl && typeof urlTpl === 'string' && apiKeyPattern.test(urlTpl)) {
            return true;
        }

        const bodyTpl = request.bodyTemplate;

        if (bodyTpl && typeof bodyTpl === 'string' && apiKeyPattern.test(bodyTpl)) {
            return true;
        }

        const headers = request.headers;

        if (Array.isArray(headers)) {
            const headersLen = headers.length;
            for (let i = 0; i < headersLen; i++) {
                const header = headers[i];

                if (header && typeof header.value === 'string' && apiKeyPattern.test(header.value)) {
                    return true;
                }
            }
        }
        return false;
    };

    const proxyEndpointUrl = definition => {
        if (definition?.kind !== 'proxy_builtin') {
            return '';
        }

        let base = definition.proxyBaseUrl || 'https://api.osprey.ac';

        if (base.endsWith('/')) {
            base = base.replace(/\/+$/, '');
        }

        let endpoint = definition.endpoint || definition.id || '';

        if (endpoint.startsWith('/')) {
            endpoint = endpoint.replace(/^\/+/, '');
        }
        return `${base}/${endpoint}`;
    };

    const supportsBlockingResult = (definition, result) => {
        if (!result) {
            return false;
        }

        const normalizedResult = String(result);
        const isBlocking = protectionResult?.blockingResults?.has(normalizedResult);
        return Boolean(isBlocking) && Array.isArray(definition?.blockingResults) && definition.blockingResults.includes(normalizedResult);
    };

    const resolveIconUrl = (definition, depth = 2) => {
        const rawIcon = definition?.icon;

        if (!rawIcon || typeof rawIcon !== 'string') {
            return '';
        }

        let value = rawIcon;

        if (value.startsWith('/')) {
            value = value.replace(/^\/+/, '');
        }

        if (depth > 0) {
            return value ? '../'.repeat(depth) + value : '';
        } else {
            return value ? '' + value : '';
        }
    };

    const getBuiltins = () => proxyBuiltins.slice();
    const getDirectIntegrations = () => directIntegrations.slice();

    const getSharedGroupMembersById = providerId => {
        const definition = getDefinition(providerId);

        if (!definition?.sharedApiKeyGroup) {
            return emptyArray;
        }
        return sharedApiKeyGroupMembers.get(String(definition.sharedApiKeyGroup)) || emptyArray;
    };

    return Object.freeze({
        getBuiltins,
        getDirectIntegrations,
        getSharedGroupMembersById,
        getAllDefinitions,
        getDefinition,
        requiresApiKey,
        proxyEndpointUrl,
        supportsBlockingResult,
        resolveIconUrl,
    });
})();
