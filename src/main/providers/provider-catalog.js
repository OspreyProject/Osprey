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

    // Runtime custom providers supplied by a remote configuration document
    // (see policy-service). Kept separate from the static catalog above so the
    // built-in set is never mutated, and rebuilt wholesale by setCustomDefinitions.
    const customById = new Map();
    const customAliasMap = new Map();
    let customDefinitions = [];

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

    let combinedDefinitions = allDefinitions;

    const setCustomDefinitions = definitions => {
        customById.clear();
        customAliasMap.clear();

        const accepted = [];
        const candidates = Array.isArray(definitions) ? definitions : [];

        for (const definition of candidates) {
            if (!definition || typeof definition !== 'object' || !definition.id) {
                continue;
            }

            if (byId.has(definition.id) || staticAliasMap.has(definition.id) || customById.has(definition.id)) {
                console.warn(`OspreyProviderCatalog ignoring custom provider with conflicting id '${definition.id}'`);
                continue;
            }

            customById.set(definition.id, definition);
            customAliasMap.set(definition.id, definition.id);

            if (Array.isArray(definition.aliases)) {
                for (const alias of definition.aliases) {
                    if (alias && !staticAliasMap.has(alias) && !customAliasMap.has(alias)) {
                        customAliasMap.set(alias, definition.id);
                    }
                }
            }

            accepted.push(definition);
        }

        customDefinitions = accepted;
        combinedDefinitions = accepted.length > 0 ? Object.freeze(allDefinitions.concat(accepted)) : allDefinitions;
        return accepted.length;
    };

    const isCustomProvider = idOrAlias => {
        if (!idOrAlias) {
            return false;
        }
        return customById.has(idOrAlias) || customAliasMap.has(idOrAlias);
    };

    const getAllDefinitions = () => combinedDefinitions;
    const getCustomDefinitions = () => customDefinitions.slice();

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

        const customResolvedId = customAliasMap.get(idOrAlias);

        if (customResolvedId !== undefined) {
            const definition = customById.get(customResolvedId);

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

        let base = definition.proxyBaseUrl || globalThis.OspreyDefaultProxyBaseUrl || 'https://api.osprey.ac';

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

        if (!protectionResult?.blockingResults?.has(normalizedResult)) {
            return false;
        }

        if (Array.isArray(definition?.blockingResults)) {
            return definition.blockingResults.includes(normalizedResult);
        }
        return Boolean(definition);
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
        getCustomDefinitions,
        setCustomDefinitions,
        isCustomProvider,
        getDefinition,
        requiresApiKey,
        proxyEndpointUrl,
        supportsBlockingResult,
        resolveIconUrl,
    });
})();
