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

globalThis.OspreyRequestBuilder = (() => {
    // Global variables
    const urlService = globalThis.OspreyUrlService;

    const templateAliases = Object.freeze({
        apiKey: ['apiKey', 'api_key'],
        lookupValue: ['lookupValue', 'lookup_value'],
    });

    const replaceTemplate = (template, values, encoded = false) => {
        let result = String(template || '');
        const format = encoded ? encodeURIComponent : String;

        for (const [key, value] of Object.entries(values)) {
            const formattedValue = format(value ?? '');
            const aliases = templateAliases[key] || [key];

            for (const alias of aliases) {
                result = result.replaceAll(`{${alias}}`, formattedValue);
            }
        }
        return result;
    };

    const buildProxyRequest = (provider, url) => ({
        url: `${provider.proxyBaseUrl}/${provider.endpoint}`,
        options: {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                url: urlService.normalizeUrl(url) || String(url)
            }),
        },
        timeoutMs: 7000,
        lookupKey: urlService.lookupValueForTarget(url, provider.lookupTarget),
    });

    const buildDirectRequest = (provider, url, apiKey = '') => {
        const parsed = url instanceof URL ? url : urlService.parseHttpUrl(url);

        if (!parsed) {
            console.warn(`OspreyRequestBuilder rejected an invalid direct request URL for provider '${provider?.id || 'unknown'}'`);
            throw new Error('Invalid URL for direct request');
        }

        const request = provider.request || {};

        const values = {
            url: urlService.normalizeUrl(parsed) || parsed.toString(),
            hostname: parsed.hostname,
            lookupValue: urlService.lookupValueForTarget(parsed, provider.lookupTarget || 'url'),
            apiKey
        };

        const headers = Object.fromEntries(
            (request.headers || [])
                .filter((header) => header?.name)
                .map((header) => [header.name, replaceTemplate(header.value, values)])
        );

        const method = String(request.method || 'GET').toUpperCase() === 'POST' ? 'POST' : 'GET';

        if (!headers['Content-Type'] && method === 'POST') {
            headers['Content-Type'] = request.contentType || 'application/json';
        }

        return {
            url: replaceTemplate(request.urlTemplate, values, true),
            options: {
                method,
                headers,
                body: method === 'POST' ? replaceTemplate(request.bodyTemplate, values) : undefined,
            },
            timeoutMs: Number(request.timeoutMs) > 0 ? Number(request.timeoutMs) : 7000,
            lookupKey: values.lookupValue,
        };
    };

    const buildRequest = (provider, url, providerState = {}) => (
        provider.kind === 'proxy_builtin' ?
            buildProxyRequest(provider, url) :
            buildDirectRequest(provider, url, providerState.apiKey || '')
    );

    // Public API
    return Object.freeze({
        buildRequest,
    });
})();
