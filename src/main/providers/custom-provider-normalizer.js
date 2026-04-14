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

globalThis.OspreyCustomProviderNormalizer = (() => {
    // Global variables
    const catalogValidator = globalThis.OspreyCatalogValidator;

    const getFormHelpers = () => globalThis.OspreyFormHelpers || null;

    const logicConditionPattern = /^response\.([A-Za-z0-9_.[\]-]+)\s*(===|!==|>|<|>=|<=|contains|exists|not_exists|truthy|falsy)\s*(.*)$/;

    const logicOperators = {
        '===': 'equals',
        '!==': 'not_equals',
        '>': 'greater_than',
        '<': 'less_than',
        '>=': 'greater_or_equal',
        '<=': 'less_or_equal',
        contains: 'contains',
        exists: 'exists',
        not_exists: 'not_exists',
        truthy: 'truthy',
        falsy: 'falsy',
    };

    const unaryOperators = new Set(['exists', 'not_exists', 'truthy', 'falsy']);

    const coerceString = (value, fallback = '') => typeof value === 'string' ? value : fallback;

    const coerceNumber = (value, fallback, min = null, max = null) => {
        const num = Number(value);
        return Number.isFinite(num) && (min === null || num >= min) && (max === null || num <= max) ? num : fallback;
    };

    const normalizeHeader = (name, value) => {
        const trimmedName = coerceString(name).trim();
        return trimmedName ? {
            name: trimmedName,
            value: coerceString(value).trim()
        } : null;
    };

    const parseHeaderLines = value => {
        if (Array.isArray(value)) {
            return value.map(item => normalizeHeader(item?.name, item?.value)).filter(Boolean);
        }

        return typeof value === 'string' ? value.split(/\r?\n/).map(line => {
            const separatorIndex = line.indexOf(':');
            return separatorIndex > 0 ? normalizeHeader(line.slice(0, separatorIndex), line.slice(separatorIndex + 1)) : null;
        }).filter(Boolean) : [];
    };

    const parseConditionValue = rawValue => {
        const value = String(rawValue || '').trim();

        if (value === 'true' || value === 'false') {
            return value === 'true';
        }

        if (value === 'null') {
            return null;
        }

        if (/^-?\d+(?:\.\d+)?$/.test(value)) {
            return Number(value);
        }

        if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
            return value.slice(1, -1);
        }
        return value;
    };

    const tokenizeLogicExpression = condition => {
        const tokens = [];
        const source = String(condition || '').trim();
        let index = 0;

        while (index < source.length) {
            const remaining = source.slice(index);
            const whitespace = /^\s+/.exec(remaining);

            if (whitespace) {
                index += whitespace[0].length;
                continue;
            }

            if (remaining.startsWith('&&') || remaining.startsWith('||')) {
                tokens.push({type: remaining.slice(0, 2)});
                index += 2;
                continue;
            }

            if (remaining[0] === '(' || remaining[0] === ')') {
                tokens.push({type: remaining[0]});
                index += 1;
                continue;
            }

            const quoted = /^("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')/.exec(remaining);

            if (quoted) {
                tokens.push({type: 'literal', value: quoted[0]});
                index += quoted[0].length;
                continue;
            }

            const responsePath = /^response\.[A-Za-z0-9_.[\]-]+/.exec(remaining);

            if (responsePath) {
                tokens.push({type: 'path', value: responsePath[0].slice('response.'.length)});
                index += responsePath[0].length;
                continue;
            }

            const operator = /^(===|!==|>=|<=|>|<|contains\b|exists\b|not_exists\b|truthy\b|falsy\b)/.exec(remaining);

            if (operator) {
                tokens.push({type: 'operator', value: operator[1]});
                index += operator[1].length;
                continue;
            }

            const bare = /^(true|false|null|-?\d+(?:\.\d+)?|[A-Za-z0-9_./:-]+)/.exec(remaining);

            if (bare) {
                tokens.push({type: 'literal', value: bare[1]});
                index += bare[1].length;
                continue;
            }

            throw new Error(`Unexpected token near '${remaining.slice(0, 16)}'`);
        }
        return tokens;
    };

    const parseLogicCondition = condition => {
        const source = String(condition || '').trim();

        if (!source) {
            return null;
        }

        const simpleMatch = !source.includes('&&') && !source.includes('||') ? logicConditionPattern.exec(source) : null;

        if (simpleMatch) {
            const [, path, operatorToken, rawValue] = simpleMatch;
            const normalizedOperator = logicOperators[operatorToken] || 'equals';

            if (unaryOperators.has(operatorToken)) {
                return {
                    path,
                    operator: normalizedOperator,
                };
            }

            if (!String(rawValue || '').trim()) {
                return null;
            }

            return {
                path,
                operator: normalizedOperator,
                value: parseConditionValue(rawValue),
            };
        }

        const tokens = tokenizeLogicExpression(source);
        let index = 0;

        const peek = () => tokens[index] || null;
        const consume = expectedType => {
            const token = peek();

            if (!token || token.type !== expectedType) {
                return null;
            }

            index += 1;
            return token;
        };

        const parsePrimary = () => {
            if (peek()?.type === '(') {
                consume('(');
                const expr = parseOrExpression();

                if (!consume(')')) {
                    return null;
                }
                return expr;
            }

            const pathToken = consume('path');
            const operatorToken = consume('operator');

            if (!pathToken || !operatorToken) {
                return null;
            }

            if (unaryOperators.has(operatorToken.value)) {
                return {
                    type: 'condition',
                    path: pathToken.value,
                    operator: logicOperators[operatorToken.value],
                };
            }

            const valueToken = consume('literal');

            if (!valueToken) {
                return null;
            }

            return {
                type: 'condition',
                path: pathToken.value,
                operator: logicOperators[operatorToken.value] || 'equals',
                value: parseConditionValue(valueToken.value),
            };
        };

        const parseAndExpression = () => {
            let left = parsePrimary();

            if (!left) {
                return null;
            }

            while (peek()?.type === '&&') {
                consume('&&');
                const right = parsePrimary();

                if (!right) {
                    return null;
                }
                left = {type: 'and', left, right};
            }
            return left;
        };

        const parseOrExpression = () => {
            let left = parseAndExpression();

            if (!left) {
                return null;
            }

            while (peek()?.type === '||') {
                consume('||');
                const right = parseAndExpression();

                if (!right) {
                    return null;
                }
                left = {type: 'or', left, right};
            }
            return left;
        };

        const expression = parseOrExpression();
        return expression && index === tokens.length ? {
            condition: source,
            expression,
        } : null;
    };

    const normalizeRule = rule => {
        if (!rule || typeof rule !== 'object') {
            return null;
        }

        const result = typeof rule.result === 'string' ? rule.result : rule.resultType;

        if (typeof result !== 'string') {
            return null;
        }

        if (typeof rule.condition === 'string' && rule.condition.trim()) {
            const parsedCondition = parseLogicCondition(rule.condition);

            if (!parsedCondition) {
                return null;
            }

            if (parsedCondition.condition) {
                return {
                    condition: parsedCondition.condition,
                    result: result.trim().toUpperCase(),
                };
            }

            return {
                path: parsedCondition.path,
                operator: parsedCondition.operator,
                value: parsedCondition.value,
                result: result.trim().toUpperCase(),
            };
        }

        if (typeof rule.path === 'string' && typeof rule.operator === 'string') {
            return {
                path: rule.path.trim(),
                operator: rule.operator.trim(),
                value: rule.value,
                result: result.trim().toUpperCase(),
            };
        }

        return null;
    };

    const normalizeId = rawId => {
        const value = String(rawId || '').trim();

        if (/^custom-[a-z0-9-]+$/.test(value)) {
            return value;
        }

        if (/^custom_[a-z0-9]+$/i.test(value)) {
            return `custom-${value.slice(7).replaceAll(/[^a-z0-9-]/gi, '-').toLowerCase()}`;
        }
        return `custom-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`;
    };

    const normalize = raw => {
        if (!raw || typeof raw !== 'object') {
            return null;
        }

        const id = normalizeId(raw.id);
        const request = raw.request || {};
        const responseRules = raw.responseRules || raw.logicBlocks;
        const lookupTarget = raw.lookupTarget === 'hostname' ||
        String(raw.apiUrl || '').includes('{url}') ||
        String(raw.requestBody || '').includes('{url}') ? 'url' : 'hostname';

        let tags = [];

        if (Array.isArray(raw.tags)) {
            tags = raw.tags.filter(Boolean);
        } else if (lookupTarget === 'hostname') {
            tags = ['hostname_only'];
        }

        return {
            id,
            aliases: [String(raw.id || '')].filter(Boolean),
            displayName: coerceString(raw.displayName || raw.name || id, id),
            lookupTarget,
            tags,
            report: raw.report && typeof raw.report === 'object' ? raw.report : {type: 'none'},
            request: {
                urlTemplate: coerceString(request.urlTemplate || raw.apiUrl),
                method: coerceString(request.method || raw.method || 'GET').toUpperCase() === 'POST' ? 'POST' : 'GET',
                headers: parseHeaderLines(request.headers || raw.requestHeaders),
                bodyTemplate: coerceString(request.bodyTemplate || raw.requestBody),
                contentType: coerceString(request.contentType || 'application/json', 'application/json'),
                timeoutMs: coerceNumber(request.timeoutMs, 7000, 1000, 30000),
            },
            responseRules: Array.isArray(responseRules) ? responseRules.map(normalizeRule).filter(Boolean) : [],
        };
    };

    const validate = definition => {
        if (!definition || typeof definition !== 'object') {
            throw new Error('Custom provider definition is required');
        }

        if (typeof definition.displayName !== 'string' || !definition.displayName.trim()) {
            throw new Error('Custom provider name is required');
        }

        if (!['url', 'hostname'].includes(definition.lookupTarget)) {
            throw new Error('Custom provider lookup target must be url or hostname');
        }

        const request = definition.request || {};

        if (typeof request.urlTemplate !== 'string' || !request.urlTemplate.trim()) {
            throw new Error('Custom provider endpoint URL is required');
        }

        let parsedRequestUrl;

        try {
            parsedRequestUrl = new URL(request.urlTemplate
                .replaceAll('{lookupValue}', 'example.test')
                .replaceAll('{hostname}', 'example.test')
                .replaceAll('{url}', 'https://example.test')
                .replaceAll('{apiKey}', 'sample')
                .replaceAll('{api_key}', 'sample'));
        } catch {
            throw new Error('Custom provider endpoint URL is invalid');
        }

        if (parsedRequestUrl.protocol !== 'https:') {
            throw new Error('Custom providers must use HTTPS endpoints');
        }

        if (!/\{(?:lookupValue|hostname|url)}/.test([
            request.urlTemplate,
            request.bodyTemplate,
            ...(request.headers || []).map(header => header?.value || ''),
        ].join('\n'))) {
            throw new Error('Custom provider must reference {lookupValue}, {hostname}, or {url}');
        }

        for (const rule of definition.responseRules) {
            if (!rule || typeof rule !== 'object') {
                throw new Error('Custom provider response rules must be objects');
            }

            if (typeof rule.condition === 'string' && rule.condition.trim()) {
                if (!parseLogicCondition(rule.condition)) {
                    throw new Error('Custom provider response rule condition is invalid');
                }
            } else {
                if (typeof rule.path !== 'string' || !rule.path.trim()) {
                    throw new Error('Custom provider response rule path is required');
                }

                if (!catalogValidator.validRuleOperators.includes(String(rule.operator || 'equals'))) {
                    throw new Error(`Unsupported response rule operator: ${rule.operator}`);
                }
            }

            const formHelpers = getFormHelpers();
            const allResultTypes = Array.isArray(formHelpers?.allResultTypes) ? formHelpers.allResultTypes : [
                'MALICIOUS', 'PHISHING', 'ADULT_CONTENT', 'ALLOWED', 'KNOWN_SAFE'
            ];

            if (!allResultTypes.includes(String(rule.result || '').toUpperCase())) {
                throw new Error(`Unsupported response rule result: ${rule.result}`);
            }
        }
    };

    const generateId = () => normalizeId('');

    // Public API
    return Object.freeze({
        normalize,
        validate,
        generateId
    });
})();
