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

globalThis.OspreyResponseRuleEngine = (() => {
    const defaultResult = 'ALLOWED';
    const maxCacheSize = 5000;

    const operators = Object.freeze(Object.assign(Object.create(null), {
        greater_than: (actual, expected) => Number(actual) > Number(expected),
        less_than: (actual, expected) => Number(actual) < Number(expected),
        greater_or_equal: (actual, expected) => Number(actual) >= Number(expected),
        less_or_equal: (actual, expected) => Number(actual) <= Number(expected),
        exists: actual => actual !== undefined,
        not_exists: actual => actual === undefined,
        truthy: Boolean,
        falsy: actual => !actual,
        equals: (actual, expected) => actual === expected,
        not_equals: (actual, expected) => actual !== expected,
        contains: (actual, expected) => {
            if (Array.isArray(actual)) {
                return actual.includes(expected);
            }
            return String(actual ?? '').includes(String(expected ?? ''));
        },
    }));

    const logicOperatorMap = Object.freeze(Object.assign(Object.create(null), {
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
    }));

    const unaryOperators = new Set(['exists', 'not_exists', 'truthy', 'falsy']);

    const pathCache = new Map();
    const astCache = new Map();
    const regexCache = new Map();

    const lruGet = (cache, key) => {
        const item = cache.get(key);

        if (item !== undefined) {
            cache.delete(key);
            cache.set(key, item);
        }
        return item;
    };

    const lruSet = (cache, key, value) => {
        if (cache.size >= maxCacheSize) {
            cache.delete(cache.keys().next().value);
        }

        cache.set(key, value);
    };

    const regexWhitespace = /\s+/y;
    const regexLogical = /&&|\|\|/y;
    const regexParenthesis = /[()]/y;
    const regexQuoted = /"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'/y;
    const regexResponsePath = /response\.([A-Za-z0-9_.[\]-]+)/y;
    const regexOperator = /(===|!==|>=|<=|>|<|contains\b|exists\b|not_exists\b|truthy\b|falsy\b)/y;
    const regexBare = /(true|false|null|-?\d+(?:\.\d+)?|[A-Za-z0-9_./:-]+)/y;
    const regexSimpleMatch = /^response\.([A-Za-z0-9_.[\]-]+)\s*(===|!==|>=|<=|>|<|contains|exists|not_exists|truthy|falsy)\s*(.*)$/;

    const getPathTokens = path => {
        let tokens = lruGet(pathCache, path);

        if (tokens) {
            return tokens;
        }

        tokens = [];
        const str = String(path || '');
        let start = 0;
        const len = str.length;

        for (let i = 0; i < len; i++) {
            const char = str[i];

            if (char === '[' || char === ']' || char === '.') {
                if (i > start) {
                    const token = str.slice(start, i).trim();

                    if (token) {
                        tokens.push(token);
                    }
                }

                start = i + 1;
            }
        }

        if (start < len) {
            const token = str.slice(start).trim();

            if (token) {
                tokens.push(token);
            }
        }

        lruSet(pathCache, path, tokens);
        return tokens;
    };

    const getPathValue = (root, path) => {
        const tokens = getPathTokens(path);
        let current = root;
        const len = tokens.length;

        for (let i = 0; i < len; i++) {
            if (current === null || current === undefined) {
                return undefined;
            }

            const key = tokens[i];

            if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
                return undefined;
            }

            current = current[key];
        }
        return current;
    };

    const compare = (actual, operator, expected) => {
        const compareFn = operators[operator];

        if (typeof compareFn === 'function') {
            return compareFn(actual, expected);
        }

        if (operator === 'regex') {
            try {
                let rx = lruGet(regexCache, expected);

                if (!rx) {
                    rx = new RegExp(String(expected || ''));
                    lruSet(regexCache, expected, rx);
                }
                return rx.test(String(actual ?? ''));
            } catch (error) {
                console.warn(`OspreyResponseRuleEngine rejected regex '${expected}'`, error);
            }
            return false;
        }

        console.warn(`OspreyResponseRuleEngine received unsupported operator '${operator}'`);
        return false;
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

        if (value.startsWith('"') && value.endsWith('"') || value.startsWith("'") && value.endsWith("'")) {
            return value.slice(1, -1);
        }
        return value;
    };

    const tokenizeLogicExpression = condition => {
        const tokens = [];
        const source = String(condition || '').trim();
        let index = 0;

        while (index < source.length) {
            let match;

            regexWhitespace.lastIndex = index;
            match = regexWhitespace.exec(source);

            if (match) {
                index = regexWhitespace.lastIndex;
                continue;
            }

            regexLogical.lastIndex = index;
            match = regexLogical.exec(source);

            if (match) {
                tokens.push({type: match[0]});
                index = regexLogical.lastIndex;
                continue;
            }

            regexParenthesis.lastIndex = index;
            match = regexParenthesis.exec(source);

            if (match) {
                tokens.push({type: match[0]});
                index = regexParenthesis.lastIndex;
                continue;
            }

            regexQuoted.lastIndex = index;
            match = regexQuoted.exec(source);

            if (match) {
                tokens.push({type: 'literal', value: match[0]});
                index = regexQuoted.lastIndex;
                continue;
            }

            regexResponsePath.lastIndex = index;
            match = regexResponsePath.exec(source);

            if (match) {
                tokens.push({type: 'path', value: match[1]});
                index = regexResponsePath.lastIndex;
                continue;
            }

            regexOperator.lastIndex = index;
            match = regexOperator.exec(source);

            if (match) {
                tokens.push({type: 'operator', value: match[1]});
                index = regexOperator.lastIndex;
                continue;
            }

            regexBare.lastIndex = index;
            match = regexBare.exec(source);

            if (match) {
                tokens.push({type: 'literal', value: match[1]});
                index = regexBare.lastIndex;
                continue;
            }
            throw new Error(`Unexpected token near '${source.slice(index, index + 16)}'`);
        }
        return tokens;
    };

    const parseConditionExpression = condition => {
        const source = String(condition || '').trim();

        if (!source) {
            return null;
        }

        if (!source.includes('&&') && !source.includes('||')) {
            const simpleMatch = regexSimpleMatch.exec(source);

            if (simpleMatch) {
                const [, path, operatorToken, rawValue] = simpleMatch;

                if (unaryOperators.has(operatorToken)) {
                    return {
                        type: 'condition',
                        path,
                        operator: logicOperatorMap[operatorToken],
                    };
                }

                if (!String(rawValue || '').trim()) {
                    return null;
                }

                return {
                    type: 'condition',
                    path,
                    operator: logicOperatorMap[operatorToken] || 'equals',
                    value: parseConditionValue(rawValue),
                };
            }
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
                    operator: logicOperatorMap[operatorToken.value],
                };
            }

            const valueToken = consume('literal');

            if (!valueToken) {
                return null;
            }

            return {
                type: 'condition',
                path: pathToken.value,
                operator: logicOperatorMap[operatorToken.value] || 'equals',
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
        return expression && index === tokens.length ? expression : null;
    };

    const getConditionAST = condition => {
        let ast = lruGet(astCache, condition);

        if (ast !== undefined) {
            return ast;
        }

        try {
            ast = parseConditionExpression(condition);
        } catch (error) {
            console.warn(`OspreyResponseRuleEngine failed to parse condition '${condition}'`, error);
            ast = null;
        }

        lruSet(astCache, condition, ast);
        return ast;
    };

    const evaluateConditionExpression = (responseBody, expression) => {
        if (!expression || typeof expression !== 'object') {
            return false;
        }

        if (expression.type === 'and') {
            return evaluateConditionExpression(responseBody, expression.left) &&
                evaluateConditionExpression(responseBody, expression.right);
        }

        if (expression.type === 'or') {
            return evaluateConditionExpression(responseBody, expression.left) ||
                evaluateConditionExpression(responseBody, expression.right);
        }

        if (expression.type === 'condition') {
            return compare(getPathValue(responseBody, expression.path), String(expression.operator || 'equals'), expression.value);
        }
        return false;
    };

    const resolveResult = rule => String(rule.result || defaultResult).toUpperCase();

    const evaluateRules = (responseBody, rules) => {
        if (!Array.isArray(rules) || rules.length === 0) {
            return defaultResult;
        }

        const len = rules.length;

        for (let i = 0; i < len; i++) {
            const rule = rules[i];

            if (!rule || typeof rule !== 'object') {
                console.warn(`OspreyResponseRuleEngine skipped invalid rule at index ${i}`);
                continue;
            }

            if (typeof rule.condition === 'string' && rule.condition.trim()) {
                const expression = getConditionAST(rule.condition);

                if (!expression) {
                    console.warn(`OspreyResponseRuleEngine skipped invalid condition rule at index ${i}`);
                    continue;
                }

                if (evaluateConditionExpression(responseBody, expression)) {
                    return resolveResult(rule);
                }
                continue;
            }

            if (compare(getPathValue(responseBody, rule.path), String(rule.operator || 'equals'), rule.value)) {
                return resolveResult(rule);
            }
        }
        return defaultResult;
    };

    return Object.freeze({
        evaluateRules,
    });
})();
