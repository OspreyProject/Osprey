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

globalThis.OspreyResponseRuleEngine = (() => {
    const defaultResult = 'ALLOWED';

    const numberOperators = {
        greater_than: (actual, expected) => Number(actual) > Number(expected),
        less_than: (actual, expected) => Number(actual) < Number(expected),
        greater_or_equal: (actual, expected) => Number(actual) >= Number(expected),
        less_or_equal: (actual, expected) => Number(actual) <= Number(expected),
    };

    const directOperators = {
        exists: actual => actual !== undefined,
        not_exists: actual => actual === undefined,
        truthy: Boolean,
        falsy: actual => !actual,
        equals: (actual, expected) => actual === expected,
        not_equals: (actual, expected) => actual !== expected,
        contains: (actual, expected) => Array.isArray(actual) ? actual.includes(expected) :
            String(actual ?? '').includes(String(expected ?? '')),
    };

    const logicOperatorMap = Object.freeze({
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
    });

    const unaryOperators = new Set(['exists', 'not_exists', 'truthy', 'falsy']);

    const tokenize = path => String(path || '')
        .replaceAll(/\[(\d+)]/g, '.$1')
        .split('.')
        .map(token => token.trim())
        .filter(Boolean);

    const getPathValue = (root, path) => {
        let current = root;

        for (const token of tokenize(path)) {
            if (current === null || current === undefined) {
                return undefined;
            }

            current = current[token];
        }
        return current;
    };

    const compare = (actual, operator, expected) => {
        const compareValue = directOperators[operator] || numberOperators[operator];

        if (compareValue) {
            return compareValue(actual, expected);
        }

        if (operator === 'regex') {
            try {
                return new RegExp(String(expected || '')).test(String(actual ?? ''));
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

    const parseConditionExpression = condition => {
        const source = String(condition || '').trim();

        if (!source) {
            return null;
        }

        const simpleMatch = !source.includes('&&') && !source.includes('||') ? /^response\.([A-Za-z0-9_.[\]-]+)\s*(===|!==|>|<|>=|<=|contains|exists|not_exists|truthy|falsy)\s*(.*)$/.exec(source) : null;

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

    const evaluateRules = (responseBody, rules) => {
        if (!Array.isArray(rules) || rules.length === 0) {
            return defaultResult;
        }

        for (const [index, rule] of rules.entries()) {
            if (!rule || typeof rule !== 'object') {
                console.warn(`OspreyResponseRuleEngine skipped invalid rule at index ${index}`);
                continue;
            }

            if (typeof rule.condition === 'string' && rule.condition.trim()) {
                const expression = parseConditionExpression(rule.condition);

                if (!expression) {
                    console.warn(`OspreyResponseRuleEngine skipped invalid condition rule at index ${index}`);
                    continue;
                }

                if (evaluateConditionExpression(responseBody, expression)) {
                    return String(rule.result || defaultResult).toUpperCase();
                }
                continue;
            }

            if (compare(getPathValue(responseBody, rule.path), String(rule.operator || 'equals'), rule.value)) {
                return String(rule.result || defaultResult).toUpperCase();
            }
        }
        return defaultResult;
    };

    // Public API
    return Object.freeze({
        evaluateRules,
    });
})();
