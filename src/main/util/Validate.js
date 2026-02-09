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

/**
 * Custom error class for validation failures.
 * Can be caught to handle validation errors gracefully.
 */
class ValidationError extends Error {
    constructor(message) {
        super(message);
        this.name = 'ValidationError';
    }
}

/**
 * Utility class for validation, similar to Apache Commons Validate.
 * Provides static methods for common validation patterns used throughout the extension.
 *
 * Use "is*" and "has*" methods to check values (return boolean).
 * Use "require*" methods to assert values (throw ValidationError on failure).
 */
const Validate = (() => {

    // ==================== CHECK METHODS (return boolean) ====================

    /**
     * Checks if the value is a valid integer.
     *
     * @param {*} value - The value to check.
     * @returns {boolean} - True if valid integer, false otherwise.
     */
    const isInteger = value => {
        return typeof value === 'number' && Number.isInteger(value) && !Number.isNaN(value) ||
            typeof value === 'string' && value.trim() !== '' && Number.isInteger(Number(value)) && !Number.isNaN(Number(value));
    };

    /**
     * Checks if the value is a non-negative integer.
     *
     * @param {*} value - The value to check.
     * @returns {boolean} - True if non-negative integer, false otherwise.
     */
    const isNonNegativeInteger = value => {
        return isInteger(value) && value >= 0;
    };

    /**
     * Checks if the value is a positive integer.
     *
     * @param {*} value - The value to check.
     * @returns {boolean} - True if positive integer, false otherwise.
     */
    const isPositiveInteger = value => {
        return isInteger(value) && value > 0;
    };

    /**
     * Checks if the value is a non-blank string.
     *
     * @param {*} value - The value to check.
     * @returns {boolean} - True if non-blank string, false otherwise.
     */
    const isNotBlank = value => {
        return typeof value === 'string' && value.trim().length > 0;
    };

    /**
     * Checks if the value is a non-empty string (may contain only whitespace).
     *
     * @param {*} value - The value to check.
     * @returns {boolean} - True if non-empty string, false otherwise.
     */
    const isNotEmpty = value => {
        return typeof value === 'string' && value.length > 0;
    };

    /**
     * Checks if an object has a property with a non-nullish value.
     *
     * @param {object} obj - The object to check.
     * @param {string} key - The property key to check.
     * @returns {boolean} - True if property exists and is not null/undefined, false otherwise.
     */
    const hasProperty = (obj, key) => {
        return obj !== null && Object.hasOwn(obj, key) && obj[key] !== null;
    };

    /**
     * Checks if an object has a property with a non-blank string value.
     *
     * @param {object} obj - The object to check.
     * @param {string} key - The property key to check.
     * @returns {boolean} - True if property exists and is a non-blank string, false otherwise.
     */
    const hasStringProperty = (obj, key) => {
        return hasProperty(obj, key) && isNotBlank(obj[key]);
    };

    /**
     * Attempts to parse a value as a valid origin number.
     * Handles both string and number inputs.
     *
     * @param {*} value - The value to parse.
     * @returns {{valid: boolean, value: number}} - Object with valid flag and parsed value.
     */
    const parseOriginValue = value => {
        if (isInteger(value)) {
            return {valid: true, value: value};
        }

        if (typeof value === 'string') {
            const parsed = Number(value);

            if (isInteger(parsed)) {
                return {valid: true, value: parsed};
            }
        }
        return {valid: false, value: Number.NaN};
    };

    /**
     * Checks if the origin value is valid according to ProtectionResult.Origin.
     * Note: Requires ProtectionResult to be loaded.
     *
     * @param {number} originValue - The origin value to validate.
     * @param {object} originEnum - The ProtectionResult.Origin enum object.
     * @returns {boolean} - True if valid origin, false otherwise.
     */
    const isValidOrigin = (originValue, originEnum) => {
        // Makes sure the originValue is a valid number and exists in the enum values
        if (!isInteger(originValue)) {
            return false;
        }

        // Converts a potential string originValue to a number for comparison
        const parsedOrigin = Number(originValue);
        return Object.values(originEnum).includes(parsedOrigin);
    };

    /**
     * Checks if a URL string is valid and can be parsed into a URL object.
     *
     * @param {string} urlString - The URL string to parse.
     * @returns {{valid: boolean, url: URL|null, error: string|null}} - Parse result object.
     */
    const parseUrl = urlString => {
        if (!isNotBlank(urlString)) {
            return {valid: false, url: null, error: 'URL string is blank'};
        }

        try {
            const url = new URL(urlString);
            return {valid: true, url: url, error: null};
        } catch (error) {
            return {valid: false, url: null, error: error.message};
        }
    };

    /**
     * Checks if a URL has a valid HTTP or HTTPS protocol.
     *
     * @param {URL} urlObject - The URL object to check.
     * @param {Set<string>} validProtocols - Set of valid protocol strings (e.g., 'http:', 'https:').
     * @returns {boolean} - True if protocol is valid, false otherwise.
     */
    const hasValidProtocol = (urlObject, validProtocols) => {
        if (!urlObject || typeof urlObject.protocol !== 'string') {
            return false;
        }
        return validProtocols.has(urlObject.protocol.toLowerCase());
    };

    /**
     * Validates that a URL string parses correctly and has a valid HTTP(S) protocol.
     *
     * @param {string} urlString - The URL string to validate.
     * @param {Set<string>} validProtocols - Set of valid protocol strings.
     * @returns {{valid: boolean, url: URL|null, error: string|null}} - Validation result object.
     */
    const validateHttpUrl = (urlString, validProtocols) => {
        const parseResult = parseUrl(urlString);

        if (!parseResult.valid) {
            return parseResult;
        }

        if (!hasValidProtocol(parseResult.url, validProtocols)) {
            return {
                valid: false,
                url: parseResult.url,
                error: `Invalid protocol: ${parseResult.url.protocol}`
            };
        }
        return parseResult;
    };

    /**
     * Checks if all specified properties exist and are non-blank strings in an object.
     *
     * @param {object} obj - The object to check.
     * @param {string[]} keys - Array of property keys to check.
     * @returns {boolean} - True if all properties exist and are non-blank strings, false otherwise.
     */
    const hasAllStringProperties = (obj, keys) => {
        return keys.every(key => hasStringProperty(obj, key));
    };

    /**
     * Checks if a value is null or undefined.
     *
     * @param {*} value - The value to check.
     * @returns {boolean} - True if null or undefined, false otherwise.
     */
    const isNullish = value => {
        return value === null || value === undefined || !value;
    };

    /**
     * Checks if a value is not null and not undefined.
     *
     * @param {*} value - The value to check.
     * @returns {boolean} - True if not null/undefined, false otherwise.
     */
    const isNotNull = value => {
        return !isNullish(value);
    };

    /**
     * Checks if a value is an array with at least one element.
     *
     * @param {*} value - The value to check.
     * @returns {boolean} - True if non-empty array, false otherwise.
     */
    const isNonEmptyArray = value => {
        return Array.isArray(value) && value.length > 0;
    };

    /**
     * Checks if a value is a boolean.
     *
     * @param {*} value - The value to check.
     * @returns {boolean} - True if boolean, false otherwise.
     */
    const isBoolean = value => {
        return typeof value === 'boolean';
    };

    /**
     * Checks if a value is a function.
     *
     * @param {*} value - The value to check.
     * @returns {boolean} - True if function, false otherwise.
     */
    const isFunction = value => {
        return typeof value === 'function';
    };

    /**
     * Checks if a value is a plain object (not null, not array).
     *
     * @param {*} value - The value to check.
     * @returns {boolean} - True if plain object, false otherwise.
     */
    const isPlainObject = value => {
        return typeof value === 'object' && value !== null && !Array.isArray(value);
    };

    // ==================== ASSERTION METHODS (throw ValidationError on failure) ====================

    /**
     * Requires value to be a non-negative integer, throws ValidationError otherwise.
     *
     * @param {*} value - The value to check.
     * @param {string} [message] - Custom error message.
     * @returns {number} - The validated value.
     * @throws {ValidationError} - If validation fails.
     */
    const requireNonNegativeInteger = (value, message) => {
        if (!isNonNegativeInteger(value)) {
            const msg = message || `Value must be a non-negative integer, got: ${value}`;
            console.warn(msg);
            throw new ValidationError(msg);
        }
        return value;
    };

    /**
     * Requires value to be an integer, throws ValidationError otherwise.
     *
     * @param {*} value - The value to check.
     * @param {string} [message] - Custom error message.
     * @returns {number} - The validated value.
     * @throws {ValidationError} - If validation fails.
     */
    const requireInteger = (value, message) => {
        if (!isInteger(value)) {
            const msg = message || `Value must be an integer, got: ${value}`;
            console.warn(msg);
            throw new ValidationError(msg);
        }
        return value;
    };

    /**
     * Requires value to be a string, throws ValidationError otherwise.
     *
     * @param {*} value - The value to check.
     * @param {string} [message] - Custom error message.
     * @returns {string} - The validated value.
     * @throws {ValidationError} - If validation fails.
     */
    const requireString = (value, message) => {
        if (typeof value !== 'string') {
            const msg = message || `Value must be a string, got: ${value}`;
            console.warn(msg);
            throw new ValidationError(msg);
        }
        return value;
    };

    const requireArray = (value, message) => {
        if (!Array.isArray(value)) {
            const msg = message || `Value must be an array, got: ${value}`;
            console.warn(msg);
            throw new ValidationError(msg);
        }
        return value;
    };

    /**
     * Requires value to be a boolean, throws ValidationError otherwise.
     *
     * @param {*} value - The value to check.
     * @param {string} [message] - Custom error message.
     * @returns {boolean} - The validated value.
     * @throws {ValidationError} - If validation fails.
     */
    const requireBoolean = (value, message) => {
        if (!isBoolean(value)) {
            const msg = message || `Value must be a boolean, got: ${value}`;
            console.warn(msg);
            throw new ValidationError(msg);
        }
        return value;
    };

    /**
     * Requires value to be a non-blank string, throws ValidationError otherwise.
     *
     * @param {*} value - The value to check.
     * @param {string} [message] - Custom error message.
     * @returns {string} - The validated value.
     * @throws {ValidationError} - If validation fails.
     */
    const requireNotBlank = (value, message) => {
        if (!isNotBlank(value)) {
            const msg = message || `Value must be a non-blank string, got: ${value}`;
            console.warn(msg);
            throw new ValidationError(msg);
        }
        return value;
    };

    /**
     * Requires value to be non-null/undefined, throws ValidationError otherwise.
     *
     * @param {*} value - The value to check.
     * @param {string} [message] - Custom error message.
     * @returns {*} - The validated value.
     * @throws {ValidationError} - If validation fails.
     */
    const requireNotNull = (value, message) => {
        if (isNullish(value)) {
            const msg = message || `Value must not be null or undefined`;
            console.warn(msg);
            throw new ValidationError(msg);
        }
        return value;
    };

    /**
     * Requires value to be an object, throws ValidationError otherwise.
     *
     * @param {*} value - The value to check.
     * @param {string} [message] - Custom error message.
     * @returns {*} - The validated value.
     * @throws {ValidationError} - If validation fails.
     */
    const requireObject = (value, message) => {
        if (!isPlainObject(value)) {
            const msg = message || `Value must be a plain object, got: ${value}`;
            console.warn(msg);
            throw new ValidationError(msg);
        }
        return value;
    };

    /**
     * Requires URL string to be valid and have HTTP(S) protocol, throws ValidationError otherwise.
     *
     * @param {string} urlString - The URL string to check.
     * @param {Set<string>} validProtocols - Set of valid protocol strings.
     * @param {string} [message] - Custom error message.
     * @returns {URL} - The parsed URL object.
     * @throws {ValidationError} - If validation fails.
     */
    const requireValidHttpUrl = (urlString, validProtocols, message) => {
        const result = validateHttpUrl(urlString, validProtocols);
        if (!result.valid) {
            const msg = message || `Invalid URL: ${result.error}`;
            console.warn(msg);
            throw new ValidationError(msg);
        }
        return result.url;
    };

    /**
     * Requires URL string to be parseable, throws ValidationError otherwise.
     *
     * @param {*} urlString - The URL string to check.
     * @param {string} [message] - Custom error message.
     * @returns {URL} - The parsed URL object.
     * @throws {ValidationError} - If validation fails.
     */
    const requireValidUrl = (urlString, message) => {
        const result = parseUrl(urlString);
        if (!result.valid) {
            const msg = message || `Invalid URL format: ${result.error}`;
            console.warn(msg);
            throw new ValidationError(msg);
        }
        return result.url;
    };

    /**
     * Requires object to have a property with non-nullish value, throws ValidationError otherwise.
     *
     * @param {object} obj - The object to check.
     * @param {string} key - The property key to check.
     * @param {string} [message] - Custom error message.
     * @returns {*} - The property value.
     * @throws {ValidationError} - If validation fails.
     */
    const requireProperty = (obj, key, message) => {
        if (!hasProperty(obj, key)) {
            const msg = message || `Object must have property: ${key}`;
            console.warn(msg);
            throw new ValidationError(msg);
        }
        return obj[key];
    };

    /**
     * Requires object to have a property with non-blank string value, throws ValidationError otherwise.
     *
     * @param {object} obj - The object to check.
     * @param {string} key - The property key to check.
     * @param {string} [message] - Custom error message.
     * @returns {string} - The property value.
     * @throws {ValidationError} - If validation fails.
     */
    const requireStringProperty = (obj, key, message) => {
        if (!hasStringProperty(obj, key)) {
            const msg = message || `Object must have non-blank string property: ${key}`;
            console.warn(msg);
            throw new ValidationError(msg);
        }
        return obj[key];
    };

    /**
     * Requires origin value to be valid, throws ValidationError otherwise.
     * Handles both string and number inputs.
     *
     * @param {*} value - The origin value to validate.
     * @param {object} originEnum - The ProtectionResult.Origin enum object.
     * @param {string} [message] - Custom error message.
     * @returns {number} - The validated origin value.
     * @throws {ValidationError} - If validation fails.
     */
    const requireValidOrigin = (value, originEnum, message) => {
        const parsed = parseOriginValue(value);

        if (!parsed.valid) {
            const msg = message || `Origin value is not a valid number: ${value}`;
            console.warn(msg);
            throw new ValidationError(msg);
        }

        if (!isValidOrigin(parsed.value, originEnum)) {
            const msg = message || `Invalid origin value: ${parsed.value}`;
            console.warn(msg);
            throw new ValidationError(msg);
        }
        return parsed.value;
    };

    /**
     * Requires value to equal expected, throws ValidationError otherwise.
     *
     * @param {*} value - The value to check.
     * @param {*} expected - The expected value to compare against.
     * @param {string} [message] - Custom error message.
     * @returns {*} - The validated value.
     * @throws {ValidationError} - If validation fails.
     */
    const requireEquals = (value, expected, message) => {
        if (value !== expected) {
            const msg = message || `Value must equal ${expected}, got: ${value}`;
            console.warn(msg);
            throw new ValidationError(msg);
        }
        return value;
    };

    // Public API
    return Object.freeze({
        // Check methods (return boolean)
        isInteger,
        isNonNegativeInteger,
        isPositiveInteger,
        isNotBlank,
        isNotEmpty,
        hasProperty,
        hasStringProperty,
        hasAllStringProperties,
        parseOriginValue,
        isValidOrigin,
        parseUrl,
        hasValidProtocol,
        validateHttpUrl,
        isNullish,
        isNotNull,
        isNonEmptyArray,
        isBoolean,
        isFunction,
        isPlainObject,

        // Assertion methods (throw ValidationError)
        requireNonNegativeInteger,
        requireInteger,
        requireNotBlank,
        requireNotNull,
        requireValidHttpUrl,
        requireValidUrl,
        requireProperty,
        requireObject,
        requireString,
        requireArray,
        requireBoolean,
        requireStringProperty,
        requireValidOrigin,
        requireEquals,
    });
})();
