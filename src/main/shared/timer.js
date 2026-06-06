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

globalThis.OspreyTimer = (() => {
    const hasHighResClock = typeof performance !== 'undefined' && typeof performance.now === 'function';
    const readClock = () => hasHighResClock ? performance.now() : Date.now();
    const formatDuration = elapsedMs => `${elapsedMs.toFixed(2)}ms`;
    const nextPrefix = () => `#${Math.floor(100 + Math.random() * 900)} | `;

    // Whether the timer is enabled
    let enabled = false;

    const logStart = (prefix, label) => {
        console.debug(`${prefix}'${label}' started at ${new Date().toISOString()}`);
    };

    const logFinish = (prefix, label, elapsedMs, failed) => {
        failed ?
            console.warn(`${prefix}'${label}' failed after ${formatDuration(elapsedMs)}`) :
            console.debug(`${prefix}'${label}' finished in ${formatDuration(elapsedMs)}`);
    };

    /**
     * Runs fn with the given args and logs the time taken to complete.
     *
     * @param {string} label Human-readable name for the work being timed.
     * @param {Function} fn The function to run and time.
     * @param {...*} args Arguments to forward to fn.
     * @returns {*} The return value of fn, if any.
     */
    const time = (label, fn, ...args) => {
        const prefix = nextPrefix();

        if (typeof fn !== 'function') {
            console.warn(`${prefix}time() was called for '${label}' without a function to run`);
            return undefined;
        }

        if (!enabled) {
            return fn(...args);
        }

        logStart(prefix, label);
        const start = readClock();

        let result;
        try {
            result = fn(...args);
        } catch (error) {
            logFinish(prefix, label, readClock() - start, true);
            throw error;
        }

        if (result && typeof result.then === 'function') {
            return result.then(
                value => {
                    logFinish(prefix, label, readClock() - start, false);
                    return value;
                },
                error => {
                    logFinish(prefix, label, readClock() - start, true);
                    throw error;
                }
            );
        }

        logFinish(prefix, label, readClock() - start, false);
        return result;
    };

    /**
     * Returns a wrapper around fn that behaves the same but logs the time taken for each invocation.
     *
     * @param {string} label Human-readable name for the work being timed.
     * @param {Function} fn The function to wrap and time.
     * @returns {Function} A wrapped version of fn that logs its execution time.
     */
    const wrap = (label, fn) => {
        if (typeof fn !== 'function') {
            console.warn(`${nextPrefix()}wrap() was called for '${label}' without a function`);
            return fn;
        }

        return function timed(...args) {
            return time(label, fn.bind(this), ...args);
        };
    };

    /**
     * Returns a frozen copy of apiObject in which every function-valued property
     * is replaced by a timed wrapper (labeled `${namespace}.${key}`).
     *
     * @param {string} namespace Label prefix for the wrapped methods.
     * @param {Object} apiObject The public API object to instrument.
     * @returns {Object} A frozen, instrumented copy of apiObject.
     */
    const instrument = (namespace, apiObject) => {
        if (!apiObject || typeof apiObject !== 'object') {
            return apiObject;
        }

        const instrumented = {};

        for (const key of Object.keys(apiObject)) {
            const value = apiObject[key];
            instrumented[key] = typeof value === 'function' ? wrap(`${namespace}.${key}`, value) : value;
        }
        return Object.freeze(instrumented);
    };

    const setEnabled = value => {
        enabled = Boolean(value);
    };

    const isEnabled = () => enabled;

    // Public API
    return Object.freeze({
        time,
        wrap,
        instrument,
        setEnabled,
        isEnabled,
    });
})();
