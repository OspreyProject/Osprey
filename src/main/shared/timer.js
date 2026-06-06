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
    // Instrumentation can be silenced globally without unwrapping any call site.
    let enabled = true;

    const hasHighResClock = typeof performance !== 'undefined' && typeof performance.now === 'function';
    const readClock = () => hasHighResClock ? performance.now() : Date.now();
    const formatDuration = elapsedMs => `${elapsedMs.toFixed(2)}ms`;

    // Each timed run is tagged with its own random id, so a 'started' line can be
    // matched to its 'finished' line even when async work from many calls
    // interleaves in the console. Always three digits, e.g. '#274 | '.
    const nextPrefix = () => `#${Math.floor(100 + Math.random() * 900)} | `;

    const logStart = (prefix, label) => {
        console.debug(`${prefix}'${label}' started at ${new Date().toISOString()}`);
    };

    const logFinish = (prefix, label, elapsedMs, failed) => {
        failed ?
            console.warn(`${prefix}'${label}' failed after ${formatDuration(elapsedMs)}`) :
            console.debug(`${prefix}'${label}' finished in ${formatDuration(elapsedMs)}`);
    };

    /**
     * Runs fn immediately, logging when it started and how long it took to finish.
     * Transparent to callers: the original return value is passed through, thrown
     * errors are re-thrown, and Promise results are awaited so the reported
     * duration reflects full settlement (resolve or reject).
     *
     * @param {string} label Human-readable name for the work being timed.
     * @param {Function} fn The function to execute and measure.
     * @param {...*} args Arguments forwarded to fn.
     * @returns {*} Whatever fn returns (a Promise stays a Promise).
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
     * Wraps fn in a timed equivalent. The returned function preserves `this` and
     * forwards every argument, so it is a drop-in replacement for the original.
     *
     * @param {string} label Human-readable name for the work being timed.
     * @param {Function} fn The function to wrap.
     * @returns {Function} A function that times each invocation of fn.
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
     * is replaced by a timed wrapper (labeled `${namespace}.${key}`). Non-function
     * properties are carried across untouched. This lets a module instrument its
     * entire public surface in a single call at its return site.
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
