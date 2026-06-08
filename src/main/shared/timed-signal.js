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

globalThis.OspreyTimedSignal = (() => {
    class TimedSignalCoordinator {
        constructor(parentSignal, timeoutMs) {
            this.controller = new AbortController();
            this.parentSignal = parentSignal || null;
            this.timerId = null;

            if (this.parentSignal !== null && this.parentSignal.aborted) {
                this.controller.abort(this.parentSignal.reason ?? 'parent-aborted');
                this.parentSignal = null;
                return;
            }

            if (this.parentSignal !== null) {
                this.parentSignal.addEventListener('abort', this, {
                    once: true,
                });
            }

            this.timerId = setTimeout(() => {
                this.timerId = null;

                if (!this.controller.signal.aborted) {
                    this.controller.abort('timeout');
                }

                this.cleanup();
            }, timeoutMs);
        }

        // noinspection JSUnusedGlobalSymbols
        handleEvent() {
            if (!this.controller.signal.aborted) {
                this.controller.abort(this.parentSignal?.reason ?? 'parent-aborted');
            }

            this.cleanup();
        }

        cleanup() {
            if (this.timerId !== null) {
                clearTimeout(this.timerId);
                this.timerId = null;
            }

            if (this.parentSignal !== null) {
                this.parentSignal.removeEventListener('abort', this);
                this.parentSignal = null;
            }
        }
    }

    const create = (parentSignal, timeoutMs) => {
        const coordinator = new TimedSignalCoordinator(parentSignal, timeoutMs);

        return {
            signal: coordinator.controller.signal,
            cleanup: () => coordinator.cleanup(),
        };
    };

    return Object.freeze({
        create,
    });
})();
