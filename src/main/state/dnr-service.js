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

/**
 * Owns every declarativeNetRequest dynamic rule Osprey installs, under a single reserved
 * id registry so no two features can collide. Currently: SafeSearch enforcement on Google,
 * Bing, and DuckDuckGo (query rewrites) and YouTube Restricted Mode (a request header).
 * All rules require the matching optional host permission to have been granted; managed
 * deployments force-grant through the browser's ExtensionSettings runtime_allowed_hosts
 * policy, documented in docs/remote-config.md. Rules rebuild from effective policy on
 * every service worker start and on policy refresh, and both policies default off, so a
 * search engine changing its parameters can always be neutralized by clearing the policy
 * or by an emergency settings migration removing the rules.
 */
globalThis.OspreyDnrService = (() => {
    const browserAPI = globalThis.OspreyBrowserAPI;
    const policyService = globalThis.OspreyPolicyService;
    const providerStateStore = globalThis.OspreyProviderStateStore;

    // Reserved dynamic rule ids. Never reuse or renumber a shipped id.
    const ruleIDs = Object.freeze({
        SAFESEARCH_GOOGLE: 1001,
        SAFESEARCH_BING_SEARCH: 1002,
        SAFESEARCH_BING_IMAGES: 1003,
        SAFESEARCH_BING_VIDEOS: 1004,
        SAFESEARCH_DDG: 1005,
        YOUTUBE_RESTRICT: 1010,
    });

    const allIDs = Object.freeze(Object.values(ruleIDs));

    const dnr = () => browserAPI?.runtime?.declarativeNetRequest
        || globalThis.chrome?.declarativeNetRequest
        || globalThis.browser?.declarativeNetRequest;

    const safeSearchRule = (id, hostEquals, path, param, value) => ({
        id,
        priority: 1,
        action: {
            type: 'redirect',
            redirect: {transform: {queryTransform: {addOrReplaceParams: [{key: param, value}]}}},
        },
        condition: {
            // The negative lookahead is the loop guard: a request already carrying the
            // exact parameter value never matches, so the redirect cannot loop.
            regexFilter: `^https://${hostEquals.replaceAll('.', '\\.')}${path
            }(?!(?:.*[?&])?${param}=${value}(?:&|$)).*$`,
            resourceTypes: ['main_frame'],
        },
    });

    const buildRules = policy => {
        const rules = [];

        if (policy.safeSearch === 'strict') {
            rules.push(safeSearchRule(ruleIDs.SAFESEARCH_GOOGLE, 'www.google.com', String.raw`/search\?`, 'safe', 'active'),
                safeSearchRule(ruleIDs.SAFESEARCH_BING_SEARCH, 'www.bing.com', String.raw`/search\?`, 'adlt', 'strict'),
                safeSearchRule(ruleIDs.SAFESEARCH_BING_IMAGES, 'www.bing.com', String.raw`/images/search\?`, 'adlt', 'strict'),
                safeSearchRule(ruleIDs.SAFESEARCH_BING_VIDEOS, 'www.bing.com', String.raw`/videos/search\?`, 'adlt', 'strict'),
                safeSearchRule(ruleIDs.SAFESEARCH_DDG, 'duckduckgo.com', String.raw`/\?`, 'kp', '1'),
            );
        }

        if (policy.youtubeRestrict === 'moderate' || policy.youtubeRestrict === 'strict') {
            rules.push({
                id: ruleIDs.YOUTUBE_RESTRICT,
                priority: 1,
                action: {
                    type: 'modifyHeaders',
                    requestHeaders: [{
                        header: 'YouTube-Restrict',
                        operation: 'set',
                        value: policy.youtubeRestrict === 'strict' ? 'Strict' : 'Moderate',
                    }],
                },
                condition: {
                    requestDomains: ['youtube.com', 'm.youtube.com', 'youtubei.googleapis.com', 'youtube-nocookie.com'],
                    resourceTypes: ['main_frame', 'sub_frame', 'xmlhttprequest'],
                },
            });
        }
        return rules;
    };

    /**
     * Rebuilds the dynamic rules from effective policy: managed values win over local
     * state, matching every other app policy. Removing all reserved ids first makes the
     * sync idempotent and is also the kill-switch path an emergency migration can call.
     */
    const sync = async () => {
        const api = dnr();

        if (!api?.updateDynamicRules) {
            globalThis.OspreyEventLogService?.record?.('dnr_unavailable', {});
            return {ok: false, reason: 'unsupported'};
        }

        try {
            const state = await providerStateStore.getState();
            const effective = await policyService.applyToAppState(state.app);
            const policy = {
                safeSearch: typeof effective?.safeSearch === 'string' ? effective.safeSearch : '',
                youtubeRestrict: typeof effective?.youtubeRestrict === 'string' ? effective.youtubeRestrict : '',
            };

            await api.updateDynamicRules({
                removeRuleIds: [...allIDs],
                addRules: buildRules(policy),
            });
            return {ok: true};
        } catch (error) {
            console.warn('DNR rule sync failed', error);
            return {ok: false, reason: String(error?.message || error)};
        }
    };

    const clearAllRules = async () => {
        const api = dnr();

        if (api?.updateDynamicRules) {
            await api.updateDynamicRules({removeRuleIds: [...allIDs]});
        }
    };

    return Object.freeze({
        RULE_IDS: ruleIDs,
        buildRules,
        sync,
        clearAllRules,
    });
})();
